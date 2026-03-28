/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use arrayvec::ArrayVec;
use hickory_proto::op::response_code::ResponseCode as HickoryResponseCode;
use hickory_proto::rr::record_type::RecordType as HickoryRecordType;
use std::collections::BTreeMap;
use std::mem;
use std::net::IpAddr;

#[cfg(test)]
use std::mem::MaybeUninit;

use crate::custom_types::DnsNameBuf;
use crate::record::DnsRecord;

const INLINE_TIMELINE_CAPACITY: usize = 1;

// Matcher identity preserves the observed presentation-form QNAME bytes and does not lowercase
// them before building in-flight keys. This is an accepted operational hypothesis for the current
// offline capture path: responses are expected to preserve the query's 0x20 casing. If a capture
// violates that assumption, query/response pairs that differ only by case may not match.
pub(super) type QueryIdentityKey = (u16, DnsNameBuf, IpAddr, u16, HickoryRecordType);
pub(super) type ResponseIdentityKey = (u16, DnsNameBuf, IpAddr, u16, HickoryRecordType);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct TimelineKey {
    pub(super) timestamp_micros: i64,
    pub(super) packet_ordinal: u64,
    pub(super) record_ordinal: u32,
}

impl TimelineKey {
    pub(super) fn new(timestamp_micros: i64, packet_ordinal: u64, record_ordinal: u32) -> Self {
        Self {
            timestamp_micros,
            packet_ordinal,
            record_ordinal,
        }
    }

    pub(super) fn lower_bound(timestamp_micros: i64) -> Self {
        Self::new(timestamp_micros, u64::MIN, u32::MIN)
    }

    pub(super) fn upper_bound(timestamp_micros: i64) -> Self {
        Self::new(timestamp_micros, u64::MAX, u32::MAX)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct QueryEventPayload;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ResponseEventPayload {
    pub(super) response_code: HickoryResponseCode,
}

pub(super) enum Timeline<Record> {
    Inline(ArrayVec<(TimelineKey, Record), INLINE_TIMELINE_CAPACITY>),
    Tree(BTreeMap<TimelineKey, Record>),
}

impl<Record> Default for Timeline<Record> {
    fn default() -> Self {
        Self::Inline(ArrayVec::new())
    }
}

impl<Record> Timeline<Record> {
    pub(super) fn insert(&mut self, key: TimelineKey, record: Record) -> Option<Record> {
        match self {
            Self::Inline(entries) => {
                match entries.binary_search_by_key(&key, |(entry_key, _)| *entry_key) {
                    Ok(index) => Some(mem::replace(&mut entries[index], (key, record)).1),
                    Err(index) if entries.len() < INLINE_TIMELINE_CAPACITY => {
                        entries.insert(index, (key, record));
                        None
                    }
                    Err(_) => {
                        let mut tree = BTreeMap::new();
                        for (entry_key, entry_record) in entries.drain(..) {
                            tree.insert(entry_key, entry_record);
                        }
                        let replaced = tree.insert(key, record);
                        *self = Self::Tree(tree);
                        replaced
                    }
                }
            }
            Self::Tree(tree) => tree.insert(key, record),
        }
    }

    pub(super) fn contains_timestamp_range(
        &self,
        lower_timestamp_micros: i64,
        upper_timestamp_micros: i64,
    ) -> bool {
        self.first_entry_in_range(lower_timestamp_micros, upper_timestamp_micros)
            .is_some()
    }

    pub(super) fn first_entry_in_range(
        &self,
        lower_timestamp_micros: i64,
        upper_timestamp_micros: i64,
    ) -> Option<(TimelineKey, &Record)> {
        match self {
            Self::Inline(entries) => {
                let lower_bound = TimelineKey::lower_bound(lower_timestamp_micros);
                let index =
                    match entries.binary_search_by_key(&lower_bound, |(entry_key, _)| *entry_key) {
                        Ok(index) | Err(index) => index,
                    };
                let (key, record) = entries.get(index)?;
                (key.timestamp_micros <= upper_timestamp_micros).then_some((*key, record))
            }
            Self::Tree(tree) => tree
                .range(
                    TimelineKey::lower_bound(lower_timestamp_micros)
                        ..=TimelineKey::upper_bound(upper_timestamp_micros),
                )
                .next()
                .map(|(key, record)| (*key, record)),
        }
    }

    pub(super) fn last_entry_in_range(
        &self,
        lower_timestamp_micros: i64,
        upper_timestamp_micros: i64,
    ) -> Option<(TimelineKey, &Record)> {
        match self {
            Self::Inline(entries) => {
                let upper_bound = TimelineKey::upper_bound(upper_timestamp_micros);
                let index =
                    match entries.binary_search_by_key(&upper_bound, |(entry_key, _)| *entry_key) {
                        Ok(index) => index,
                        Err(index) => index.checked_sub(1)?,
                    };
                let (key, record) = entries.get(index)?;
                (key.timestamp_micros >= lower_timestamp_micros).then_some((*key, record))
            }
            Self::Tree(tree) => tree
                .range(
                    TimelineKey::lower_bound(lower_timestamp_micros)
                        ..=TimelineKey::upper_bound(upper_timestamp_micros),
                )
                .next_back()
                .map(|(key, record)| (*key, record)),
        }
    }

    pub(super) fn remove(&mut self, key: TimelineKey) -> Option<Record> {
        match self {
            Self::Inline(entries) => {
                let index = entries
                    .binary_search_by_key(&key, |(entry_key, _)| *entry_key)
                    .ok()?;
                Some(entries.remove(index).1)
            }
            Self::Tree(tree) => tree.remove(&key),
        }
    }

    pub(super) fn drain_before(
        &mut self,
        threshold_timestamp_micros: i64,
        mut visit: impl FnMut(TimelineKey, Record),
    ) {
        match self {
            Self::Inline(entries) => {
                let split_index = entries
                    .iter()
                    .position(|(key, _)| key.timestamp_micros >= threshold_timestamp_micros)
                    .unwrap_or(entries.len());
                for (key, record) in entries.drain(..split_index) {
                    visit(key, record);
                }
            }
            Self::Tree(tree) => {
                while tree
                    .first_key_value()
                    .is_some_and(|(key, _)| key.timestamp_micros < threshold_timestamp_micros)
                {
                    let (key, record) = tree.pop_first().expect("timeline must have first entry");
                    visit(key, record);
                }
            }
        }
    }

    pub(super) fn into_entries(self, mut visit: impl FnMut(TimelineKey, Record)) {
        match self {
            Self::Inline(entries) => {
                for (key, record) in entries {
                    visit(key, record);
                }
            }
            Self::Tree(tree) => {
                for (key, record) in tree {
                    visit(key, record);
                }
            }
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Inline(entries) => entries.is_empty(),
            Self::Tree(tree) => tree.is_empty(),
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Inline(entries) => entries.len(),
            Self::Tree(tree) => tree.len(),
        }
    }
}

pub(super) type QueryTimeline = Timeline<QueryEventPayload>;
pub(super) type ResponseTimeline = Timeline<ResponseEventPayload>;

pub(super) type QueryMap = BTreeMap<QueryIdentityKey, QueryTimeline>;
pub(super) type ResponseMap = BTreeMap<ResponseIdentityKey, ResponseTimeline>;

#[cfg(test)]
const FREE_LIST_EMPTY: u32 = u32::MAX;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EntryHandle {
    slot: u32,
    generation: u32,
}

#[cfg(test)]
struct EntrySlot<T> {
    generation: u32,
    next_free: u32,
    occupied: bool,
    value: MaybeUninit<T>,
}

#[cfg(test)]
pub(super) struct EntryArena<T> {
    slots: Vec<EntrySlot<T>>,
    free_head: u32,
}

#[cfg(test)]
impl<T> Default for EntryArena<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            free_head: FREE_LIST_EMPTY,
        }
    }
}

#[cfg(test)]
impl<T> EntryArena<T> {
    pub(super) fn alloc(&mut self, value: T) -> EntryHandle {
        if self.free_head != FREE_LIST_EMPTY {
            let slot_idx = self.free_head;
            let slot = self
                .slots
                .get_mut(slot_idx as usize)
                .expect("free-list slot must exist");
            debug_assert!(!slot.occupied);
            self.free_head = slot.next_free;
            slot.next_free = FREE_LIST_EMPTY;
            slot.occupied = true;
            slot.value = MaybeUninit::new(value);
            return EntryHandle {
                slot: slot_idx,
                generation: slot.generation,
            };
        }

        let slot_idx =
            u32::try_from(self.slots.len()).expect("entry arena exceeds 32-bit slot capacity");
        self.slots.push(EntrySlot {
            generation: 0,
            next_free: FREE_LIST_EMPTY,
            occupied: true,
            value: MaybeUninit::new(value),
        });
        EntryHandle {
            slot: slot_idx,
            generation: 0,
        }
    }

    pub(super) fn get(&self, handle: EntryHandle) -> Option<&T> {
        let slot = self.slots.get(handle.slot as usize)?;
        if !slot.occupied || slot.generation != handle.generation {
            return None;
        }

        // Hypothesis: no single slot will be recycled 2^32 times during one process lifetime,
        // so generation wraparound remains practically unreachable for stale-handle detection.
        Some(unsafe { slot.value.assume_init_ref() })
    }

    pub(super) fn remove(&mut self, handle: EntryHandle) -> Option<T> {
        let slot = self.slots.get_mut(handle.slot as usize)?;
        if !slot.occupied || slot.generation != handle.generation {
            return None;
        }

        slot.occupied = false;
        slot.generation = slot.generation.wrapping_add(1);
        let value = unsafe { slot.value.assume_init_read() };
        slot.next_free = self.free_head;
        self.free_head = handle.slot;
        Some(value)
    }
}

#[cfg(test)]
impl<T> Drop for EntryArena<T> {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            if slot.occupied {
                unsafe {
                    slot.value.assume_init_drop();
                }
            }
        }
    }
}

#[derive(Default)]
pub(super) struct ShardProcessingResult {
    pub(super) output_records: Vec<DnsRecord>,
    pub(super) dns_query_count: usize,
    pub(super) duplicated_query_count: usize,
    pub(super) dns_response_count: usize,
    pub(super) matched_query_response_count: usize,
    pub(super) timeout_query_count: usize,
    pub(super) matched_rtt_sum_micros: u64,
    pub(super) out_of_order_combined_count: usize,
}

#[derive(Debug, Clone)]
pub(super) struct ProcessedDnsRecord {
    pub(super) id: u16,
    pub(super) timestamp_micros: i64,
    pub(super) packet_ordinal: u64,
    pub(super) record_ordinal: u32,
    pub(super) src_ip: IpAddr,
    pub(super) src_port: u16,
    pub(super) dst_ip: IpAddr,
    pub(super) dst_port: u16,
    pub(super) is_query: bool,
    pub(super) name: DnsNameBuf,
    pub(super) query_type: HickoryRecordType,
    pub(super) response_code: HickoryResponseCode,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq)]
pub(super) struct DnsQuery {
    pub(super) id: u16,
    pub(super) name: DnsNameBuf,
    pub(super) src_ip: IpAddr,
    pub(super) src_port: u16,
    pub(super) timestamp_micros: i64,
    pub(super) packet_ordinal: u64,
    pub(super) record_ordinal: u32,
    pub(super) query_type: HickoryRecordType,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq)]
pub(super) struct DnsResponse {
    pub(super) id: u16,
    pub(super) name: DnsNameBuf,
    pub(super) dst_ip: IpAddr,
    pub(super) dst_port: u16,
    pub(super) timestamp_micros: i64,
    pub(super) packet_ordinal: u64,
    pub(super) record_ordinal: u32,
    pub(super) response_code: HickoryResponseCode,
    pub(super) query_type: HickoryRecordType,
}

#[derive(Default)]
pub(super) struct MatcherShardState {
    pub(super) query_map: QueryMap,
    pub(super) response_map: ResponseMap,
}
