/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

//! Bounded IPv4/UDP fragment assembly before DNS flow routing.
//!
//! Later fragments have no UDP ports, so this state has one owner in the routing stage.
//! A completed datagram replaces its first fragment with one ordinary IPv4 packet. An
//! incomplete first fragment is released on expiry, eviction, input end, or opted-in reuse;
//! the existing `--allow-fragments` parser then decides whether its DNS prefix is usable.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use super::types::VlanContext;
use crate::packet_parser::{PacketBatch, PacketData, PacketPayload};

#[cfg(test)]
const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_PROTOCOL_UDP: u8 = 17;
const DNS_PORT: u16 = 53;
const MORE_FRAGMENTS: u16 = 0x2000;
const DONT_FRAGMENT: u16 = 0x4000;
const RESERVED_FLAG: u16 = 0x8000;
const FRAGMENT_OFFSET_MASK: u16 = 0x1fff;

/// Bounds are independent of capture timestamps, which may regress in normal mode.
const MAX_PENDING_DATAGRAMS: usize = 8_192;
const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
const ENTRY_OVERHEAD_ESTIMATE: usize = 256;
const SEGMENT_OVERHEAD_ESTIMATE: usize = 64;
const MAX_RECENT_COMPLETIONS: usize = 4_096;
const MAX_RECENT_BYTES: usize = 16 * 1024 * 1024;
const RECENT_ENTRY_OVERHEAD_ESTIMATE: usize = 128;
const MAX_NON_DNS_KEYS: usize = 4_096;
const MAX_NON_DNS_BYTES: usize = 1024 * 1024;
const MIN_RECENT_RETENTION_MICROS: i64 = 5_000_000;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FragmentKey {
    source: [u8; 4],
    destination: [u8; 4],
    identification: u16,
    vlan_context: VlanContext,
}

struct FragmentPart {
    key: FragmentKey,
    offset: usize,
    payload: Box<[u8]>,
    more_fragments: bool,
    first_udp_length: Option<usize>,
    first_header_len: Option<usize>,
    first_l3_offset: Option<usize>,
}

struct FragmentSegment {
    payload: Box<[u8]>,
    more_fragments: bool,
}

struct CompletedDatagram {
    payload: Arc<[u8]>,
    observed_timestamp: i64,
    arrival_order: u64,
    reuse_cutoff_timestamp: Option<i64>,
}

impl CompletedDatagram {
    fn memory_bytes(&self) -> usize {
        RECENT_ENTRY_OVERHEAD_ESTIMATE + self.payload.len()
    }
}

struct NonDnsKey {
    observed_timestamp: i64,
    arrival_order: u64,
    reuse_cutoff_timestamp: Option<i64>,
}

enum FragmentInput {
    Ordinary,
    Skip,
    NonDnsFirst(FragmentKey),
    Part(FragmentPart),
}

/// Byte intervals must not overlap, except for an exact duplicate fragment.
struct PendingDatagram {
    arrival_order: u64,
    first_seen_timestamp: i64,
    max_observed_timestamp: i64,
    reuse_cutoff_timestamp: Option<i64>,
    first: Option<PacketData>,
    first_header_len: Option<usize>,
    first_l3_offset: Option<usize>,
    udp_length: Option<usize>,
    final_payload_length: Option<usize>,
    final_fragment_event: Option<(i64, u64)>,
    segments: BTreeMap<usize, FragmentSegment>,
    /// Present while every observed fragment matches a recently completed datagram.
    recent_payload: Option<Arc<[u8]>>,
    rejected: bool,
}

impl PendingDatagram {
    fn new(arrival_order: u64, timestamp: i64, recent_payload: Option<Arc<[u8]>>) -> Self {
        Self {
            arrival_order,
            first_seen_timestamp: timestamp,
            max_observed_timestamp: timestamp,
            reuse_cutoff_timestamp: None,
            first: None,
            first_header_len: None,
            first_l3_offset: None,
            udp_length: None,
            final_payload_length: None,
            final_fragment_event: None,
            segments: BTreeMap::new(),
            recent_payload,
            rejected: false,
        }
    }

    fn memory_bytes(&self) -> usize {
        ENTRY_OVERHEAD_ESTIMATE
            + self.first.as_ref().map_or(0, |first| first.data.len())
            + self
                .segments
                .values()
                .map(|segment| segment.payload.len() + SEGMENT_OVERHEAD_ESTIMATE)
                .sum::<usize>()
            + self
                .recent_payload
                .as_ref()
                .map_or(0, |payload| payload.len())
    }

    fn reject(&mut self) {
        self.first = None;
        self.first_header_len = None;
        self.first_l3_offset = None;
        self.udp_length = None;
        self.final_payload_length = None;
        self.final_fragment_event = None;
        self.segments.clear();
        self.recent_payload = None;
        self.rejected = true;
    }

    fn into_fallback(self) -> Option<PacketData> {
        // A prefix whose observed bytes still match a completed datagram is a
        // possible capture duplicate, not a second inferred DNS response.
        if self.recent_payload.is_some() {
            None
        } else {
            self.first
        }
    }

    fn insert(&mut self, part: FragmentPart, packet: PacketData) -> Result<bool, ()> {
        if self.rejected {
            return Err(());
        }
        if self
            .recent_payload
            .as_ref()
            .is_some_and(|payload| !fragment_matches_payload(&part, payload))
        {
            self.recent_payload = None;
        }
        let event = (packet.timestamp_micros, packet.packet_ordinal);
        let end = part.offset.checked_add(part.payload.len()).ok_or(())?;
        if self
            .final_payload_length
            .is_some_and(|final_end| end > final_end)
        {
            return Err(());
        }
        if part.more_fragments
            && (self.udp_length.is_some_and(|udp_length| end >= udp_length)
                || self
                    .final_payload_length
                    .is_some_and(|final_end| end >= final_end))
        {
            return Err(());
        }
        if let Some(udp_length) = self.udp_length
            && end > udp_length
        {
            return Err(());
        }
        if part.offset == 0 {
            if self.first.is_some() {
                // A repeated first fragment may be a capture duplicate. A different
                // first fragment with the same IPv4 ID is ambiguous, so reject it.
                let existing = self.segments.get(&0).ok_or(())?;
                return if existing.payload.as_ref() == part.payload.as_ref()
                    && existing.more_fragments == part.more_fragments
                {
                    Ok(self.is_complete())
                } else {
                    Err(())
                };
            }
            let udp_length = part.first_udp_length.ok_or(())?;
            let header_len = part.first_header_len.ok_or(())?;
            let l3_offset = part.first_l3_offset.ok_or(())?;
            if end > udp_length
                || self
                    .final_payload_length
                    .is_some_and(|last| last != udp_length)
                || self
                    .segments
                    .last_key_value()
                    .is_some_and(|(offset, segment)| {
                        // Disjoint intervals have increasing ends, so the last retained
                        // tail is enough to validate the newly known UDP boundary.
                        let segment_end = offset + segment.payload.len();
                        segment_end > udp_length
                            || (segment.more_fragments && segment_end == udp_length)
                    })
            {
                return Err(());
            }
            self.udp_length = Some(udp_length);
            self.first_header_len = Some(header_len);
            self.first_l3_offset = Some(l3_offset);
            self.first = Some(packet);
        }

        if let Some((&start, existing)) = self.segments.range(..=part.offset).next_back() {
            if start == part.offset {
                if existing.payload.as_ref() != part.payload.as_ref()
                    || existing.more_fragments != part.more_fragments
                {
                    return Err(());
                }
                if !part.more_fragments {
                    self.set_final_length(end, event)?;
                }
                return Ok(self.is_complete());
            }
            if start + existing.payload.len() > part.offset {
                return Err(());
            }
        }
        if let Some((&next_start, _)) = self.segments.range(part.offset..).next()
            && end > next_start
        {
            return Err(());
        }
        if let Some(udp_length) = self.udp_length
            && end > udp_length
        {
            return Err(());
        }
        if !part.more_fragments {
            self.set_final_length(end, event)?;
        }
        self.segments.insert(
            part.offset,
            FragmentSegment {
                payload: part.payload,
                more_fragments: part.more_fragments,
            },
        );
        Ok(self.is_complete())
    }

    fn set_final_length(&mut self, end: usize, event: (i64, u64)) -> Result<(), ()> {
        if self
            .final_payload_length
            .is_some_and(|previous| previous != end)
            || self.udp_length.is_some_and(|udp_length| udp_length != end)
            || self
                .segments
                .iter()
                .any(|(offset, segment)| offset + segment.payload.len() > end)
        {
            return Err(());
        }
        self.final_payload_length = Some(end);
        self.final_fragment_event = Some(
            self.final_fragment_event
                .map_or(event, |old| old.min(event)),
        );
        Ok(())
    }

    fn is_complete(&self) -> bool {
        let Some(expected) = self.udp_length else {
            return false;
        };
        if self.first.is_none() || self.final_payload_length != Some(expected) {
            return false;
        }
        let mut cursor = 0;
        for (offset, segment) in &self.segments {
            if *offset != cursor {
                return false;
            }
            cursor += segment.payload.len();
        }
        cursor == expected
    }

    fn into_packet(self) -> Option<PacketData> {
        let first = self.first?;
        let header_len = self.first_header_len?;
        let l3_offset = self.first_l3_offset?;
        let udp_length = self.udp_length?;
        let (timestamp_micros, packet_ordinal) = self.final_fragment_event?;
        let total_length = header_len.checked_add(udp_length)?;
        let total_length = u16::try_from(total_length).ok()?;
        let header_end = l3_offset.checked_add(header_len)?;
        let first_header = first.data.as_slice().get(..header_end)?;

        let mut bytes = Vec::with_capacity(l3_offset + usize::from(total_length));
        bytes.extend_from_slice(first_header);
        bytes[l3_offset + 2..l3_offset + 4].copy_from_slice(&total_length.to_be_bytes());
        // It is now a complete synthetic IPv4 datagram. Recompute the header checksum.
        bytes[l3_offset + 6..l3_offset + 8].copy_from_slice(&0_u16.to_be_bytes());
        bytes[l3_offset + 10..l3_offset + 12].copy_from_slice(&0_u16.to_be_bytes());
        let checksum = ipv4_header_checksum(&bytes[l3_offset..header_end]);
        bytes[l3_offset + 10..l3_offset + 12].copy_from_slice(&checksum.to_be_bytes());
        for (_, segment) in self.segments {
            bytes.extend_from_slice(&segment.payload);
        }
        Some(PacketData {
            data: PacketPayload::owned(bytes.into_boxed_slice()),
            timestamp_micros,
            packet_ordinal,
        })
    }
}

fn fragment_matches_payload(part: &FragmentPart, payload: &[u8]) -> bool {
    let Some(end) = part.offset.checked_add(part.payload.len()) else {
        return false;
    };
    end <= payload.len()
        && part.more_fragments == (end < payload.len())
        && part.payload.as_ref() == &payload[part.offset..end]
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for word in header.as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One instance must survive every batch of a capture, including across worker handoffs.
pub(super) struct Ipv4FragmentReassembler {
    pending: HashMap<FragmentKey, PendingDatagram>,
    arrival_order: BTreeMap<u64, FragmentKey>,
    pending_bytes: usize,
    next_arrival_order: u64,
    recently_completed: HashMap<FragmentKey, CompletedDatagram>,
    completed_order: BTreeMap<u64, FragmentKey>,
    completed_bytes: usize,
    next_completed_order: u64,
    known_non_dns: HashMap<FragmentKey, NonDnsKey>,
    non_dns_order: BTreeMap<u64, FragmentKey>,
    non_dns_bytes: usize,
    next_non_dns_order: u64,
    max_seen_timestamp: Option<i64>,
    timeout_micros: i64,
    monotonic_capture: bool,
    reuse_gap_micros: Option<i64>,
}

impl Ipv4FragmentReassembler {
    pub(super) fn new(match_timeout_micros: i64, monotonic_capture: bool) -> Self {
        Self {
            pending: HashMap::new(),
            arrival_order: BTreeMap::new(),
            pending_bytes: 0,
            next_arrival_order: 0,
            recently_completed: HashMap::new(),
            completed_order: BTreeMap::new(),
            completed_bytes: 0,
            next_completed_order: 0,
            known_non_dns: HashMap::new(),
            non_dns_order: BTreeMap::new(),
            non_dns_bytes: 0,
            next_non_dns_order: 0,
            max_seen_timestamp: None,
            timeout_micros: match_timeout_micros.max(1),
            monotonic_capture,
            reuse_gap_micros: None,
        }
    }

    pub(super) fn with_reuse_gap_micros(mut self, gap: Option<i64>) -> Self {
        debug_assert!(gap.is_none_or(|gap| gap > 0));
        debug_assert!(gap.is_none() || !self.monotonic_capture);
        self.reuse_gap_micros = gap;
        self
    }

    fn retained_reuse_cutoff(&self, key: &FragmentKey) -> Option<i64> {
        // Preserve the default path's lookups when recovery is disabled.
        self.reuse_gap_micros?;
        self.pending
            .get(key)
            .and_then(|entry| entry.reuse_cutoff_timestamp)
            .max(
                self.recently_completed
                    .get(key)
                    .and_then(|entry| entry.reuse_cutoff_timestamp),
            )
            .max(
                self.known_non_dns
                    .get(key)
                    .and_then(|entry| entry.reuse_cutoff_timestamp),
            )
    }

    /// Returns decodable packets and the oldest unresolved fragment timestamp.
    /// The caller must cap monotonic matcher eviction at that timestamp until resolution.
    pub(super) fn process_batch(&mut self, input: PacketBatch) -> (PacketBatch, Option<i64>) {
        let mut output = Vec::with_capacity(input.len());
        for packet in input {
            self.max_seen_timestamp = Some(
                self.max_seen_timestamp
                    .map_or(packet.timestamp_micros, |current| {
                        current.max(packet.timestamp_micros)
                    }),
            );
            match classify_fragment(&packet) {
                FragmentInput::Ordinary => output.push(packet),
                FragmentInput::Skip => {}
                FragmentInput::NonDnsFirst(key) => {
                    let cutoff = self.retained_reuse_cutoff(&key);
                    if cutoff.is_some_and(|cutoff| packet.timestamp_micros <= cutoff) {
                        continue;
                    }
                    // Later fragments have no ports. Drop any tails retained before
                    // this first fragment established that the datagram is not DNS.
                    self.take_entry(&key);
                    self.remember_non_dns(key, packet.timestamp_micros, cutoff);
                }
                FragmentInput::Part(part) => {
                    let cutoff = self.retained_reuse_cutoff(&part.key);
                    if cutoff.is_some_and(|cutoff| packet.timestamp_micros <= cutoff) {
                        continue;
                    }
                    self.expire_completed_key_at(&part.key, packet.timestamp_micros);
                    self.expire_non_dns_key_at(&part.key, packet.timestamp_micros);
                    self.expire_key_at(&part.key, packet.timestamp_micros, &mut output);
                    if self.known_non_dns.contains_key(&part.key) {
                        if part.offset != 0 {
                            // The known non-DNS first fragment owns this IPv4 ID.
                            continue;
                        }
                        // A new DNS first fragment reuses the IPv4 ID; its later
                        // fragments may now be assembled again.
                        self.take_non_dns(&part.key);
                    }
                    self.accept_part(part, packet, cutoff, &mut output);
                    // One input batch may contain many large fragments. Enforce the
                    // memory bound per fragment, not only after the whole batch.
                    self.enforce_limits(&mut output);
                }
            }
        }
        self.expire_old(&mut output);
        self.expire_recent_completions();
        self.expire_non_dns_keys();
        self.enforce_limits(&mut output);
        let oldest_pending_timestamp = self
            .pending
            .values()
            .filter(|entry| !entry.rejected)
            .map(|entry| entry.first_seen_timestamp)
            .min();
        (output, oldest_pending_timestamp)
    }

    /// At EOF, incomplete datagrams can only contribute an observable first prefix.
    pub(super) fn finish(&mut self) -> PacketBatch {
        let mut output = Vec::new();
        while let Some((order, key)) = self
            .arrival_order
            .first_key_value()
            .map(|(order, key)| (*order, key.clone()))
        {
            debug_assert_eq!(
                self.pending.get(&key).map(|entry| entry.arrival_order),
                Some(order)
            );
            if let Some(entry) = self.take_entry(&key)
                && let Some(first) = entry.into_fallback()
            {
                output.push(first);
            }
        }
        output
    }

    fn accept_part(
        &mut self,
        part: FragmentPart,
        packet: PacketData,
        mut cutoff: Option<i64>,
        output: &mut PacketBatch,
    ) {
        let key = part.key.clone();
        let observed_timestamp = packet.timestamp_micros;
        let mut existing = self.take_entry(&key);
        if let Some(gap) = self.reuse_gap_micros
            && part.offset == 0
            && let Some(entry) = existing.as_ref()
            && let Some(recovered_cutoff) =
                recovery_cutoff(entry.max_observed_timestamp, observed_timestamp, gap)
        {
            // Compare before admitting this first fragment, including exact duplicates.
            // The old candidate owns the fallback decision and all its retained bytes.
            if let Some(first) = existing.take().and_then(PendingDatagram::into_fallback) {
                output.push(first);
            }
            self.take_completion(&key);
            cutoff = cutoff.max(Some(recovered_cutoff));
        }
        if existing.as_ref().is_some_and(|entry| {
            entry.recent_payload.is_some()
                && entry.first.is_some()
                && part.offset == 0
                && !fragment_matches_payload(
                    &part,
                    entry.recent_payload.as_ref().expect("checked above"),
                )
        }) {
            // A different first fragment starts a new generation of this IPv4 ID.
            // The old candidate matched a completed datagram and needs no fallback.
            existing = None;
        }
        let recent_payload = self
            .recently_completed
            .get(&key)
            .map(|entry| Arc::clone(&entry.payload));
        let mut entry = existing.unwrap_or_else(|| {
            let arrival_order = self.next_arrival_order;
            self.next_arrival_order = self.next_arrival_order.wrapping_add(1);
            PendingDatagram::new(arrival_order, observed_timestamp, recent_payload)
        });
        if self.reuse_gap_micros.is_some() {
            entry.reuse_cutoff_timestamp = entry.reuse_cutoff_timestamp.max(cutoff);
            // Exact duplicates and insert errors are admitted observations too.
            entry.max_observed_timestamp = entry.max_observed_timestamp.max(observed_timestamp);
        }
        match entry.insert(part, packet) {
            Ok(true) => {
                let previous_payload = entry.recent_payload.clone();
                let cutoff = entry.reuse_cutoff_timestamp;
                let header_len = entry
                    .first_header_len
                    .expect("complete datagram has first header");
                let l3_offset = entry
                    .first_l3_offset
                    .expect("complete datagram has first Ethernet header");
                if let Some(packet) = entry.into_packet() {
                    let payload = &packet.data[l3_offset + header_len..];
                    if !previous_payload
                        .as_ref()
                        .is_some_and(|previous| previous.as_ref() == payload)
                    {
                        self.remember_completion(
                            key.clone(),
                            Arc::<[u8]>::from(payload),
                            observed_timestamp,
                            cutoff,
                        );
                        output.push(packet);
                    } else if cutoff.is_some() {
                        if let Some(completed) = self.recently_completed.get_mut(&key) {
                            completed.reuse_cutoff_timestamp =
                                completed.reuse_cutoff_timestamp.max(cutoff);
                        } else {
                            // A pending duplicate can outlive its bounded cache entry.
                            // Preserve its fence when completion suppresses the output.
                            self.remember_completion(
                                key,
                                previous_payload.expect("duplicate has a recent payload"),
                                observed_timestamp,
                                cutoff,
                            );
                        }
                    }
                }
            }
            Ok(false) => self.insert_entry(key, entry),
            Err(()) => {
                // Keep a bounded tombstone so later fragments with the same IPv4 ID
                // cannot turn a rejected datagram into a prefix match.
                entry.reject();
                self.insert_entry(key, entry);
            }
        }
    }

    fn insert_entry(&mut self, key: FragmentKey, entry: PendingDatagram) {
        self.pending_bytes += entry.memory_bytes() + key.vlan_context.memory_bytes();
        self.arrival_order.insert(entry.arrival_order, key.clone());
        self.pending.insert(key, entry);
    }

    fn take_entry(&mut self, key: &FragmentKey) -> Option<PendingDatagram> {
        let entry = self.pending.remove(key)?;
        self.pending_bytes -= entry.memory_bytes() + key.vlan_context.memory_bytes();
        self.arrival_order.remove(&entry.arrival_order);
        Some(entry)
    }

    fn remember_completion(
        &mut self,
        key: FragmentKey,
        payload: Arc<[u8]>,
        observed_timestamp: i64,
        reuse_cutoff_timestamp: Option<i64>,
    ) {
        let reuse_cutoff_timestamp = reuse_cutoff_timestamp.max(
            self.take_completion(&key)
                .and_then(|entry| entry.reuse_cutoff_timestamp),
        );
        let arrival_order = self.next_completed_order;
        self.next_completed_order = self.next_completed_order.wrapping_add(1);
        let completed = CompletedDatagram {
            payload,
            observed_timestamp,
            arrival_order,
            reuse_cutoff_timestamp,
        };
        self.completed_bytes += completed.memory_bytes() + key.vlan_context.memory_bytes();
        self.completed_order.insert(arrival_order, key.clone());
        self.recently_completed.insert(key, completed);
        while self.recently_completed.len() > MAX_RECENT_COMPLETIONS
            || self.completed_bytes > MAX_RECENT_BYTES
        {
            let Some((_, oldest_key)) = self.completed_order.first_key_value() else {
                break;
            };
            let oldest_key = oldest_key.clone();
            self.take_completion(&oldest_key);
        }
    }

    fn take_completion(&mut self, key: &FragmentKey) -> Option<CompletedDatagram> {
        let completed = self.recently_completed.remove(key)?;
        self.completed_bytes -= completed.memory_bytes() + key.vlan_context.memory_bytes();
        self.completed_order.remove(&completed.arrival_order);
        Some(completed)
    }

    fn remember_non_dns(
        &mut self,
        key: FragmentKey,
        observed_timestamp: i64,
        reuse_cutoff_timestamp: Option<i64>,
    ) {
        let reuse_cutoff_timestamp = reuse_cutoff_timestamp.max(
            self.take_non_dns(&key)
                .and_then(|entry| entry.reuse_cutoff_timestamp),
        );
        let arrival_order = self.next_non_dns_order;
        self.next_non_dns_order = self.next_non_dns_order.wrapping_add(1);
        self.non_dns_bytes += RECENT_ENTRY_OVERHEAD_ESTIMATE + key.vlan_context.memory_bytes();
        self.non_dns_order.insert(arrival_order, key.clone());
        self.known_non_dns.insert(
            key,
            NonDnsKey {
                observed_timestamp,
                arrival_order,
                reuse_cutoff_timestamp,
            },
        );
        while self.known_non_dns.len() > MAX_NON_DNS_KEYS || self.non_dns_bytes > MAX_NON_DNS_BYTES
        {
            let Some((_, oldest_key)) = self.non_dns_order.first_key_value() else {
                break;
            };
            let oldest_key = oldest_key.clone();
            self.take_non_dns(&oldest_key);
        }
    }

    fn take_non_dns(&mut self, key: &FragmentKey) -> Option<NonDnsKey> {
        let known = self.known_non_dns.remove(key)?;
        self.non_dns_bytes -= RECENT_ENTRY_OVERHEAD_ESTIMATE + key.vlan_context.memory_bytes();
        self.non_dns_order.remove(&known.arrival_order);
        Some(known)
    }

    fn recent_retention_micros(&self) -> i64 {
        self.timeout_micros.max(MIN_RECENT_RETENTION_MICROS)
    }

    fn expire_completed_key_at(&mut self, key: &FragmentKey, timestamp: i64) {
        if !self.monotonic_capture {
            // Capture timestamps may regress arbitrarily in normal mode. The
            // entry and byte caps bound this history instead.
            return;
        }
        let expired = self.recently_completed.get(key).is_some_and(|entry| {
            timestamp.saturating_sub(entry.observed_timestamp) > self.recent_retention_micros()
        });
        if expired {
            self.take_completion(key);
        }
    }

    fn expire_non_dns_key_at(&mut self, key: &FragmentKey, timestamp: i64) {
        if !self.monotonic_capture {
            return;
        }
        let expired = self.known_non_dns.get(key).is_some_and(|entry| {
            timestamp.saturating_sub(entry.observed_timestamp) > self.recent_retention_micros()
        });
        if expired {
            self.take_non_dns(key);
        }
    }

    fn expire_recent_completions(&mut self) {
        if !self.monotonic_capture {
            return;
        }
        let Some(frontier) = self.max_seen_timestamp else {
            return;
        };
        while let Some((_, key)) = self.completed_order.first_key_value() {
            let key = key.clone();
            let completed = self
                .recently_completed
                .get(&key)
                .expect("completion order references a cached datagram");
            if frontier.saturating_sub(completed.observed_timestamp)
                <= self.recent_retention_micros()
            {
                break;
            }
            self.take_completion(&key);
        }
    }

    fn expire_non_dns_keys(&mut self) {
        if !self.monotonic_capture {
            return;
        }
        let Some(frontier) = self.max_seen_timestamp else {
            return;
        };
        while let Some((_, key)) = self.non_dns_order.first_key_value() {
            let key = key.clone();
            let known = self
                .known_non_dns
                .get(&key)
                .expect("non-DNS order references a cached key");
            if frontier.saturating_sub(known.observed_timestamp) <= self.recent_retention_micros() {
                break;
            }
            self.take_non_dns(&key);
        }
    }

    fn expire_old(&mut self, output: &mut PacketBatch) {
        if !self.monotonic_capture {
            // A timestamp regression can otherwise expire adjacent capture fragments.
            // Entry limits and EOF still bound incomplete state in this mode.
            return;
        }
        let Some(frontier) = self.max_seen_timestamp else {
            return;
        };
        let mut stale: Vec<(u64, FragmentKey)> = self
            .pending
            .iter()
            .filter_map(|(key, entry)| {
                (frontier.saturating_sub(entry.first_seen_timestamp) > self.timeout_micros)
                    .then_some((entry.arrival_order, key.clone()))
            })
            .collect();
        stale.sort_unstable_by_key(|(arrival_order, _)| *arrival_order);
        // Match the arrival order used by EOF and capacity eviction.
        for (_, key) in stale {
            if let Some(entry) = self.take_entry(&key)
                && let Some(first) = entry.into_fallback()
            {
                output.push(first);
            }
        }
    }

    fn expire_key_at(&mut self, key: &FragmentKey, timestamp: i64, output: &mut PacketBatch) {
        if !self.monotonic_capture {
            return;
        }
        let expired = self.pending.get(key).is_some_and(|entry| {
            timestamp.saturating_sub(entry.first_seen_timestamp) > self.timeout_micros
        });
        if expired
            && let Some(entry) = self.take_entry(key)
            && let Some(first) = entry.into_fallback()
        {
            output.push(first);
        }
    }

    fn enforce_limits(&mut self, output: &mut PacketBatch) {
        while self.pending.len() > MAX_PENDING_DATAGRAMS || self.pending_bytes > MAX_PENDING_BYTES {
            let Some((_, key)) = self.arrival_order.first_key_value() else {
                break;
            };
            let key = key.clone();
            if let Some(entry) = self.take_entry(&key)
                && let Some(first) = entry.into_fallback()
            {
                output.push(first);
            }
        }
    }
}

/// A checked exclusive fence; saturated capture timestamps have unknown provenance.
fn recovery_cutoff(old_max: i64, timestamp: i64, gap: i64) -> Option<i64> {
    if matches!(old_max, i64::MIN | i64::MAX) || matches!(timestamp, i64::MIN | i64::MAX) {
        return None;
    }
    let old_max = i128::from(old_max);
    let gap = i128::from(gap);
    if i128::from(timestamp) - old_max <= gap {
        return None;
    }
    i64::try_from(old_max + gap).ok()
}

fn classify_fragment(packet: &PacketData) -> FragmentInput {
    let bytes = packet.data.as_slice();
    let Ok((ethertype, l3_offset, vlan_context)) =
        super::parser::ethernet_ethertype_and_payload_offset(bytes)
    else {
        return FragmentInput::Ordinary;
    };
    if ethertype != ETHERTYPE_IPV4 || bytes.len() < l3_offset + IPV4_MIN_HEADER_LEN {
        return FragmentInput::Ordinary;
    }
    let ip = &bytes[l3_offset..];
    if ip[0] >> 4 != 4 {
        return FragmentInput::Ordinary;
    }
    let flags = u16::from_be_bytes([ip[6], ip[7]]);
    let offset = usize::from(flags & FRAGMENT_OFFSET_MASK) * 8;
    let more_fragments = flags & MORE_FRAGMENTS != 0;
    if !more_fragments && offset == 0 {
        return FragmentInput::Ordinary;
    }
    if ip[9] != IP_PROTOCOL_UDP {
        return FragmentInput::Skip;
    }
    let header_len = usize::from(ip[0] & 0x0f) * 4;
    let total_length = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if header_len < IPV4_MIN_HEADER_LEN
        || header_len > ip.len()
        || total_length < header_len
        || total_length > ip.len()
        || flags & RESERVED_FLAG != 0
        || flags & DONT_FRAGMENT != 0
    {
        return FragmentInput::Skip;
    }
    let payload = &ip[header_len..total_length];
    let Some(end) = offset.checked_add(payload.len()) else {
        return FragmentInput::Skip;
    };
    if payload.is_empty()
        || end > usize::from(u16::MAX) - IPV4_MIN_HEADER_LEN
        || (more_fragments && !payload.len().is_multiple_of(8))
    {
        return FragmentInput::Skip;
    }
    let key = FragmentKey {
        source: ip[12..16].try_into().expect("IPv4 minimum header checked"),
        destination: ip[16..20].try_into().expect("IPv4 minimum header checked"),
        identification: u16::from_be_bytes([ip[4], ip[5]]),
        vlan_context,
    };
    let first_udp_length = if offset == 0 {
        if payload.len() < UDP_HEADER_LEN {
            return FragmentInput::Skip;
        }
        let source_port = u16::from_be_bytes([payload[0], payload[1]]);
        let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
        if source_port != DNS_PORT && destination_port != DNS_PORT {
            return FragmentInput::NonDnsFirst(key);
        }
        let udp_length = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
        if udp_length < UDP_HEADER_LEN
            || udp_length <= payload.len()
            || udp_length > usize::from(u16::MAX) - header_len
        {
            return FragmentInput::Skip;
        }
        Some(udp_length)
    } else {
        None
    };
    FragmentInput::Part(FragmentPart {
        key,
        offset,
        payload: payload.into(),
        more_fragments,
        first_udp_length,
        first_header_len: (offset == 0).then_some(header_len),
        first_l3_offset: (offset == 0).then_some(l3_offset),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(offset: usize, more: bool, ordinal: u64, timestamp: i64) -> PacketData {
        let dns: [u8; 32] = [
            0x12, 0x34, 0x80, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 4, b't', b'e', b's', b't', 0,
            0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut udp = Vec::from([0_u8; UDP_HEADER_LEN]);
        udp[0..2].copy_from_slice(&DNS_PORT.to_be_bytes());
        udp[2..4].copy_from_slice(&53000_u16.to_be_bytes());
        udp.extend_from_slice(&dns);
        let udp_length = udp.len() as u16;
        udp[4..6].copy_from_slice(&udp_length.to_be_bytes());
        let fragment_len = if more { 24 } else { udp.len() - offset };
        let payload = &udp[offset..offset + fragment_len];
        let mut frame = vec![0_u8; ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18]
            .copy_from_slice(&((IPV4_MIN_HEADER_LEN + payload.len()) as u16).to_be_bytes());
        frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
        let flags = ((offset / 8) as u16) | if more { MORE_FRAGMENTS } else { 0 };
        frame[20..22].copy_from_slice(&flags.to_be_bytes());
        frame[23] = IP_PROTOCOL_UDP;
        frame[26..30].copy_from_slice(&[192, 0, 2, 53]);
        frame[30..34].copy_from_slice(&[192, 0, 2, 1]);
        frame.extend_from_slice(payload);
        PacketData {
            data: PacketPayload::owned(frame.into_boxed_slice()),
            timestamp_micros: timestamp,
            packet_ordinal: ordinal,
        }
    }

    fn non_dns_first(ordinal: u64, timestamp: i64) -> PacketData {
        let mut packet = packet(0, true, ordinal, timestamp);
        let mut bytes = packet.data.as_slice().to_vec();
        let udp_offset = ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        bytes[udp_offset..udp_offset + 4].copy_from_slice(&[0x04, 0xd2, 0x10, 0xe1]);
        packet.data = PacketPayload::owned(bytes.into_boxed_slice());
        packet
    }

    fn tagged_packet(mut packet: PacketData, tags: &[(u16, u16)]) -> PacketData {
        let bytes = packet.data.as_slice();
        let mut tagged = Vec::with_capacity(bytes.len() + tags.len() * 4);
        tagged.extend_from_slice(&bytes[..12]);
        for &(ethertype, vlan_id) in tags {
            tagged.extend_from_slice(&ethertype.to_be_bytes());
            tagged.extend_from_slice(&vlan_id.to_be_bytes());
        }
        tagged.extend_from_slice(&bytes[12..]);
        packet.data = PacketPayload::owned(tagged.into_boxed_slice());
        packet
    }

    fn changed_first(ordinal: u64, timestamp: i64) -> PacketData {
        let mut first = packet(0, true, ordinal, timestamp);
        let mut bytes = first.data.as_slice().to_vec();
        bytes[ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN] ^= 1;
        first.data = PacketPayload::owned(bytes.into_boxed_slice());
        first
    }

    fn with_id(mut packet: PacketData, id: u16) -> PacketData {
        let mut bytes = packet.data.as_slice().to_vec();
        bytes[ETHERNET_HEADER_LEN + 4..ETHERNET_HEADER_LEN + 6].copy_from_slice(&id.to_be_bytes());
        packet.data = PacketPayload::owned(bytes.into_boxed_slice());
        packet
    }

    fn recovering() -> Ipv4FragmentReassembler {
        Ipv4FragmentReassembler::new(1_200_000, false).with_reuse_gap_micros(Some(1_000))
    }

    #[test]
    fn late_first_recovers_live_and_rejected_candidates_only_when_enabled() {
        for enabled in [false, true] {
            for rejected in [false, true] {
                let mut assembler = Ipv4FragmentReassembler::new(1_200_000, false)
                    .with_reuse_gap_micros(enabled.then_some(120_000_000));
                assembler.process_batch(vec![packet(0, true, 1, 100)]);
                if rejected {
                    assert!(
                        assembler
                            .process_batch(vec![changed_first(2, 101)])
                            .0
                            .is_empty()
                    );
                }
                let (output, pending) = assembler.process_batch(vec![
                    changed_first(3, 121_000_100),
                    packet(24, false, 4, 121_000_101),
                ]);
                assert_eq!(
                    output.len(),
                    if enabled {
                        1 + usize::from(!rejected)
                    } else {
                        0
                    }
                );
                assert_eq!(pending, None);
                if enabled {
                    assert_eq!(output.last().unwrap().packet_ordinal, 4);
                    assert_eq!(&output.last().unwrap().data[20..22], &[0, 0]);
                    if !rejected {
                        assert_eq!(output[0].packet_ordinal, 1);
                        assert_eq!(&output[0].data[20..22], &MORE_FRAGMENTS.to_be_bytes());
                    }
                }
                assert!(assembler.finish().is_empty());
                assert!(assembler.finish().is_empty());
            }
        }
    }

    #[test]
    fn reuse_gap_is_strict_and_can_restart_an_identical_first() {
        for identical in [false, true] {
            for extra_micros in [0, 1] {
                let mut assembler = recovering();
                assembler.process_batch(vec![packet(0, true, 1, 100)]);
                let timestamp = 1_100 + extra_micros;
                let first = if identical {
                    packet(0, true, 2, timestamp)
                } else {
                    changed_first(2, timestamp)
                };
                let (output, _) = assembler.process_batch(vec![first]);
                assert_eq!(output.len(), extra_micros as usize);
                let entry = assembler.pending.values().next().unwrap();
                assert_eq!(
                    entry.reuse_cutoff_timestamp,
                    (extra_micros == 1).then_some(1_100)
                );
                assert_eq!(
                    entry.first_seen_timestamp,
                    if extra_micros == 1 { timestamp } else { 100 }
                );
                let (complete, _) =
                    assembler.process_batch(vec![packet(24, false, 3, timestamp + 1)]);
                assert_eq!(complete.len(), usize::from(identical || extra_micros == 1));
                assert!(assembler.finish().is_empty());
            }
        }
    }

    #[test]
    fn admitted_duplicates_tails_and_rejections_advance_candidate_max() {
        for observation in [
            packet(0, true, 2, 150),
            packet(32, false, 2, 150),
            packet(16, false, 2, 150),
        ] {
            let mut assembler = recovering();
            assembler.process_batch(vec![packet(0, true, 1, 100), observation]);
            assert_eq!(
                assembler
                    .pending
                    .values()
                    .next()
                    .unwrap()
                    .max_observed_timestamp,
                150
            );
            assert!(
                assembler
                    .process_batch(vec![changed_first(3, 1_101)])
                    .0
                    .is_empty()
            );
            let entry = assembler.pending.values().next().unwrap();
            assert!(
                entry.rejected,
                "a fresh observation prevents premature recovery"
            );
            assert_eq!(entry.max_observed_timestamp, 1_101);
            assembler.process_batch(vec![packet(16, false, 4, 1_250)]);
            assert_eq!(
                assembler
                    .pending
                    .values()
                    .next()
                    .unwrap()
                    .max_observed_timestamp,
                1_250
            );
            assert!(
                assembler
                    .process_batch(vec![changed_first(5, 2_250)])
                    .0
                    .is_empty()
            );
            let (output, _) =
                assembler.process_batch(vec![changed_first(6, 3_251), packet(24, false, 7, 3_252)]);
            assert_eq!(output.len(), 1, "rejected generations have no fallback");
            assert_eq!(output[0].packet_ordinal, 7);
            assert!(assembler.finish().is_empty());
        }
    }

    #[test]
    fn saved_cutoff_discards_old_first_tail_and_non_dns_before_and_after_completion() {
        let mut assembler = recovering();
        assembler.process_batch(vec![packet(0, true, 1, 100)]);
        assert_eq!(
            assembler
                .process_batch(vec![changed_first(2, 1_101)])
                .0
                .len(),
            1
        );
        for completed in [false, true] {
            for timestamp in [-10_000, 100, 1_100] {
                for replay in [
                    packet(0, true, 10, timestamp),
                    packet(24, false, 11, timestamp),
                    non_dns_first(12, timestamp),
                ] {
                    let pending_bytes = assembler.pending_bytes;
                    let completed_bytes = assembler.completed_bytes;
                    assert!(assembler.process_batch(vec![replay]).0.is_empty());
                    assert_eq!(assembler.pending_bytes, pending_bytes);
                    assert_eq!(assembler.completed_bytes, completed_bytes);
                    assert!(assembler.known_non_dns.is_empty());
                    if !completed {
                        let entry = assembler.pending.values().next().unwrap();
                        assert!(!entry.rejected);
                        assert_eq!(entry.max_observed_timestamp, 1_101);
                    } else {
                        assert!(assembler.pending.is_empty());
                    }
                }
            }
            if !completed {
                assert_eq!(
                    assembler
                        .process_batch(vec![packet(24, false, 3, 1_102)])
                        .0
                        .len(),
                    1
                );
                assert_eq!(
                    assembler
                        .recently_completed
                        .values()
                        .next()
                        .unwrap()
                        .reuse_cutoff_timestamp,
                    Some(1_100)
                );
            }
        }
        assert!(assembler.finish().is_empty());
    }

    #[test]
    fn cutoff_survives_non_dns_and_duplicate_completion_transfers() {
        let mut assembler = recovering();
        assembler.process_batch(vec![packet(0, true, 1, 100), changed_first(2, 1_101)]);
        assembler.process_batch(vec![non_dns_first(3, 1_102)]);
        assert!(assembler.pending.is_empty());
        assert_eq!(
            assembler
                .known_non_dns
                .values()
                .next()
                .unwrap()
                .reuse_cutoff_timestamp,
            Some(1_100)
        );
        assert!(
            assembler
                .process_batch(vec![packet(0, true, 4, 1_100)])
                .0
                .is_empty()
        );
        assert_eq!(assembler.known_non_dns.len(), 1);
        assert_eq!(
            assembler
                .process_batch(vec![changed_first(5, 1_103), packet(24, false, 6, 1_104)])
                .0
                .len(),
            1
        );
        assembler.process_batch(vec![non_dns_first(7, 1_105)]);
        assert!(
            assembler
                .process_batch(vec![changed_first(8, 1_106), packet(24, false, 9, 1_107)])
                .0
                .is_empty()
        );
        assert!(assembler.pending.is_empty());
        assert!(assembler.known_non_dns.is_empty());
        assert_eq!(
            assembler
                .recently_completed
                .values()
                .next()
                .unwrap()
                .reuse_cutoff_timestamp,
            Some(1_100)
        );
        assert!(
            assembler
                .process_batch(vec![
                    packet(0, true, 10, 1_100),
                    packet(24, false, 11, 1_100)
                ])
                .0
                .is_empty()
        );
        assert!(assembler.finish().is_empty());
    }

    #[test]
    fn completed_history_alone_does_not_restart_but_pending_duplicate_can() {
        let mut assembler = recovering();
        assert_eq!(
            assembler
                .process_batch(vec![packet(0, true, 1, 100), packet(24, false, 2, 101)])
                .0
                .len(),
            1
        );
        assert!(
            assembler
                .process_batch(vec![packet(0, true, 3, 1_102), packet(24, false, 4, 1_103)])
                .0
                .is_empty()
        );
        assert_eq!(
            assembler
                .recently_completed
                .values()
                .next()
                .unwrap()
                .reuse_cutoff_timestamp,
            None
        );
        assembler.process_batch(vec![packet(0, true, 5, 1_104)]);
        assert!(
            assembler
                .process_batch(vec![packet(0, true, 6, 2_105)])
                .0
                .is_empty(),
            "duplicate candidate has no prefix fallback"
        );
        assert!(
            assembler.recently_completed.is_empty(),
            "restart retires the old payload history"
        );
        assert_eq!(
            assembler
                .process_batch(vec![packet(24, false, 7, 2_106)])
                .0
                .len(),
            1
        );
        assert!(assembler.finish().is_empty());
    }

    #[test]
    fn pending_duplicate_retains_fence_when_completion_cache_is_evicted() {
        let mut assembler = recovering();
        assembler.process_batch(vec![
            packet(0, true, 1, 100),
            changed_first(2, 1_101),
            packet(24, false, 3, 1_102),
        ]);
        let key = assembler.recently_completed.keys().next().unwrap().clone();
        assembler.process_batch(vec![changed_first(4, 1_103)]);
        for id in 0..MAX_RECENT_COMPLETIONS {
            let mut other = key.clone();
            other.identification = id as u16;
            assembler.remember_completion(other, Arc::from(&b"payload"[..]), 2_000, None);
        }
        assert!(!assembler.recently_completed.contains_key(&key));
        assert!(
            assembler
                .process_batch(vec![packet(24, false, 5, 1_104)])
                .0
                .is_empty()
        );
        assert_eq!(
            assembler
                .recently_completed
                .get(&key)
                .unwrap()
                .reuse_cutoff_timestamp,
            Some(1_100)
        );
        assert!(
            assembler
                .process_batch(vec![packet(0, true, 6, 1_100), packet(24, false, 7, 1_100)])
                .0
                .is_empty()
        );
        assert!(assembler.finish().is_empty());
        assert!(assembler.recently_completed.len() <= MAX_RECENT_COMPLETIONS);
        assert_eq!(
            assembler.completed_bytes,
            assembler
                .recently_completed
                .iter()
                .map(|(key, entry)| entry.memory_bytes() + key.vlan_context.memory_bytes())
                .sum::<usize>()
        );
    }

    #[test]
    fn capacity_eviction_releases_new_prefix_once_and_ends_its_replay_fence() {
        let mut assembler = recovering();
        assert_eq!(
            assembler
                .process_batch(vec![packet(0, true, 1, 100), changed_first(2, 1_101)])
                .0
                .len(),
            1
        );
        let input = (0..MAX_PENDING_DATAGRAMS)
            .map(|id| with_id(packet(0, true, id as u64 + 1_000, 300), id as u16 + 20_000))
            .collect();
        let (evicted, _) = assembler.process_batch(input);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].packet_ordinal, 2);
        assert_eq!(assembler.pending.len(), MAX_PENDING_DATAGRAMS);
        assert!(assembler.pending_bytes <= MAX_PENDING_BYTES);
        // All owners of this key were evicted. Older replay is now eligible again.
        let (output, _) = assembler.process_batch(vec![
            packet(0, true, 90_000, 100),
            packet(24, false, 90_001, 101),
        ]);
        assert_eq!(
            output
                .iter()
                .filter(|packet| packet.packet_ordinal == 90_001)
                .count(),
            1
        );
        assert!(
            assembler
                .finish()
                .iter()
                .all(|packet| packet.packet_ordinal != 2)
        );
        assert_eq!(assembler.pending_bytes, 0);
    }

    #[test]
    fn recovery_is_independent_of_other_addresses_vlan_and_global_future_time() {
        for dimension in 0..3 {
            let mut assembler = recovering();
            assembler.process_batch(vec![packet(0, true, 1, 100)]);
            // Admitted timestamp regressions preserve the candidate's maximum.
            assembler.process_batch(vec![packet(0, true, 2, -100)]);
            let mut unrelated = packet(0, true, 3, i64::MAX - 1);
            if dimension == 2 {
                unrelated = tagged_packet(unrelated, &[(0x8100, 100)]);
            } else {
                let mut bytes = unrelated.data.as_slice().to_vec();
                bytes[if dimension == 0 { 29 } else { 33 }] ^= 1;
                unrelated.data = PacketPayload::owned(bytes.into_boxed_slice());
            }
            assembler.process_batch(vec![unrelated]);
            let (output, pending) =
                assembler.process_batch(vec![changed_first(4, 1_101), packet(24, false, 5, 1_102)]);
            assert_eq!(output.len(), 2);
            assert_eq!(output[0].packet_ordinal, 1);
            assert_eq!(output[1].packet_ordinal, 5);
            assert_eq!(pending, Some(i64::MAX - 1));
            let leftover = assembler.finish();
            assert_eq!(leftover.len(), 1);
            assert_eq!(leftover[0].packet_ordinal, 3);
        }
    }

    #[test]
    fn recovery_and_eof_are_independent_of_batch_boundaries() {
        for chunk_size in [1, 2, 5] {
            let mut assembler = recovering();
            let input = [
                packet(0, true, 1, 100),
                changed_first(2, 1_101),
                packet(24, false, 3, 1_100),
                non_dns_first(4, 100),
                packet(24, false, 5, 1_102),
            ];
            let mut output = Vec::new();
            for chunk in input.chunks(chunk_size) {
                output.extend(assembler.process_batch(chunk.to_vec()).0);
            }
            assert_eq!(
                output
                    .iter()
                    .map(|packet| packet.packet_ordinal)
                    .collect::<Vec<_>>(),
                vec![1, 5]
            );
            assert!(assembler.finish().is_empty());
            assert!(assembler.finish().is_empty());
        }
        let mut assembler = recovering();
        assert_eq!(
            assembler
                .process_batch(vec![packet(0, true, 1, 100), changed_first(2, 1_101)])
                .0
                .len(),
            1
        );
        let fallback = assembler.finish();
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback[0].packet_ordinal, 2);
        assert!(assembler.finish().is_empty());
    }

    #[test]
    fn reuse_preserves_overlap_and_incomplete_coverage_checks() {
        for tail in [packet(16, false, 3, 1_102), packet(32, false, 3, 1_102)] {
            let mut assembler = recovering();
            assembler.process_batch(vec![packet(0, true, 1, 100), changed_first(2, 1_101)]);
            let (output, _) = assembler.process_batch(vec![tail]);
            assert!(output.is_empty());
            // A missing byte range remains incomplete; an overlap becomes rejected.
            let (output, _) = assembler.process_batch(vec![packet(16, false, 4, 1_103)]);
            assert!(output.is_empty());
            assert!(assembler.pending.values().next().unwrap().rejected);
            assert!(assembler.finish().is_empty());
        }
    }

    #[test]
    fn reuse_keeps_udp_mf_and_final_boundary_validation() {
        for (offset, payload_len, more) in [(32_u16, 16, false), (32, 8, true), (24, 8, false)] {
            let mut assembler = recovering();
            assembler.process_batch(vec![packet(0, true, 1, 100), changed_first(2, 1_101)]);
            let mut tail = packet(24, false, 3, 1_102);
            let mut bytes = tail.data.as_slice().to_vec();
            bytes.truncate(ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + payload_len);
            bytes[16..18]
                .copy_from_slice(&((IPV4_MIN_HEADER_LEN + payload_len) as u16).to_be_bytes());
            let flags = (offset / 8) | if more { MORE_FRAGMENTS } else { 0 };
            bytes[20..22].copy_from_slice(&flags.to_be_bytes());
            tail.data = PacketPayload::owned(bytes.into_boxed_slice());
            assert!(assembler.process_batch(vec![tail]).0.is_empty());
            assert!(assembler.pending.values().next().unwrap().rejected);
            assert!(assembler.finish().is_empty());
        }
    }

    #[test]
    fn recovery_timestamp_arithmetic_handles_extremes_without_saturation() {
        let cases = [
            (i64::MIN, 0, 1_000, false),
            (0, i64::MAX, 1_000, false),
            (i64::MAX, i64::MAX - 1, 1_000, false),
            (i64::MAX - 10, i64::MAX - 1, 1_000, false),
            (i64::MIN + 1, i64::MIN + 1_002, 1_000, true),
            (i64::MAX - 2_000, i64::MAX - 999, 1_000, true),
            (i64::MIN + 1, i64::MAX - 1, 1_000, true),
            (0, i64::MAX - 1, (i64::MAX / 1_000) * 1_000, true),
        ];
        for (old, new, gap, allowed) in cases {
            let mut assembler =
                Ipv4FragmentReassembler::new(1_200_000, false).with_reuse_gap_micros(Some(gap));
            assembler.process_batch(vec![packet(0, true, 1, old)]);
            let (output, _) =
                assembler.process_batch(vec![changed_first(2, new), packet(24, false, 3, new)]);
            assert_eq!(
                output.len(),
                if allowed { 2 } else { 0 },
                "old={old}, new={new}, gap={gap}"
            );
            assert!(assembler.finish().is_empty());
        }
    }

    #[test]
    fn reuse_metadata_fits_existing_accounting_estimates() {
        use std::mem::size_of;
        assert!(size_of::<PendingDatagram>() + size_of::<FragmentKey>() <= ENTRY_OVERHEAD_ESTIMATE);
        assert!(
            size_of::<CompletedDatagram>() + size_of::<FragmentKey>()
                <= RECENT_ENTRY_OVERHEAD_ESTIMATE
        );
        assert!(
            size_of::<NonDnsKey>() + size_of::<FragmentKey>() <= RECENT_ENTRY_OVERHEAD_ESTIMATE
        );
        let mut assembler = recovering();
        assembler.process_batch(vec![
            tagged_packet(packet(0, true, 1, 100), &[(0x8100, 10)]),
            tagged_packet(changed_first(2, 1_101), &[(0x8100, 10)]),
        ]);
        assert_eq!(
            assembler.pending_bytes,
            assembler
                .pending
                .iter()
                .map(|(key, entry)| entry.memory_bytes() + key.vlan_context.memory_bytes())
                .sum::<usize>()
        );
        assembler.process_batch(vec![tagged_packet(
            non_dns_first(3, 1_102),
            &[(0x8100, 10)],
        )]);
        assert_eq!(assembler.pending_bytes, 0);
        assert_eq!(assembler.non_dns_bytes, RECENT_ENTRY_OVERHEAD_ESTIMATE + 4);
        assert_eq!(
            assembler
                .known_non_dns
                .values()
                .next()
                .unwrap()
                .reuse_cutoff_timestamp,
            Some(1_100)
        );
    }

    #[test]
    fn non_dns_first_discards_tails_before_and_after_it() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let (output, pending) = reassembler.process_batch(vec![packet(24, false, 1, 100)]);
        assert!(output.is_empty());
        assert_eq!(pending, Some(100));

        let (output, pending) = reassembler.process_batch(vec![non_dns_first(2, 101)]);
        assert!(output.is_empty());
        assert_eq!(pending, None);
        assert_eq!(reassembler.pending_bytes, 0);

        let (output, pending) = reassembler.process_batch(vec![packet(24, false, 3, 102)]);
        assert!(output.is_empty());
        assert_eq!(pending, None);
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn dns_first_with_reused_id_assembles_after_non_dns_first() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let (output, pending) = reassembler.process_batch(vec![
            non_dns_first(1, 100),
            packet(24, false, 2, 101),
            packet(0, true, 3, 102),
            packet(24, false, 4, 103),
        ]);
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].timestamp_micros, 103);
        assert_eq!(pending, None);
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn non_dns_history_is_bounded_without_eviction_of_completed_dns() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let (complete, _) =
            reassembler.process_batch(vec![packet(0, true, 1, 100), packet(24, false, 2, 101)]);
        assert_eq!(complete.len(), 1);
        let completed_key = reassembler
            .recently_completed
            .keys()
            .next()
            .expect("DNS completion is remembered")
            .clone();

        for id in 0..=MAX_NON_DNS_KEYS {
            let mut first = non_dns_first(id as u64 + 3, id as i64 + 102);
            let mut bytes = first.data.as_slice().to_vec();
            bytes[ETHERNET_HEADER_LEN + 4..ETHERNET_HEADER_LEN + 6]
                .copy_from_slice(&(id as u16).to_be_bytes());
            first.data = PacketPayload::owned(bytes.into_boxed_slice());
            reassembler.process_batch(vec![first]);
        }
        assert!(reassembler.known_non_dns.len() <= MAX_NON_DNS_KEYS);
        assert!(reassembler.non_dns_bytes <= MAX_NON_DNS_BYTES);
        assert!(reassembler.recently_completed.contains_key(&completed_key));

        let (duplicate, _) = reassembler.process_batch(vec![packet(0, true, 5_000, 5_000)]);
        assert!(duplicate.is_empty());
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn tagged_fragments_assemble_without_cross_vlan_coalescence() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let vlan_one = &[(0x8100, 100)];
        let vlan_two = &[(0x88a8, 200), (0x8100, 100)];
        let (output, pending) = reassembler.process_batch(vec![
            tagged_packet(packet(0, true, 1, 100), vlan_one),
            tagged_packet(packet(24, false, 2, 101), vlan_two),
        ]);
        assert!(output.is_empty());
        assert_eq!(pending, Some(100));

        let (output, pending) = reassembler.process_batch(vec![
            tagged_packet(packet(0, true, 3, 102), vlan_two),
            tagged_packet(packet(24, false, 4, 103), vlan_one),
        ]);
        assert_eq!(output.len(), 2);
        assert_eq!(pending, None);
        for (packet, (tags, l3_offset)) in output.iter().zip([
            (vlan_two.as_slice(), ETHERNET_HEADER_LEN + 8),
            (vlan_one.as_slice(), ETHERNET_HEADER_LEN + 4),
        ]) {
            let bytes = packet.data.as_slice();
            assert_eq!(bytes.len(), l3_offset + IPV4_MIN_HEADER_LEN + 40);
            assert_eq!(ipv4_header_checksum(&bytes[l3_offset..l3_offset + 20]), 0);
            assert_eq!(&bytes[l3_offset + 6..l3_offset + 8], &[0, 0]);
            let expected = tagged_packet(self::packet(0, true, 0, 0), tags);
            assert_eq!(&bytes[..l3_offset], &expected.data[..l3_offset]);
        }
    }

    #[test]
    fn tagged_fragments_ignore_priority_and_drop_eligibility_bits() {
        let mut assembler = Ipv4FragmentReassembler::new(1_200_000, false);
        let first = tagged_packet(packet(0, true, 1, 100), &[(0x88a8, 10), (0x8100, 100)]);
        let last = tagged_packet(
            packet(24, false, 2, 101),
            &[(0x88a8, 0xb00a), (0x8100, 0xf064)],
        );
        let (output, pending) = assembler.process_batch(vec![first, last]);
        assert_eq!(pending, None);
        assert_eq!(
            output.len(),
            1,
            "QoS changes do not change the fragment key"
        );
        let meta = super::super::DnsProcessor::packet_routing_meta(output[0].data.as_slice())
            .expect("reassembled tagged datagram routes");
        assert!(!meta.partial_first_ipv4_fragment);
    }

    #[test]
    fn assembles_across_batches_once_at_final_fragment_time() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let (first, pending) = reassembler.process_batch(vec![packet(0, true, 4, 100)]);
        assert!(first.is_empty());
        assert_eq!(pending, Some(100));
        let (complete, pending) = reassembler.process_batch(vec![packet(24, false, 5, 101)]);
        assert_eq!(pending, None);
        assert_eq!(complete.len(), 1);
        let frame = &complete[0];
        assert_eq!((frame.timestamp_micros, frame.packet_ordinal), (101, 5));
        assert_eq!(&frame.data[20..22], &[0, 0]);
        assert_eq!(ipv4_header_checksum(&frame.data[14..34]), 0);
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn completed_datagram_does_not_fallback_duplicate_first_fragment() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let (complete, pending) =
            reassembler.process_batch(vec![packet(0, true, 1, 100), packet(24, false, 2, 101)]);
        assert_eq!(complete.len(), 1);
        assert_eq!(pending, None);

        let (duplicate, pending) = reassembler.process_batch(vec![packet(0, true, 3, 102)]);
        assert!(duplicate.is_empty());
        assert_eq!(pending, Some(102));
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn completed_datagram_is_not_emitted_again_from_duplicate_fragments() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let (output, _) = reassembler.process_batch(vec![
            packet(0, true, 1, 100),
            packet(24, false, 2, 101),
            packet(24, false, 3, 102),
            packet(0, true, 4, 103),
            packet(0, true, 5, 104),
            packet(24, false, 6, 105),
        ]);
        assert_eq!(output.len(), 1);
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn reused_ipv4_id_with_different_payload_still_assembles() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let (original, _) =
            reassembler.process_batch(vec![packet(0, true, 1, 100), packet(24, false, 2, 101)]);
        assert_eq!(original.len(), 1);

        let mut changed_last = packet(24, false, 4, 103);
        let mut bytes = changed_last.data.as_slice().to_vec();
        *bytes.last_mut().expect("fragment has payload") ^= 1;
        changed_last.data = PacketPayload::owned(bytes.into_boxed_slice());
        let (different_last, _) =
            reassembler.process_batch(vec![packet(0, true, 3, 102), changed_last]);
        assert_eq!(different_last.len(), 1);
        assert_ne!(
            different_last[0].data.as_slice(),
            original[0].data.as_slice()
        );

        let mut changed_first = packet(0, true, 5, 104);
        let mut bytes = changed_first.data.as_slice().to_vec();
        bytes[ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN] ^= 1;
        changed_first.data = PacketPayload::owned(bytes.into_boxed_slice());
        let (different_first, _) =
            reassembler.process_batch(vec![changed_first, packet(24, false, 6, 105)]);
        assert_eq!(different_first.len(), 1);
        assert_ne!(
            different_first[0].data.as_slice(),
            different_last[0].data.as_slice()
        );
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn reused_ipv4_id_with_new_first_assembles_after_identical_orphan_last() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let (original, _) =
            reassembler.process_batch(vec![packet(0, true, 1, 100), packet(24, false, 2, 101)]);
        assert_eq!(original.len(), 1);

        let mut changed_first = packet(0, true, 4, 103);
        let mut bytes = changed_first.data.as_slice().to_vec();
        bytes[ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN] ^= 1;
        changed_first.data = PacketPayload::owned(bytes.into_boxed_slice());
        let (new_datagram, pending) =
            reassembler.process_batch(vec![packet(24, false, 3, 102), changed_first]);
        assert_eq!(new_datagram.len(), 1);
        assert_eq!(new_datagram[0].timestamp_micros, 102);
        assert_eq!(pending, None);
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn timestamp_regression_does_not_forget_recent_completion() {
        let mut reassembler = Ipv4FragmentReassembler::new(100, false);
        let (complete, _) =
            reassembler.process_batch(vec![packet(0, true, 1, 100), packet(24, false, 2, 101)]);
        assert_eq!(complete.len(), 1);
        let (duplicate, _) = reassembler.process_batch(vec![packet(0, true, 3, -10_000_000)]);
        assert!(duplicate.is_empty());
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn duplicate_first_fragment_does_not_fallback_on_timeout() {
        let mut reassembler = Ipv4FragmentReassembler::new(100, true);
        let (complete, _) =
            reassembler.process_batch(vec![packet(0, true, 1, 100), packet(24, false, 2, 101)]);
        assert_eq!(complete.len(), 1);
        reassembler.process_batch(vec![packet(0, true, 3, 102)]);

        let ordinary = PacketData {
            data: PacketPayload::owned(vec![0_u8; ETHERNET_HEADER_LEN].into_boxed_slice()),
            timestamp_micros: 203,
            packet_ordinal: 4,
        };
        let (output, pending) = reassembler.process_batch(vec![ordinary]);
        assert_eq!(output.len(), 1);
        assert_eq!(pending, None);
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn recent_completion_window_expires_and_is_bounded() {
        let mut reassembler = Ipv4FragmentReassembler::new(100, true);
        let (first, _) =
            reassembler.process_batch(vec![packet(0, true, 1, 100), packet(24, false, 2, 101)]);
        assert_eq!(first.len(), 1);

        let (later, _) = reassembler.process_batch(vec![
            packet(0, true, 3, 5_000_102),
            packet(24, false, 4, 5_000_103),
        ]);
        assert_eq!(later.len(), 1);

        for id in 0..=MAX_RECENT_COMPLETIONS {
            reassembler.remember_completion(
                FragmentKey {
                    source: [192, 0, 2, 1],
                    destination: [192, 0, 2, 53],
                    identification: id as u16,
                    vlan_context: VlanContext::default(),
                },
                Arc::<[u8]>::from(&b"payload"[..]),
                5_000_103,
                None,
            );
        }
        assert!(reassembler.recently_completed.len() <= MAX_RECENT_COMPLETIONS);
        assert!(reassembler.completed_bytes <= MAX_RECENT_BYTES);
    }

    #[test]
    fn orphan_later_fragment_can_precede_first() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let (orphan, pending) = reassembler.process_batch(vec![packet(24, false, 4, 100)]);
        assert!(orphan.is_empty());
        assert_eq!(pending, Some(100));
        let (complete, pending) = reassembler.process_batch(vec![packet(0, true, 5, 101)]);
        assert_eq!(complete.len(), 1);
        assert_eq!(pending, None);
        assert_eq!(
            (complete[0].timestamp_micros, complete[0].packet_ordinal),
            (100, 4)
        );
    }

    #[test]
    fn incomplete_first_is_released_once_at_finish() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let (output, pending) = reassembler.process_batch(vec![packet(0, true, 4, 100)]);
        assert!(output.is_empty());
        assert_eq!(pending, Some(100));
        let fallback = reassembler.finish();
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback[0].packet_ordinal, 4);
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn overlapping_segments_discard_datagram_without_prefix_fallback() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        reassembler.process_batch(vec![packet(0, true, 4, 100)]);
        let (output, pending) = reassembler.process_batch(vec![packet(16, false, 5, 101)]);
        assert!(output.is_empty());
        assert_eq!(pending, None);
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn incomplete_first_expires_to_one_prefix() {
        let mut reassembler = Ipv4FragmentReassembler::new(100, true);
        reassembler.process_batch(vec![packet(0, true, 4, 100)]);
        let ordinary = PacketData {
            data: PacketPayload::owned(vec![0_u8; 14].into_boxed_slice()),
            timestamp_micros: 201,
            packet_ordinal: 6,
        };
        let (output, pending) = reassembler.process_batch(vec![ordinary]);
        assert_eq!(output.len(), 2);
        assert_eq!(pending, None);
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn expired_first_fragments_follow_arrival_order() {
        let mut reassembler = Ipv4FragmentReassembler::new(100, true);
        let first_fragments = (1_u16..=8)
            .map(|id| {
                let mut first = packet(0, true, u64::from(id), 100 + i64::from(id));
                let mut bytes = first.data.as_slice().to_vec();
                bytes[ETHERNET_HEADER_LEN + 4..ETHERNET_HEADER_LEN + 6]
                    .copy_from_slice(&id.to_be_bytes());
                first.data = PacketPayload::owned(bytes.into_boxed_slice());
                first
            })
            .collect();
        let (output, pending) = reassembler.process_batch(first_fragments);
        assert!(output.is_empty());
        assert_eq!(pending, Some(101));

        let ordinary = PacketData {
            data: PacketPayload::owned(vec![0_u8; ETHERNET_HEADER_LEN].into_boxed_slice()),
            timestamp_micros: 300,
            packet_ordinal: 9,
        };
        let (output, pending) = reassembler.process_batch(vec![ordinary]);
        assert_eq!(pending, None);
        assert_eq!(
            output
                .iter()
                .map(|packet| packet.packet_ordinal)
                .collect::<Vec<_>>(),
            vec![9, 1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn fragments_too_far_apart_in_same_batch_do_not_assemble() {
        let mut reassembler = Ipv4FragmentReassembler::new(100, true);
        let (output, pending) =
            reassembler.process_batch(vec![packet(0, true, 4, 100), packet(24, false, 5, 201)]);
        assert_eq!(output.len(), 1);
        assert_eq!(
            (output[0].timestamp_micros, output[0].packet_ordinal),
            (100, 4)
        );
        assert_eq!(pending, Some(201));
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn fragment_expiration_requires_monotonic_capture() {
        for monotonic_capture in [false, true] {
            for final_first in [false, true] {
                let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, monotonic_capture);
                let (first_ordinal, final_ordinal) = if final_first { (2, 1) } else { (1, 2) };
                let first_timestamp = 1_100_000 + (first_ordinal as i64 - 1) * 1_300_000;
                let final_timestamp = 1_100_000 + (final_ordinal as i64 - 1) * 1_300_000;
                let first = packet(0, true, first_ordinal, first_timestamp);
                let final_fragment = packet(24, false, final_ordinal, final_timestamp);
                let input = if final_first {
                    vec![final_fragment, first]
                } else {
                    vec![first, final_fragment]
                };

                let (mut output, pending) = reassembler.process_batch(input);
                assert_eq!(
                    pending,
                    monotonic_capture.then_some(2_400_000),
                    "monotonic_capture={monotonic_capture}, final_first={final_first}"
                );
                output.extend(reassembler.finish());
                assert_eq!(output.len(), 1);
                if monotonic_capture {
                    // Expiration retains only the first-fragment fallback in either order.
                    assert_eq!(output[0].timestamp_micros, first_timestamp);
                    assert_eq!(&output[0].data[20..22], &MORE_FRAGMENTS.to_be_bytes());
                } else {
                    assert_eq!(output[0].timestamp_micros, final_timestamp);
                    assert_eq!(output[0].packet_ordinal, final_ordinal);
                    assert_eq!(&output[0].data[20..22], &[0, 0]);
                    assert_eq!(
                        output[0].data.len(),
                        ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + 40
                    );
                }
            }
        }
    }

    #[test]
    fn timestamp_regression_does_not_expire_adjacent_fragments() {
        let mut reassembler = Ipv4FragmentReassembler::new(100, false);
        let unrelated = PacketData {
            data: PacketPayload::owned(vec![0_u8; 14].into_boxed_slice()),
            timestamp_micros: 10_000,
            packet_ordinal: 1,
        };
        let (output, pending) = reassembler.process_batch(vec![
            unrelated,
            packet(0, true, 2, 100),
            packet(24, false, 3, 101),
        ]);
        assert_eq!(output.len(), 2);
        assert_eq!(output[1].timestamp_micros, 101);
        assert_eq!(pending, None);
    }

    #[test]
    fn orphan_final_fragment_holds_monotonic_watermark_until_first_arrives() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200, true);
        let (_, pending) = reassembler.process_batch(vec![packet(24, false, 1, 500)]);
        assert_eq!(pending, Some(500));
        let unrelated = PacketData {
            data: PacketPayload::owned(vec![0_u8; 14].into_boxed_slice()),
            timestamp_micros: 1_300,
            packet_ordinal: 2,
        };
        let (_, pending) = reassembler.process_batch(vec![unrelated]);
        assert_eq!(pending, Some(500));
        let (assembled, pending) = reassembler.process_batch(vec![packet(0, true, 3, 1_400)]);
        assert_eq!(assembled.len(), 1);
        assert_eq!(assembled[0].timestamp_micros, 500);
        assert_eq!(pending, None);
    }

    #[test]
    fn conflicting_fragment_flags_leave_a_tombstone_without_prefix_fallback() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200, true);
        let mut nonfinal = packet(24, false, 2, 101);
        let mut bytes = nonfinal.data.as_slice().to_vec();
        bytes[20..22].copy_from_slice(&(MORE_FRAGMENTS | 3).to_be_bytes());
        nonfinal.data = PacketPayload::owned(bytes.into_boxed_slice());
        let (output, _) = reassembler.process_batch(vec![
            nonfinal,
            packet(24, false, 3, 102),
            packet(0, true, 4, 103),
        ]);
        assert!(output.is_empty());
        assert!(reassembler.finish().is_empty());
    }

    #[test]
    fn nonfinal_payload_at_or_beyond_udp_length_is_rejected_in_both_orders() {
        // The fixture declares UDP Length=40; these eight-byte tails end at 40 and 48.
        for offset in [32_u16, 40] {
            for tail_first in [false, true] {
                let mut reassembler = Ipv4FragmentReassembler::new(1_200, true);
                let (first_ordinal, tail_ordinal) = if tail_first { (2, 1) } else { (1, 2) };
                let mut tail = packet(24, false, tail_ordinal, 99 + tail_ordinal as i64);
                let mut bytes = tail.data.as_slice().to_vec();
                bytes.truncate(ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + 8);
                bytes[16..18].copy_from_slice(&(IPV4_MIN_HEADER_LEN as u16 + 8).to_be_bytes());
                bytes[20..22].copy_from_slice(&(MORE_FRAGMENTS | (offset / 8)).to_be_bytes());
                tail.data = PacketPayload::owned(bytes.into_boxed_slice());
                let first = packet(0, true, first_ordinal, 99 + first_ordinal as i64);
                let input = if tail_first {
                    vec![tail, first]
                } else {
                    vec![first, tail]
                };

                let (output, pending) = reassembler.process_batch(input);
                assert!(
                    output.is_empty(),
                    "offset={offset}, tail_first={tail_first}"
                );
                assert_eq!(pending, None, "offset={offset}, tail_first={tail_first}");
                assert!(
                    reassembler.finish().is_empty(),
                    "invalid tails must not produce prefix fallback: offset={offset}, tail_first={tail_first}"
                );
            }
        }
    }

    #[test]
    fn payload_beyond_final_fragment_is_rejected() {
        let mut reassembler = Ipv4FragmentReassembler::new(1_200, true);
        let mut extra = packet(24, false, 2, 101);
        let mut bytes = extra.data.as_slice().to_vec();
        bytes.truncate(ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + 8);
        bytes[16..18].copy_from_slice(&(IPV4_MIN_HEADER_LEN as u16 + 8).to_be_bytes());
        bytes[20..22].copy_from_slice(&(MORE_FRAGMENTS | 5).to_be_bytes());
        extra.data = PacketPayload::owned(bytes.into_boxed_slice());
        let (output, _) = reassembler.process_batch(vec![
            packet(24, false, 1, 100),
            extra,
            packet(0, true, 3, 102),
        ]);
        assert!(output.is_empty());
        assert!(reassembler.finish().is_empty());
    }
}
