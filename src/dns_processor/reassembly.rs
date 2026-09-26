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
//! incomplete first fragment is released only when it expires, is evicted, or input ends;
//! the existing `--allow-fragments` parser then decides whether its DNS prefix is usable.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::packet_parser::{PacketBatch, PacketData, PacketPayload};

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
const MIN_RECENT_RETENTION_MICROS: i64 = 5_000_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FragmentKey {
    source: [u8; 4],
    destination: [u8; 4],
    identification: u16,
}

struct FragmentPart {
    key: FragmentKey,
    offset: usize,
    payload: Box<[u8]>,
    more_fragments: bool,
    first_udp_length: Option<usize>,
    first_header_len: Option<usize>,
}

struct FragmentSegment {
    payload: Box<[u8]>,
    more_fragments: bool,
}

struct CompletedDatagram {
    payload: Arc<[u8]>,
    observed_timestamp: i64,
    arrival_order: u64,
}

impl CompletedDatagram {
    fn memory_bytes(&self) -> usize {
        RECENT_ENTRY_OVERHEAD_ESTIMATE + self.payload.len()
    }
}

enum FragmentInput {
    Ordinary,
    Skip,
    Part(FragmentPart),
}

/// Byte intervals must not overlap, except for an exact duplicate fragment.
struct PendingDatagram {
    arrival_order: u64,
    first_seen_timestamp: i64,
    first: Option<PacketData>,
    first_header_len: Option<usize>,
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
            first: None,
            first_header_len: None,
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
            if end > udp_length
                || self
                    .final_payload_length
                    .is_some_and(|last| last != udp_length)
            {
                return Err(());
            }
            self.udp_length = Some(udp_length);
            self.first_header_len = Some(header_len);
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
        let udp_length = self.udp_length?;
        let (timestamp_micros, packet_ordinal) = self.final_fragment_event?;
        let total_length = header_len.checked_add(udp_length)?;
        let total_length = u16::try_from(total_length).ok()?;
        let header_end = ETHERNET_HEADER_LEN.checked_add(header_len)?;
        let first_header = first.data.as_slice().get(..header_end)?;

        let mut bytes = Vec::with_capacity(ETHERNET_HEADER_LEN + usize::from(total_length));
        bytes.extend_from_slice(first_header);
        bytes[ETHERNET_HEADER_LEN + 2..ETHERNET_HEADER_LEN + 4]
            .copy_from_slice(&total_length.to_be_bytes());
        // It is now a complete synthetic IPv4 datagram. Recompute the header checksum.
        bytes[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8]
            .copy_from_slice(&0_u16.to_be_bytes());
        bytes[ETHERNET_HEADER_LEN + 10..ETHERNET_HEADER_LEN + 12]
            .copy_from_slice(&0_u16.to_be_bytes());
        let checksum = ipv4_header_checksum(&bytes[ETHERNET_HEADER_LEN..header_end]);
        bytes[ETHERNET_HEADER_LEN + 10..ETHERNET_HEADER_LEN + 12]
            .copy_from_slice(&checksum.to_be_bytes());
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
    for word in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
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
    max_seen_timestamp: Option<i64>,
    timeout_micros: i64,
    monotonic_capture: bool,
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
            max_seen_timestamp: None,
            timeout_micros: match_timeout_micros.max(1),
            monotonic_capture,
        }
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
                FragmentInput::Part(part) => {
                    self.expire_completed_key_at(&part.key, packet.timestamp_micros);
                    self.expire_key_at(&part.key, packet.timestamp_micros, &mut output);
                    self.accept_part(part, packet, &mut output);
                    // One input batch may contain many large fragments. Enforce the
                    // memory bound per fragment, not only after the whole batch.
                    self.enforce_limits(&mut output);
                }
            }
        }
        self.expire_old(&mut output);
        self.expire_recent_completions();
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
        while let Some((&order, &key)) = self.arrival_order.first_key_value() {
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

    fn accept_part(&mut self, part: FragmentPart, packet: PacketData, output: &mut PacketBatch) {
        let key = part.key;
        let observed_timestamp = packet.timestamp_micros;
        let mut existing = self.take_entry(&key);
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
        match entry.insert(part, packet) {
            Ok(true) => {
                let previous_payload = entry.recent_payload.clone();
                let header_len = entry
                    .first_header_len
                    .expect("complete datagram has first header");
                if let Some(packet) = entry.into_packet() {
                    let payload = &packet.data[ETHERNET_HEADER_LEN + header_len..];
                    if !previous_payload
                        .as_ref()
                        .is_some_and(|previous| previous.as_ref() == payload)
                    {
                        self.remember_completion(
                            key,
                            Arc::<[u8]>::from(payload),
                            observed_timestamp,
                        );
                        output.push(packet);
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
        self.pending_bytes += entry.memory_bytes();
        self.arrival_order.insert(entry.arrival_order, key);
        self.pending.insert(key, entry);
    }

    fn take_entry(&mut self, key: &FragmentKey) -> Option<PendingDatagram> {
        let entry = self.pending.remove(key)?;
        self.pending_bytes -= entry.memory_bytes();
        self.arrival_order.remove(&entry.arrival_order);
        Some(entry)
    }

    fn remember_completion(
        &mut self,
        key: FragmentKey,
        payload: Arc<[u8]>,
        observed_timestamp: i64,
    ) {
        self.take_completion(&key);
        let arrival_order = self.next_completed_order;
        self.next_completed_order = self.next_completed_order.wrapping_add(1);
        let completed = CompletedDatagram {
            payload,
            observed_timestamp,
            arrival_order,
        };
        self.completed_bytes += completed.memory_bytes();
        self.completed_order.insert(arrival_order, key);
        self.recently_completed.insert(key, completed);
        while self.recently_completed.len() > MAX_RECENT_COMPLETIONS
            || self.completed_bytes > MAX_RECENT_BYTES
        {
            let Some((_, &oldest_key)) = self.completed_order.first_key_value() else {
                break;
            };
            self.take_completion(&oldest_key);
        }
    }

    fn take_completion(&mut self, key: &FragmentKey) -> Option<CompletedDatagram> {
        let completed = self.recently_completed.remove(key)?;
        self.completed_bytes -= completed.memory_bytes();
        self.completed_order.remove(&completed.arrival_order);
        Some(completed)
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

    fn expire_recent_completions(&mut self) {
        if !self.monotonic_capture {
            return;
        }
        let Some(frontier) = self.max_seen_timestamp else {
            return;
        };
        while let Some((_, &key)) = self.completed_order.first_key_value() {
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

    fn expire_old(&mut self, output: &mut PacketBatch) {
        if !self.monotonic_capture {
            // A timestamp regression can otherwise expire adjacent capture fragments.
            // Entry limits and EOF still bound incomplete state in this mode.
            return;
        }
        let Some(frontier) = self.max_seen_timestamp else {
            return;
        };
        let stale: Vec<FragmentKey> = self
            .pending
            .iter()
            .filter_map(|(key, entry)| {
                (frontier.saturating_sub(entry.first_seen_timestamp) > self.timeout_micros)
                    .then_some(*key)
            })
            .collect();
        // Hash iteration does not define output order; sorting is always explicit.
        for key in stale {
            if let Some(entry) = self.take_entry(&key)
                && let Some(first) = entry.into_fallback()
            {
                output.push(first);
            }
        }
    }

    fn expire_key_at(&mut self, key: &FragmentKey, timestamp: i64, output: &mut PacketBatch) {
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
            let Some((_, &key)) = self.arrival_order.first_key_value() else {
                break;
            };
            if let Some(entry) = self.take_entry(&key)
                && let Some(first) = entry.into_fallback()
            {
                output.push(first);
            }
        }
    }
}

fn classify_fragment(packet: &PacketData) -> FragmentInput {
    let bytes = packet.data.as_slice();
    if bytes.len() < ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN
        || u16::from_be_bytes([bytes[12], bytes[13]]) != ETHERTYPE_IPV4
    {
        return FragmentInput::Ordinary;
    }
    let ip = &bytes[ETHERNET_HEADER_LEN..];
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
        || (more_fragments && payload.len() % 8 != 0)
    {
        return FragmentInput::Skip;
    }
    let key = FragmentKey {
        source: ip[12..16].try_into().expect("IPv4 minimum header checked"),
        destination: ip[16..20].try_into().expect("IPv4 minimum header checked"),
        identification: u16::from_be_bytes([ip[4], ip[5]]),
    };
    let first_udp_length = if offset == 0 {
        if payload.len() < UDP_HEADER_LEN {
            return FragmentInput::Skip;
        }
        let source_port = u16::from_be_bytes([payload[0], payload[1]]);
        let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
        if source_port != DNS_PORT && destination_port != DNS_PORT {
            return FragmentInput::Skip;
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
                },
                Arc::<[u8]>::from(&b"payload"[..]),
                5_000_103,
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
