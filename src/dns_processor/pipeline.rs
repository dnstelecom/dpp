/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use arrayvec::ArrayVec;
use crossbeam::channel::{Receiver, Sender};
use rayon::prelude::*;
use seahash::SeaHasher;
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::io;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::thread;

use super::DnsProcessor;
use super::parser::{CanonicalFlowKey, PacketProcessingOutcome, ParsedUdpDnsMeta};
use super::reassembly::Ipv4FragmentReassembler;
use super::types::{MatcherShardState, ProcessedDnsRecord, ShardProcessingResult};
use crate::config::{ExecutionBudget, MATCHER_SHARD_FACTOR, PACKET_BATCH_SIZE};
use crate::output::{OutputMessage, OutputRecordBatches};
use crate::packet_parser::{PacketBatch, PacketData, PacketParser, sort_packet_batch};
use crate::record::DnsRecord;
use crate::runtime::AffinityPlan;

const BATCH_PREFETCH_DEPTH: usize = 2;
const MATCHER_WORKER_QUEUE_DEPTH: usize = 2;
const AGGREGATOR_REORDER_BUFFER_CAPACITY: usize =
    BATCH_PREFETCH_DEPTH + MATCHER_WORKER_QUEUE_DEPTH + 2;

struct WorkerShutdownSignals {
    shutdown_requested: Arc<AtomicBool>,
    intake_failed: Arc<AtomicBool>,
    output_closed: Arc<AtomicBool>,
}

struct FragmentProcessingConfig {
    allow_fragments: bool,
    full_fragments: bool,
    match_timeout_micros: i64,
    monotonic_capture: bool,
}

pub(crate) struct PipelineExecutionConfig {
    pub(crate) execution_budget: ExecutionBudget,
    pub(crate) affinity_plan: AffinityPlan,
    pub(crate) shard_parallelism_enabled: bool,
}

fn staged_matcher_affinity_slot(worker_idx: usize) -> usize {
    worker_idx
}

fn staged_parser_affinity_slot(worker_count: usize) -> usize {
    worker_count
}

fn staged_aggregator_affinity_slot(worker_count: usize) -> usize {
    worker_count + 1
}

struct PipelineCounters {
    oversized_qname_message_count: usize,
    fragmented_response_prefix_count: usize,
    dns_query_count: usize,
    duplicated_query_count: usize,
    dns_response_count: usize,
    matched_query_response_count: usize,
    timeout_query_count: usize,
    matched_rtt_sum_micros: u64,
    out_of_order_combined_count: usize,
    output_channel_open: bool,
}

impl Default for PipelineCounters {
    fn default() -> Self {
        Self {
            oversized_qname_message_count: 0,
            fragmented_response_prefix_count: 0,
            dns_query_count: 0,
            duplicated_query_count: 0,
            dns_response_count: 0,
            matched_query_response_count: 0,
            timeout_query_count: 0,
            matched_rtt_sum_micros: 0,
            out_of_order_combined_count: 0,
            output_channel_open: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ProcessingCounters {
    pub(crate) total_packets_processed: usize,
    /// DNS messages rejected because a decompressed QNAME exceeds the RFC 1035 255-octet limit.
    pub(crate) oversized_qname_message_count: usize,
    pub(crate) fragmented_response_prefix_count: usize,
    pub(crate) dns_query_count: usize,
    pub(crate) duplicated_query_count: usize,
    pub(crate) dns_response_count: usize,
    pub(crate) matched_query_response_count: usize,
    pub(crate) timeout_query_count: usize,
    pub(crate) matched_rtt_sum_micros: u64,
}

impl PipelineCounters {
    fn absorb(
        &mut self,
        tx: &Sender<OutputMessage>,
        shard_result: ShardProcessingResult,
        output_closed: &AtomicBool,
    ) -> bool {
        self.oversized_qname_message_count += shard_result.oversized_qname_message_count;
        self.fragmented_response_prefix_count += shard_result.fragmented_response_prefix_count;
        self.dns_query_count += shard_result.dns_query_count;
        self.duplicated_query_count += shard_result.duplicated_query_count;
        self.dns_response_count += shard_result.dns_response_count;
        self.matched_query_response_count += shard_result.matched_query_response_count;
        self.timeout_query_count += shard_result.timeout_query_count;
        self.matched_rtt_sum_micros += shard_result.matched_rtt_sum_micros;
        self.out_of_order_combined_count += shard_result.out_of_order_combined_count;

        if !self.output_channel_open {
            return false;
        }

        if !shard_result.output_records.is_empty()
            && !emit_record_batches(tx, shard_result.output_records, output_closed)
        {
            self.output_channel_open = false;
            return false;
        }

        true
    }

    fn finalize(self, total_packets_processed: usize) -> ProcessingCounters {
        ProcessingCounters {
            total_packets_processed,
            oversized_qname_message_count: self.oversized_qname_message_count,
            fragmented_response_prefix_count: self.fragmented_response_prefix_count,
            dns_query_count: self.dns_query_count,
            duplicated_query_count: self.duplicated_query_count,
            dns_response_count: self.dns_response_count,
            matched_query_response_count: self.matched_query_response_count,
            timeout_query_count: self.timeout_query_count,
            matched_rtt_sum_micros: self.matched_rtt_sum_micros,
        }
    }
}

struct MatcherBatchWork {
    batch_seq: u64,
    batch_max_timestamp_micros: Option<i64>,
    shard_packets: Vec<RoutedDnsPackets>,
}

struct RoutedWorkerBatches {
    batch_max_timestamp_micros: Option<i64>,
    worker_batches: Vec<Vec<RoutedDnsPackets>>,
}

#[derive(Default)]
struct RoutedDnsPackets {
    packets: Vec<PacketData>,
    metas: Vec<ParsedUdpDnsMeta>,
}

#[derive(Default)]
struct ParsedShardRecords {
    records: Vec<ProcessedDnsRecord>,
    oversized_qname_message_count: usize,
}

impl RoutedDnsPackets {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            packets: Vec::with_capacity(capacity),
            metas: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, packet: PacketData, meta: ParsedUdpDnsMeta) {
        self.packets.push(packet);
        self.metas.push(meta);
    }
}

enum MatcherWorkerEvent {
    BatchResult {
        batch_seq: u64,
        worker_idx: usize,
        result: ShardProcessingResult,
    },
    Finalization {
        worker_idx: usize,
        result: ShardProcessingResult,
    },
}

struct PendingBatchResults {
    worker_results: Vec<Option<ShardProcessingResult>>,
}

impl PendingBatchResults {
    fn new(worker_count: usize) -> Self {
        Self {
            worker_results: std::iter::repeat_with(|| None).take(worker_count).collect(),
        }
    }

    fn insert_result(
        &mut self,
        worker_idx: usize,
        result: ShardProcessingResult,
        batch_seq: u64,
    ) -> anyhow::Result<()> {
        let slot = self.worker_results.get_mut(worker_idx).ok_or_else(|| {
            anyhow::anyhow!(
                "Received matcher result for batch {} from invalid worker index {}",
                batch_seq,
                worker_idx
            )
        })?;

        if slot.is_some() {
            return Err(anyhow::anyhow!(
                "Received duplicate matcher result for batch {} from worker {}",
                batch_seq,
                worker_idx
            ));
        }

        *slot = Some(result);
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.worker_results.iter().all(Option::is_some)
    }

    fn into_results(self) -> Vec<ShardProcessingResult> {
        self.worker_results.into_iter().flatten().collect()
    }
}

struct PendingBatchBuffer {
    next_batch_seq: u64,
    worker_count: usize,
    slots: VecDeque<PendingBatchResults>,
}

impl PendingBatchBuffer {
    fn new(worker_count: usize) -> Self {
        Self {
            next_batch_seq: 0,
            worker_count,
            slots: VecDeque::with_capacity(AGGREGATOR_REORDER_BUFFER_CAPACITY),
        }
    }

    fn insert_result(
        &mut self,
        batch_seq: u64,
        worker_idx: usize,
        result: ShardProcessingResult,
    ) -> anyhow::Result<()> {
        let offset = batch_seq.checked_sub(self.next_batch_seq).ok_or_else(|| {
            anyhow::anyhow!(
                "Received stale matcher result for batch {} while waiting for batch {}",
                batch_seq,
                self.next_batch_seq
            )
        })? as usize;

        while self.slots.len() <= offset {
            self.slots
                .push_back(PendingBatchResults::new(self.worker_count));
        }

        self.slots[offset].insert_result(worker_idx, result, batch_seq)
    }

    fn pop_ready(&mut self) -> Option<Vec<ShardProcessingResult>> {
        if self
            .slots
            .front()
            .is_some_and(PendingBatchResults::is_complete)
        {
            let ready = self.slots.pop_front().expect("ready batch slot must exist");
            self.next_batch_seq = self.next_batch_seq.wrapping_add(1);
            Some(ready.into_results())
        } else {
            None
        }
    }

    fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    fn len(&self) -> usize {
        self.slots.len()
    }
}

fn stop_requested(shutdown_requested: &AtomicBool, output_closed: &AtomicBool) -> bool {
    shutdown_requested.load(AtomicOrdering::SeqCst) || output_closed.load(AtomicOrdering::Relaxed)
}

fn emit_record_batches(
    tx: &Sender<OutputMessage>,
    batches: OutputRecordBatches,
    output_closed: &AtomicBool,
) -> bool {
    batches
        .into_batch_iter()
        .all(|batch| send_record_batch(tx, batch, output_closed))
}

fn send_record_batch(
    tx: &Sender<OutputMessage>,
    records: Vec<DnsRecord>,
    output_closed: &AtomicBool,
) -> bool {
    debug_assert!(!records.is_empty());

    if output_closed.load(AtomicOrdering::Relaxed) {
        return false;
    }

    if tx.send(OutputMessage::Records(records)).is_err() {
        output_closed.store(true, AtomicOrdering::Relaxed);
        return false;
    }

    true
}

fn join_thread<T>(handle: thread::JoinHandle<anyhow::Result<T>>, label: &str) -> anyhow::Result<T> {
    handle
        .join()
        .map_err(|err| io::Error::other(format!("{label} panicked: {:?}", err)))?
}

fn logical_shard_count(num_threads: usize, shard_parallelism_enabled: bool) -> usize {
    if !shard_parallelism_enabled {
        return 1;
    }

    num_threads.saturating_mul(MATCHER_SHARD_FACTOR).max(1)
}

fn matcher_worker_count(
    execution_budget: ExecutionBudget,
    shard_parallelism_enabled: bool,
    shard_count: usize,
) -> usize {
    if !shard_parallelism_enabled || !execution_budget.uses_staged_pipeline() {
        1
    } else {
        debug_assert!(shard_count > 0);
        execution_budget.staged_worker_budget.min(shard_count)
    }
}

fn worker_shard_ranges(shard_count: usize, worker_count: usize) -> Vec<Range<usize>> {
    debug_assert!(shard_count > 0);
    debug_assert!(worker_count > 0);
    (0..worker_count)
        .map(|worker_idx| {
            let start = worker_idx * shard_count / worker_count;
            let end = (worker_idx + 1) * shard_count / worker_count;
            start..end
        })
        .collect()
}

struct ShardRoutingPlan {
    worker_ranges: Vec<Range<usize>>,
    shard_to_worker: Vec<usize>,
}

impl ShardRoutingPlan {
    fn new(shard_count: usize, worker_count: usize) -> Self {
        debug_assert!(shard_count > 0);
        debug_assert!(worker_count > 0);
        debug_assert!(worker_count <= shard_count);

        let worker_ranges = worker_shard_ranges(shard_count, worker_count);
        let mut shard_to_worker = vec![usize::MAX; shard_count];
        for (worker_idx, shard_range) in worker_ranges.iter().enumerate() {
            shard_to_worker[shard_range.clone()].fill(worker_idx);
        }
        debug_assert!(
            shard_to_worker
                .iter()
                .all(|worker_idx| *worker_idx < worker_count),
            "worker ranges must cover every shard index"
        );

        Self {
            worker_ranges,
            shard_to_worker,
        }
    }

    fn shard_count(&self) -> usize {
        self.shard_to_worker.len()
    }

    fn worker_for_shard(&self, shard_idx: usize) -> usize {
        self.shard_to_worker[shard_idx]
    }
}

fn merge_shard_results(merged: &mut ShardProcessingResult, shard_result: ShardProcessingResult) {
    merged.oversized_qname_message_count += shard_result.oversized_qname_message_count;
    merged.fragmented_response_prefix_count += shard_result.fragmented_response_prefix_count;
    merged.dns_query_count += shard_result.dns_query_count;
    merged.duplicated_query_count += shard_result.duplicated_query_count;
    merged.dns_response_count += shard_result.dns_response_count;
    merged.matched_query_response_count += shard_result.matched_query_response_count;
    merged.timeout_query_count += shard_result.timeout_query_count;
    merged.matched_rtt_sum_micros += shard_result.matched_rtt_sum_micros;
    merged.out_of_order_combined_count += shard_result.out_of_order_combined_count;
    merged.output_records.append(shard_result.output_records);
}

fn routed_shard_capacity_hint(packet_count: usize, shard_count: usize) -> usize {
    debug_assert!(shard_count > 0);
    (packet_count / shard_count) + 1
}

// Buffer the tuple's existing Hash writes so routing runs SeaHash once per flow.
// Streaming fallback keeps future Hash implementations correct if they exceed this capacity.
enum BufferedFlowHasher {
    Buffered(ArrayVec<u8, 64>),
    Streaming(SeaHasher),
}

impl Default for BufferedFlowHasher {
    fn default() -> Self {
        Self::Buffered(ArrayVec::new())
    }
}

impl Hasher for BufferedFlowHasher {
    #[inline]
    fn finish(&self) -> u64 {
        match self {
            Self::Buffered(bytes) => seahash::hash(bytes.as_slice()),
            Self::Streaming(hasher) => hasher.finish(),
        }
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        match self {
            Self::Buffered(buffer) => {
                if buffer.try_extend_from_slice(bytes).is_err() {
                    let mut hasher = SeaHasher::new();
                    hasher.write(buffer.as_slice());
                    hasher.write(bytes);
                    *self = Self::Streaming(hasher);
                }
            }
            Self::Streaming(hasher) => hasher.write(bytes),
        }
    }

    // SeaHasher 4.1 encodes these integer writes as little endian. Its u128/i128
    // methods use Hasher's native-endian defaults, which this adapter also inherits.
    #[inline]
    fn write_u8(&mut self, value: u8) {
        self.write(&value.to_le_bytes());
    }

    #[inline]
    fn write_u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    #[inline]
    fn write_u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    #[inline]
    fn write_u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    #[inline]
    fn write_usize(&mut self, value: usize) {
        self.write(&value.to_le_bytes());
    }

    #[inline]
    fn write_i8(&mut self, value: i8) {
        self.write(&value.to_le_bytes());
    }

    #[inline]
    fn write_i16(&mut self, value: i16) {
        self.write(&value.to_le_bytes());
    }

    #[inline]
    fn write_i32(&mut self, value: i32) {
        self.write(&value.to_le_bytes());
    }

    #[inline]
    fn write_i64(&mut self, value: i64) {
        self.write(&value.to_le_bytes());
    }

    #[inline]
    fn write_isize(&mut self, value: isize) {
        self.write(&value.to_le_bytes());
    }
}

fn shard_map_index(flow_key: CanonicalFlowKey, shard_count: usize) -> usize {
    debug_assert!(shard_count > 0);
    if shard_count == 1 {
        return 0;
    }

    let mut hasher = BufferedFlowHasher::default();
    (
        flow_key.client_ip,
        flow_key.client_port,
        flow_key.resolver_ip,
    )
        .hash(&mut hasher);
    (hasher.finish() as usize) % shard_count
}

fn route_batch_to_worker_batches(
    mut packet_batch: PacketBatch,
    routing_plan: &ShardRoutingPlan,
    allow_fragments: bool,
) -> RoutedWorkerBatches {
    let shard_count = routing_plan.shard_count();
    debug_assert!(shard_count > 0);
    sort_packet_batch(packet_batch.as_mut_slice());
    let batch_max_timestamp_micros = packet_batch.last().map(|packet| packet.timestamp_micros);

    let mut worker_batches: Vec<Vec<RoutedDnsPackets>> = routing_plan
        .worker_ranges
        .iter()
        .map(|range| {
            (0..range.len())
                .map(|_| {
                    RoutedDnsPackets::with_capacity(routed_shard_capacity_hint(
                        packet_batch.len(),
                        shard_count,
                    ))
                })
                .collect()
        })
        .collect();

    for packet_data in packet_batch {
        let Some(udp_dns_meta) = DnsProcessor::packet_routing_meta_with_fragments(
            packet_data.data.as_slice(),
            allow_fragments,
        ) else {
            continue;
        };

        let shard_idx = shard_map_index(udp_dns_meta.flow_key, shard_count);
        let worker_idx = routing_plan.worker_for_shard(shard_idx);
        let local_shard_idx = shard_idx - routing_plan.worker_ranges[worker_idx].start;
        worker_batches[worker_idx][local_shard_idx].push(packet_data, udp_dns_meta);
    }

    RoutedWorkerBatches {
        batch_max_timestamp_micros,
        worker_batches,
    }
}

fn route_batch_with_reassembly(
    packet_batch: PacketBatch,
    routing_plan: &ShardRoutingPlan,
    reassembler: &mut Ipv4FragmentReassembler,
) -> RoutedWorkerBatches {
    let input_max_timestamp_micros = packet_batch
        .iter()
        .map(|packet| packet.timestamp_micros)
        .max();
    let (packets, oldest_pending_timestamp_micros) = reassembler.process_batch(packet_batch);
    let mut routed = route_batch_to_worker_batches(packets, routing_plan, true);
    routed.batch_max_timestamp_micros = input_max_timestamp_micros.map(|timestamp| {
        oldest_pending_timestamp_micros.map_or(timestamp, |pending| timestamp.min(pending))
    });
    routed
}

fn parse_shard_packets(
    dns_processor: &DnsProcessor,
    shard_packets: RoutedDnsPackets,
) -> ParsedShardRecords {
    debug_assert_eq!(shard_packets.packets.len(), shard_packets.metas.len());
    let mut parsed = ParsedShardRecords {
        records: Vec::with_capacity(shard_packets.packets.len()),
        ..ParsedShardRecords::default()
    };

    for (packet, udp_dns_meta) in shard_packets.packets.into_iter().zip(shard_packets.metas) {
        match dns_processor.process_packet_batch_with_meta_into(
            &packet.data,
            packet.timestamp_micros,
            packet.packet_ordinal,
            udp_dns_meta,
            &mut parsed.records,
        ) {
            PacketProcessingOutcome::Records(()) => {}
            PacketProcessingOutcome::RejectedOversizedQname => {
                parsed.oversized_qname_message_count += 1;
            }
            PacketProcessingOutcome::Invalid => {}
        }
    }

    parsed
}

fn run_phase_processing_worker(
    dns_processor: Arc<DnsProcessor>,
    batch_rx: Receiver<PacketBatch>,
    tx: Sender<OutputMessage>,
    shard_count: usize,
    shard_parallelism_enabled: bool,
    signals: WorkerShutdownSignals,
) -> anyhow::Result<PipelineCounters> {
    let WorkerShutdownSignals {
        shutdown_requested,
        intake_failed,
        output_closed,
    } = signals;
    let mut shard_states: Vec<MatcherShardState> = if shard_parallelism_enabled {
        (0..shard_count)
            .map(|_| MatcherShardState::default())
            .collect()
    } else {
        vec![MatcherShardState::default()]
    };
    let routing_plan = ShardRoutingPlan::new(shard_count, shard_count);
    let mut reassembler = dns_processor.full_fragments.then(|| {
        Ipv4FragmentReassembler::new(
            dns_processor.match_timeout_micros,
            dns_processor.monotonic_capture,
        )
    });

    let mut counters = PipelineCounters::default();
    loop {
        let received = batch_rx.recv();
        let final_flush = received.is_err();
        if output_closed.load(AtomicOrdering::Relaxed) {
            break;
        }

        let routed = match received {
            Ok(packet_batch) => {
                if let Some(reassembler) = reassembler.as_mut() {
                    route_batch_with_reassembly(packet_batch, &routing_plan, reassembler)
                } else {
                    route_batch_to_worker_batches(
                        packet_batch,
                        &routing_plan,
                        dns_processor.allow_fragments,
                    )
                }
            }
            Err(_) => {
                let Some(reassembler) = reassembler.as_mut() else {
                    break;
                };
                let remaining = reassembler.finish();
                if remaining.is_empty() {
                    break;
                }
                route_batch_to_worker_batches(remaining, &routing_plan, true)
            }
        };

        let RoutedWorkerBatches {
            batch_max_timestamp_micros,
            worker_batches: shard_batches,
        } = routed;

        let mut shard_results: Vec<(usize, ShardProcessingResult)> = shard_batches
            .into_par_iter()
            .map(|mut by_local_shard| by_local_shard.pop().unwrap_or_default())
            .zip(shard_states.par_iter_mut())
            .enumerate()
            .map(|(map_idx, (shard_records, state))| {
                let parsed = parse_shard_packets(&dns_processor, shard_records);
                let mut shard_result = dns_processor.process_shard_records_with_batch_watermark(
                    parsed.records,
                    state,
                    batch_max_timestamp_micros,
                );
                shard_result.oversized_qname_message_count += parsed.oversized_qname_message_count;
                (map_idx, shard_result)
            })
            .collect();

        shard_results.sort_by_key(|(map_idx, _)| *map_idx);

        for (_, shard_result) in shard_results {
            if !counters.absorb(&tx, shard_result, output_closed.as_ref()) {
                return Ok(counters);
            }
        }
        if final_flush {
            break;
        }
    }

    if !stop_requested(shutdown_requested.as_ref(), output_closed.as_ref())
        && !intake_failed.load(AtomicOrdering::SeqCst)
    {
        let mut finalization_results: Vec<(usize, ShardProcessingResult)> = shard_states
            .par_iter_mut()
            .enumerate()
            .map(|(map_idx, state)| (map_idx, dns_processor.finalize_shard(state)))
            .collect();

        finalization_results.sort_by_key(|(map_idx, _)| *map_idx);

        for (_, shard_result) in finalization_results {
            if !counters.absorb(&tx, shard_result, output_closed.as_ref()) {
                return Ok(counters);
            }
        }
    }

    Ok(counters)
}

fn run_parser_stage(
    batch_rx: Receiver<PacketBatch>,
    worker_txs: Vec<Sender<MatcherBatchWork>>,
    routing_plan: ShardRoutingPlan,
    output_closed: Arc<AtomicBool>,
    fragment_config: FragmentProcessingConfig,
) -> anyhow::Result<()> {
    let FragmentProcessingConfig {
        allow_fragments,
        full_fragments,
        match_timeout_micros,
        monotonic_capture,
    } = fragment_config;
    let mut batch_seq = 0_u64;
    let mut reassembler = full_fragments
        .then(|| Ipv4FragmentReassembler::new(match_timeout_micros, monotonic_capture));

    loop {
        let received = batch_rx.recv();
        let final_flush = received.is_err();
        if output_closed.load(AtomicOrdering::Relaxed) {
            break;
        }

        let routed = match received {
            Ok(packet_batch) => {
                if let Some(reassembler) = reassembler.as_mut() {
                    route_batch_with_reassembly(packet_batch, &routing_plan, reassembler)
                } else {
                    route_batch_to_worker_batches(packet_batch, &routing_plan, allow_fragments)
                }
            }
            Err(_) => {
                let Some(reassembler) = reassembler.as_mut() else {
                    break;
                };
                let remaining = reassembler.finish();
                if remaining.is_empty() {
                    break;
                }
                route_batch_to_worker_batches(remaining, &routing_plan, true)
            }
        };

        let RoutedWorkerBatches {
            batch_max_timestamp_micros,
            worker_batches,
        } = routed;

        for (worker_idx, shard_packets) in worker_batches.into_iter().enumerate() {
            worker_txs[worker_idx]
                .send(MatcherBatchWork {
                    batch_seq,
                    batch_max_timestamp_micros,
                    shard_packets,
                })
                .map_err(|err| {
                    anyhow::anyhow!(
                        "Failed to hand off parsed shard batch to matcher worker {}: {}",
                        worker_idx,
                        err
                    )
                })
                .or_else(|error| {
                    if output_closed.load(AtomicOrdering::Relaxed) {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })?;
        }

        batch_seq = batch_seq.wrapping_add(1);
        if final_flush {
            break;
        }
    }

    Ok(())
}

fn run_matcher_worker(
    dns_processor: Arc<DnsProcessor>,
    worker_idx: usize,
    shard_range: Range<usize>,
    batch_rx: Receiver<MatcherBatchWork>,
    result_tx: Sender<MatcherWorkerEvent>,
    signals: WorkerShutdownSignals,
) -> anyhow::Result<()> {
    let WorkerShutdownSignals {
        shutdown_requested,
        intake_failed,
        output_closed,
    } = signals;
    let logical_shard_count = shard_range.end.saturating_sub(shard_range.start);
    let mut shard_states: Vec<MatcherShardState> = (0..logical_shard_count)
        .map(|_| MatcherShardState::default())
        .collect();

    while let Ok(work) = batch_rx.recv() {
        if output_closed.load(AtomicOrdering::Relaxed) {
            break;
        }

        let mut merged = ShardProcessingResult::default();

        for (shard_packets, state) in work.shard_packets.into_iter().zip(shard_states.iter_mut()) {
            let parsed = parse_shard_packets(&dns_processor, shard_packets);
            let mut shard_result = dns_processor.process_shard_records_with_batch_watermark(
                parsed.records,
                state,
                work.batch_max_timestamp_micros,
            );
            shard_result.oversized_qname_message_count += parsed.oversized_qname_message_count;
            merge_shard_results(&mut merged, shard_result);
        }

        result_tx
            .send(MatcherWorkerEvent::BatchResult {
                batch_seq: work.batch_seq,
                worker_idx,
                result: merged,
            })
            .map_err(|err| {
                anyhow::anyhow!(
                    "Failed to send matcher batch result from worker {}: {}",
                    worker_idx,
                    err
                )
            })
            .or_else(|error| {
                if output_closed.load(AtomicOrdering::Relaxed) {
                    Ok(())
                } else {
                    Err(error)
                }
            })?;
    }

    let mut finalization = ShardProcessingResult::default();
    if !stop_requested(shutdown_requested.as_ref(), output_closed.as_ref())
        && !intake_failed.load(AtomicOrdering::SeqCst)
    {
        for state in &mut shard_states {
            merge_shard_results(&mut finalization, dns_processor.finalize_shard(state));
        }
    }

    result_tx
        .send(MatcherWorkerEvent::Finalization {
            worker_idx,
            result: finalization,
        })
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to send matcher finalization result from worker {}: {}",
                worker_idx,
                err
            )
        })
        .or_else(|error| {
            if output_closed.load(AtomicOrdering::Relaxed) {
                Ok(())
            } else {
                Err(error)
            }
        })?;

    Ok(())
}

fn run_aggregator(
    result_rx: Receiver<MatcherWorkerEvent>,
    tx: Sender<OutputMessage>,
    worker_count: usize,
    output_closed: Arc<AtomicBool>,
) -> anyhow::Result<PipelineCounters> {
    let mut counters = PipelineCounters::default();
    let mut pending_batches = PendingBatchBuffer::new(worker_count);
    let mut finalizations: Vec<Option<ShardProcessingResult>> =
        std::iter::repeat_with(|| None).take(worker_count).collect();

    while let Ok(event) = result_rx.recv() {
        match event {
            MatcherWorkerEvent::BatchResult {
                batch_seq,
                worker_idx,
                result,
            } => {
                pending_batches.insert_result(batch_seq, worker_idx, result)?;

                while let Some(ready_results) = pending_batches.pop_ready() {
                    for shard_result in ready_results {
                        if !counters.absorb(&tx, shard_result, output_closed.as_ref()) {
                            return Ok(counters);
                        }
                    }
                }
            }
            MatcherWorkerEvent::Finalization { worker_idx, result } => {
                finalizations[worker_idx] = Some(result);
            }
        }
    }

    if output_closed.load(AtomicOrdering::Relaxed) {
        return Ok(counters);
    }

    if !pending_batches.is_empty() {
        return Err(anyhow::anyhow!(
            "Aggregator stopped with {} incomplete batch result sets",
            pending_batches.len()
        ));
    }

    for (worker_idx, finalization) in finalizations.into_iter().enumerate() {
        let shard_result = finalization.ok_or_else(|| {
            anyhow::anyhow!(
                "Missing finalization result from matcher worker {}",
                worker_idx
            )
        })?;
        if !counters.absorb(&tx, shard_result, output_closed.as_ref()) {
            return Ok(counters);
        }
    }

    Ok(counters)
}

fn run_staged_processing_pipeline(
    dns_processor: Arc<DnsProcessor>,
    batch_rx: Receiver<PacketBatch>,
    tx: Sender<OutputMessage>,
    shard_count: usize,
    worker_count: usize,
    affinity_plan: AffinityPlan,
    signals: WorkerShutdownSignals,
) -> anyhow::Result<PipelineCounters> {
    let WorkerShutdownSignals {
        shutdown_requested,
        intake_failed,
        output_closed,
    } = signals;
    let routing_plan = ShardRoutingPlan::new(shard_count, worker_count);
    let (result_tx, result_rx) =
        crossbeam::channel::bounded(MATCHER_WORKER_QUEUE_DEPTH * worker_count.max(1));

    let mut worker_txs = Vec::with_capacity(worker_count);
    let mut worker_handles = Vec::with_capacity(worker_count);

    for (worker_idx, shard_range) in routing_plan.worker_ranges.iter().cloned().enumerate() {
        let (worker_tx, worker_rx) = crossbeam::channel::bounded(MATCHER_WORKER_QUEUE_DEPTH);
        worker_txs.push(worker_tx);

        worker_handles.push(
            thread::Builder::new()
                .name(format!("DPP_Matcher_{}", worker_idx))
                .spawn({
                    let dns_processor = Arc::clone(&dns_processor);
                    let result_tx = result_tx.clone();
                    let shutdown_requested = Arc::clone(&shutdown_requested);
                    let intake_failed = Arc::clone(&intake_failed);
                    let output_closed = Arc::clone(&output_closed);
                    let affinity_plan = affinity_plan.clone();
                    move || {
                        affinity_plan.apply_to_current_thread(
                            staged_matcher_affinity_slot(worker_idx),
                            "staged matcher worker",
                        );
                        run_matcher_worker(
                            dns_processor,
                            worker_idx,
                            shard_range,
                            worker_rx,
                            result_tx,
                            WorkerShutdownSignals {
                                shutdown_requested,
                                intake_failed,
                                output_closed,
                            },
                        )
                    }
                })?,
        );
    }
    drop(result_tx);

    let parser_handle = thread::Builder::new()
        .name("DPP_Parser".to_string())
        .spawn({
            let output_closed = Arc::clone(&output_closed);
            let allow_fragments = dns_processor.allow_fragments;
            let full_fragments = dns_processor.full_fragments;
            let match_timeout_micros = dns_processor.match_timeout_micros;
            let monotonic_capture = dns_processor.monotonic_capture;
            let affinity_plan = affinity_plan.clone();
            move || {
                affinity_plan.apply_to_current_thread(
                    staged_parser_affinity_slot(worker_count),
                    "staged parser",
                );
                run_parser_stage(
                    batch_rx,
                    worker_txs,
                    routing_plan,
                    output_closed,
                    FragmentProcessingConfig {
                        allow_fragments,
                        full_fragments,
                        match_timeout_micros,
                        monotonic_capture,
                    },
                )
            }
        })?;

    affinity_plan.apply_to_current_thread(
        staged_aggregator_affinity_slot(worker_count),
        "staged aggregator",
    );
    let aggregator_result = run_aggregator(result_rx, tx, worker_count, output_closed);

    let parser_result = join_thread(parser_handle, "Parser stage");
    let worker_result =
        worker_handles
            .into_iter()
            .enumerate()
            .try_for_each(|(worker_idx, worker_handle)| {
                join_thread(worker_handle, &format!("Matcher worker {}", worker_idx)).map(|_| ())
            });

    parser_result?;
    worker_result?;
    aggregator_result
}

impl DnsProcessor {
    pub fn dns_processing_loop(
        dns_processor: Arc<DnsProcessor>,
        packet_parser: &mut PacketParser,
        packet_count: &Arc<AtomicUsize>,
        tx: &Sender<OutputMessage>,
        config: PipelineExecutionConfig,
        shutdown_requested: Arc<AtomicBool>,
        output_closed: Arc<AtomicBool>,
    ) -> anyhow::Result<ProcessingCounters> {
        let PipelineExecutionConfig {
            execution_budget,
            affinity_plan,
            shard_parallelism_enabled,
        } = config;
        let shard_count =
            logical_shard_count(execution_budget.available_cpus, shard_parallelism_enabled);
        let worker_count =
            matcher_worker_count(execution_budget, shard_parallelism_enabled, shard_count);
        let (batch_tx, batch_rx) = crossbeam::channel::bounded(BATCH_PREFETCH_DEPTH);
        let intake_failed = Arc::new(AtomicBool::new(false));

        if execution_budget.uses_staged_pipeline() {
            tracing::info!(
                "Execution budget: {} CPUs, staged worker budget: {} shard workers, {} reserved service threads",
                execution_budget.available_cpus,
                worker_count,
                execution_budget.staged_reserved_service_threads
            );
        } else {
            tracing::info!(
                "Execution budget: {} CPUs, phase-parallel pipeline selected for low-core budget, Rayon worker budget: {}",
                execution_budget.available_cpus,
                execution_budget
                    .rayon_threads
                    .unwrap_or(execution_budget.available_cpus)
            );
        }

        let pipeline_handle = if execution_budget.uses_staged_pipeline() {
            thread::Builder::new()
                .name("DPP_Staged_Pipeline".to_string())
                .spawn({
                    let dns_processor = Arc::clone(&dns_processor);
                    let output_tx = tx.clone();
                    let shutdown_requested = Arc::clone(&shutdown_requested);
                    let intake_failed = Arc::clone(&intake_failed);
                    let output_closed = Arc::clone(&output_closed);
                    move || {
                        run_staged_processing_pipeline(
                            dns_processor,
                            batch_rx,
                            output_tx,
                            shard_count,
                            worker_count,
                            affinity_plan,
                            WorkerShutdownSignals {
                                shutdown_requested,
                                intake_failed,
                                output_closed,
                            },
                        )
                    }
                })?
        } else {
            thread::Builder::new()
                .name("DPP_Pipeline_Worker".to_string())
                .spawn({
                    let dns_processor = Arc::clone(&dns_processor);
                    let output_tx = tx.clone();
                    let shutdown_requested = Arc::clone(&shutdown_requested);
                    let intake_failed = Arc::clone(&intake_failed);
                    let output_closed = Arc::clone(&output_closed);
                    move || {
                        run_phase_processing_worker(
                            dns_processor,
                            batch_rx,
                            output_tx,
                            shard_count,
                            shard_parallelism_enabled,
                            WorkerShutdownSignals {
                                shutdown_requested,
                                intake_failed,
                                output_closed,
                            },
                        )
                    }
                })?
        };

        let mut processed_packet_count = 0usize;
        let intake_result = (|| -> anyhow::Result<()> {
            while !stop_requested(shutdown_requested.as_ref(), output_closed.as_ref()) {
                let Some(packet_batch) = packet_parser.next_batch(PACKET_BATCH_SIZE)? else {
                    break;
                };

                if output_closed.load(AtomicOrdering::Relaxed) {
                    break;
                }

                let packet_batch_len = packet_batch.len();
                batch_tx
                    .send(packet_batch)
                    .map_err(|err| {
                        anyhow::anyhow!(
                            "Failed to hand off packet batch to processing pipeline: {}",
                            err
                        )
                    })
                    .or_else(|error| {
                        if output_closed.load(AtomicOrdering::Relaxed) {
                            Ok(())
                        } else {
                            Err(error)
                        }
                    })?;
                if output_closed.load(AtomicOrdering::Relaxed) {
                    break;
                }
                processed_packet_count += packet_batch_len;
            }

            Ok(())
        })();

        if intake_result.is_err() {
            intake_failed.store(true, AtomicOrdering::SeqCst);
        }

        if shutdown_requested.load(AtomicOrdering::SeqCst) {
            tracing::warn!(
                "Termination signal received. DPP will stop accepting new batches, drain already accepted work, skip synthetic timeout finalization for pending unmatched queries, and discard any still-buffered output tail before exit."
            );
        }

        drop(batch_tx);

        let pipeline_result = join_thread(pipeline_handle, "Processing pipeline");
        packet_count.store(processed_packet_count, AtomicOrdering::Relaxed);

        if let Err(intake_error) = intake_result {
            if let Err(pipeline_error) = pipeline_result {
                tracing::error!(
                    "Processing pipeline teardown also failed after intake error: {pipeline_error:#}"
                );
            }
            return Err(intake_error);
        }

        let counters = pipeline_result?;

        Ok(counters.finalize(processed_packet_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InputSource, OUTPUT_RECORD_BATCH_SIZE};
    use crate::packet_parser::PacketParser;
    use crate::test_support::{
        classic_pcap_bytes, encode_dns_header, make_udp_dns_packet,
        make_udp_dns_packet_with_payload, temp_test_path, test_dns_record,
    };
    use std::fs;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn test_worker_signals(shutdown_requested: bool) -> WorkerShutdownSignals {
        WorkerShutdownSignals {
            shutdown_requested: Arc::new(AtomicBool::new(shutdown_requested)),
            intake_failed: Arc::new(AtomicBool::new(false)),
            output_closed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn shard_result(token: usize) -> ShardProcessingResult {
        ShardProcessingResult {
            dns_query_count: token,
            ..Default::default()
        }
    }

    fn unresolved_query_batch(test_name: &str) -> PacketBatch {
        let path = temp_test_path(test_name, "pcap");
        let mut dns_payload = encode_dns_header(0x1234, 0x0100, 1);
        dns_payload.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        dns_payload.extend_from_slice(&1_u16.to_be_bytes());
        dns_payload.extend_from_slice(&1_u16.to_be_bytes());
        let packet =
            make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &dns_payload);
        fs::write(&path, classic_pcap_bytes(&[(1, 0, &packet)])).expect("test pcap written");

        let mut parser =
            PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
        let batch = parser
            .next_batch(1)
            .expect("batch read succeeds")
            .expect("query packet is present");
        fs::remove_file(&path).expect("test pcap removed");

        batch
    }

    fn oversized_qname_batch(test_name: &str) -> PacketBatch {
        let path = temp_test_path(test_name, "pcap");
        let mut dns_payload = encode_dns_header(0x1234, 0x0100, 1);

        for label_len in [63_usize, 63, 63, 62] {
            dns_payload.push(label_len as u8);
            dns_payload.resize(dns_payload.len() + label_len, b'a');
        }
        dns_payload.push(0);
        dns_payload.extend_from_slice(&1_u16.to_be_bytes());
        dns_payload.extend_from_slice(&1_u16.to_be_bytes());

        let packet =
            make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &dns_payload);
        fs::write(&path, classic_pcap_bytes(&[(1, 0, &packet)])).expect("test pcap written");

        let mut parser =
            PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
        let batch = parser
            .next_batch(1)
            .expect("batch read succeeds")
            .expect("oversized-QNAME packet is present");
        fs::remove_file(&path).expect("test pcap removed");

        batch
    }

    fn capture_with_complete_batch_then_truncated_record(test_name: &str) -> std::path::PathBuf {
        let path = temp_test_path(test_name, "pcap");
        let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
        query_payload.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        query_payload.extend_from_slice(&1_u16.to_be_bytes());
        query_payload.extend_from_slice(&1_u16.to_be_bytes());

        let mut response_payload = query_payload.clone();
        response_payload[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        let query_packet = make_udp_dns_packet_with_payload(
            [10, 0, 0, 1],
            [8, 8, 8, 8],
            53_000,
            53,
            &query_payload,
        );
        let response_packet = make_udp_dns_packet_with_payload(
            [8, 8, 8, 8],
            [10, 0, 0, 1],
            53,
            53_000,
            &response_payload,
        );
        let non_dns_packet = make_udp_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 123);

        let mut packets = Vec::with_capacity(PACKET_BATCH_SIZE);
        packets.push((1, 0, query_packet.as_slice()));
        packets.push((1, 200_000, response_packet.as_slice()));
        packets.push((2, 0, query_packet.as_slice()));
        packets.extend(std::iter::repeat_n(
            (3, 0, non_dns_packet.as_slice()),
            PACKET_BATCH_SIZE - packets.len(),
        ));

        let mut capture = classic_pcap_bytes(&packets);
        capture.extend_from_slice(&4_u32.to_le_bytes());
        capture.extend_from_slice(&0_u32.to_le_bytes());
        capture.extend_from_slice(&64_u32.to_le_bytes());
        capture.extend_from_slice(&64_u32.to_le_bytes());
        capture.extend_from_slice(&[0_u8; 3]);
        fs::write(&path, capture).expect("truncated test pcap written");
        path
    }

    fn capture_with_retry_regression_across_batch_boundary(test_name: &str) -> std::path::PathBuf {
        let path = temp_test_path(test_name, "pcap");
        let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
        query_payload.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        query_payload.extend_from_slice(&1_u16.to_be_bytes());
        query_payload.extend_from_slice(&1_u16.to_be_bytes());

        let query_packet = make_udp_dns_packet_with_payload(
            [10, 0, 0, 1],
            [8, 8, 8, 8],
            53_000,
            53,
            &query_payload,
        );
        let non_dns_packet = make_udp_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 123);

        let mut packets = Vec::with_capacity(PACKET_BATCH_SIZE + 1);
        packets.extend(std::iter::repeat_n(
            (1, 0, non_dns_packet.as_slice()),
            PACKET_BATCH_SIZE - 1,
        ));
        packets.push((2, 0, query_packet.as_slice()));
        packets.push((1, 500_000, query_packet.as_slice()));

        fs::write(&path, classic_pcap_bytes(&packets)).expect("test pcap written");
        path
    }

    #[test]
    fn matcher_worker_budget_respects_staged_execution_plan() {
        let low_core_budget = ExecutionBudget::from_available_cpus(4);
        let staged_budget = ExecutionBudget::from_available_cpus(16);

        assert_eq!(matcher_worker_count(low_core_budget, true, 64), 1);
        assert_eq!(matcher_worker_count(staged_budget, true, 64), 14);
        assert_eq!(matcher_worker_count(staged_budget, true, 8), 8);
    }

    #[test]
    fn staged_pipeline_applies_affinity_to_every_processing_role() {
        let path = temp_test_path("pipeline-staged-affinity", "pcap");
        fs::write(&path, classic_pcap_bytes(&[])).expect("empty pcap written");

        let applied = Arc::new(Mutex::new(Vec::new()));
        let affinity_plan = AffinityPlan::for_test(vec![2, 5, 9, 12, 17], {
            let applied = Arc::clone(&applied);
            move |core_id| {
                let thread_name = thread::current().name().unwrap_or("unnamed").to_string();
                applied
                    .lock()
                    .expect("affinity record lock")
                    .push((thread_name, core_id));
                true
            }
        })
        .expect("test affinity plan resolves");

        let mut parser =
            PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
        let packet_count = Arc::new(AtomicUsize::new(0));
        let (output_tx, _output_rx) = crossbeam::channel::unbounded();

        DnsProcessor::dns_processing_loop(
            Arc::new(DnsProcessor::new(None).expect("processor initializes")),
            &mut parser,
            &packet_count,
            &output_tx,
            PipelineExecutionConfig {
                execution_budget: ExecutionBudget::from_available_cpus(5),
                affinity_plan,
                shard_parallelism_enabled: true,
            },
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .expect("staged pipeline completes");
        fs::remove_file(path).expect("empty pcap removed");

        let mut applied = applied.lock().expect("affinity record lock").clone();
        applied.sort();
        assert_eq!(
            applied,
            vec![
                ("DPP_Matcher_0".to_string(), 2),
                ("DPP_Matcher_1".to_string(), 5),
                ("DPP_Matcher_2".to_string(), 9),
                ("DPP_Parser".to_string(), 12),
                ("DPP_Staged_Pipeline".to_string(), 17),
            ]
        );
    }

    #[test]
    fn non_parallel_mode_collapses_to_single_worker() {
        let staged_budget = ExecutionBudget::from_available_cpus(16);

        assert_eq!(matcher_worker_count(staged_budget, false, 64), 1);
    }

    #[test]
    fn shard_routing_plan_covers_even_and_uneven_worker_ranges() {
        for (shard_count, worker_count) in [(1, 1), (7, 3), (8, 8), (64, 14)] {
            let routing_plan = ShardRoutingPlan::new(shard_count, worker_count);

            assert_eq!(routing_plan.shard_to_worker.len(), shard_count);
            for shard_idx in 0..shard_count {
                let worker_idx = routing_plan.worker_for_shard(shard_idx);
                assert!(worker_idx < worker_count);
                assert!(routing_plan.worker_ranges[worker_idx].contains(&shard_idx));
            }
        }

        let uneven = ShardRoutingPlan::new(7, 3);
        assert_eq!(uneven.worker_ranges, vec![0..2, 2..4, 4..7]);
        assert_eq!(uneven.shard_to_worker, vec![0, 0, 1, 1, 2, 2, 2]);
    }

    #[test]
    fn pending_batch_buffer_releases_results_in_batch_sequence() {
        let mut buffer = PendingBatchBuffer::new(2);

        buffer
            .insert_result(1, 0, shard_result(10))
            .expect("batch 1 worker 0 insert succeeds");
        buffer
            .insert_result(1, 1, shard_result(11))
            .expect("batch 1 worker 1 insert succeeds");
        assert!(buffer.pop_ready().is_none());

        buffer
            .insert_result(0, 1, shard_result(1))
            .expect("batch 0 worker 1 insert succeeds");
        assert!(buffer.pop_ready().is_none());

        buffer
            .insert_result(0, 0, shard_result(0))
            .expect("batch 0 worker 0 insert succeeds");

        let first_batch = buffer.pop_ready().expect("batch 0 becomes ready");
        assert_eq!(
            first_batch
                .into_iter()
                .map(|result| result.dns_query_count)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );

        let second_batch = buffer.pop_ready().expect("batch 1 becomes ready");
        assert_eq!(
            second_batch
                .into_iter()
                .map(|result| result.dns_query_count)
                .collect::<Vec<_>>(),
            vec![10, 11]
        );
        assert!(buffer.is_empty());
    }

    #[test]
    fn pending_batch_buffer_rejects_duplicate_worker_results() {
        let mut buffer = PendingBatchBuffer::new(2);

        buffer
            .insert_result(0, 0, shard_result(0))
            .expect("first insert succeeds");

        let err = buffer
            .insert_result(0, 0, shard_result(1))
            .expect_err("duplicate worker result must fail");

        assert!(
            err.to_string()
                .contains("duplicate matcher result for batch 0 from worker 0")
        );
    }

    #[test]
    fn pending_batch_buffer_rejects_stale_batch_results() {
        let mut buffer = PendingBatchBuffer::new(1);

        buffer
            .insert_result(0, 0, shard_result(0))
            .expect("batch 0 insert succeeds");
        let released = buffer.pop_ready().expect("batch 0 becomes ready");
        assert_eq!(released.len(), 1);

        let err = buffer
            .insert_result(0, 0, shard_result(1))
            .expect_err("stale batch result must fail");

        assert!(
            err.to_string()
                .contains("Received stale matcher result for batch 0 while waiting for batch 1")
        );
    }

    #[test]
    fn intake_error_joins_both_pipeline_models_without_timeout_finalization() {
        let path = capture_with_complete_batch_then_truncated_record("pipeline-intake-error");

        for available_cpus in [1, 5] {
            let mut parser =
                PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
            let packet_count = Arc::new(AtomicUsize::new(0));
            let (output_tx, output_rx) = crossbeam::channel::unbounded();

            let result = DnsProcessor::dns_processing_loop(
                Arc::new(DnsProcessor::new(None).expect("processor initializes")),
                &mut parser,
                &packet_count,
                &output_tx,
                PipelineExecutionConfig {
                    execution_budget: ExecutionBudget::from_available_cpus(available_cpus),
                    affinity_plan: AffinityPlan::disabled(),
                    shard_parallelism_enabled: true,
                },
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            );

            assert!(result.is_err(), "available_cpus={available_cpus}");
            assert_eq!(
                packet_count.load(AtomicOrdering::Relaxed),
                PACKET_BATCH_SIZE,
                "available_cpus={available_cpus}"
            );

            drop(output_tx);
            let records = output_rx
                .into_iter()
                .flat_map(|message| match message {
                    OutputMessage::Records(records) => records,
                    message => panic!("unexpected output message: {message:?}"),
                })
                .collect::<Vec<_>>();
            assert_eq!(records.len(), 1, "available_cpus={available_cpus}");
            assert_eq!(records[0].response_timestamp, Some(1_200_000));
        }

        fs::remove_file(path).expect("test pcap removed");
    }

    #[test]
    fn retry_deduplication_survives_timestamp_regression_between_batches() {
        let path = capture_with_retry_regression_across_batch_boundary(
            "pipeline-cross-batch-retry-regression",
        );

        for available_cpus in [1, 5] {
            let mut parser =
                PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
            let packet_count = Arc::new(AtomicUsize::new(0));
            let (output_tx, output_rx) = crossbeam::channel::unbounded();

            let counters = DnsProcessor::dns_processing_loop(
                Arc::new(DnsProcessor::new(None).expect("processor initializes")),
                &mut parser,
                &packet_count,
                &output_tx,
                PipelineExecutionConfig {
                    execution_budget: ExecutionBudget::from_available_cpus(available_cpus),
                    affinity_plan: AffinityPlan::disabled(),
                    shard_parallelism_enabled: true,
                },
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            )
            .expect("pipeline completes");

            assert_eq!(
                counters.total_packets_processed,
                PACKET_BATCH_SIZE + 1,
                "available_cpus={available_cpus}"
            );
            assert_eq!(
                counters.dns_query_count, 2,
                "available_cpus={available_cpus}"
            );
            assert_eq!(
                counters.duplicated_query_count, 1,
                "available_cpus={available_cpus}"
            );
            assert_eq!(
                counters.dns_response_count, 0,
                "available_cpus={available_cpus}"
            );
            assert_eq!(
                counters.matched_query_response_count, 0,
                "available_cpus={available_cpus}"
            );
            assert_eq!(
                counters.timeout_query_count, 1,
                "available_cpus={available_cpus}"
            );
            assert_eq!(parser.non_monotonic_timestamp_count(), 1);

            let regression = parser
                .first_non_monotonic_timestamp()
                .expect("timestamp regression is recorded");
            assert_eq!(
                regression.previous_packet_ordinal,
                (PACKET_BATCH_SIZE - 1) as u64
            );
            assert_eq!(regression.previous_timestamp_micros, 2_000_000);
            assert_eq!(regression.current_packet_ordinal, PACKET_BATCH_SIZE as u64);
            assert_eq!(regression.current_timestamp_micros, 1_500_000);

            drop(output_tx);
            let records = output_rx
                .into_iter()
                .flat_map(|message| match message {
                    OutputMessage::Records(records) => records,
                    message => panic!("unexpected output message: {message:?}"),
                })
                .collect::<Vec<_>>();
            assert_eq!(records.len(), 1, "available_cpus={available_cpus}");
            assert_eq!(records[0].request_timestamp, 1_500_000);
            assert_eq!(records[0].response_timestamp, None);
            assert_eq!(records[0].response_code, None);
        }

        fs::remove_file(path).expect("test pcap removed");
    }

    #[test]
    fn both_pipeline_models_preserve_matches_after_chained_retry_regressions() {
        let path = temp_test_path("pipeline-chained-retry-regression", "pcap");
        let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
        query_payload.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        query_payload.extend_from_slice(&1_u16.to_be_bytes());
        query_payload.extend_from_slice(&1_u16.to_be_bytes());
        let mut response_payload = query_payload.clone();
        response_payload[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        let query = make_udp_dns_packet_with_payload(
            [10, 0, 0, 1],
            [8, 8, 8, 8],
            53_000,
            53,
            &query_payload,
        );
        let response = make_udp_dns_packet_with_payload(
            [8, 8, 8, 8],
            [10, 0, 0, 1],
            53,
            53_000,
            &response_payload,
        );
        let padding = make_udp_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 123);
        let mut packets = Vec::with_capacity(2 * PACKET_BATCH_SIZE + 2);
        for timestamp in [3, 2] {
            packets.push((timestamp, 0, query.as_slice()));
            packets.extend(std::iter::repeat_n(
                (timestamp, 0, padding.as_slice()),
                PACKET_BATCH_SIZE - 1,
            ));
        }
        packets.push((1, 0, query.as_slice()));
        packets.push((3, 100_000, response.as_slice()));
        fs::write(&path, classic_pcap_bytes(&packets)).expect("test pcap written");

        for available_cpus in [1, 5] {
            let mut parser =
                PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
            let (output_tx, output_rx) = crossbeam::channel::unbounded();
            let counters = DnsProcessor::dns_processing_loop(
                Arc::new(DnsProcessor::new(None).expect("processor initializes")),
                &mut parser,
                &Arc::new(AtomicUsize::new(0)),
                &output_tx,
                PipelineExecutionConfig {
                    execution_budget: ExecutionBudget::from_available_cpus(available_cpus),
                    affinity_plan: AffinityPlan::disabled(),
                    shard_parallelism_enabled: true,
                },
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            )
            .expect("pipeline completes");
            assert_eq!(counters.total_packets_processed, 2 * PACKET_BATCH_SIZE + 2);
            assert_eq!(counters.dns_query_count, 3);
            assert_eq!(counters.duplicated_query_count, 1);
            assert_eq!(counters.dns_response_count, 1);
            assert_eq!(counters.matched_query_response_count, 1);
            assert_eq!(counters.timeout_query_count, 1);
            drop(output_tx);
            let rows = output_rx
                .into_iter()
                .flat_map(|message| match message {
                    OutputMessage::Records(records) => records,
                    other => panic!("unexpected output message: {other:?}"),
                })
                .map(|record| (record.request_timestamp, record.response_timestamp))
                .collect::<Vec<_>>();
            assert_eq!(
                rows,
                vec![(3_000_000, Some(3_100_000)), (1_000_000, None)],
                "available_cpus={available_cpus}"
            );
        }
        fs::remove_file(path).expect("test pcap removed");
    }

    #[test]
    fn full_ipv4_reassembly_crosses_packet_batch_boundary_in_both_pipeline_models() {
        let path = temp_test_path("pipeline-cross-batch-ipv4-fragments", "pcap");
        let mut query_payload = encode_dns_header(0x3456, 0x0100, 1);
        query_payload.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        query_payload.extend_from_slice(&1_u16.to_be_bytes());
        query_payload.extend_from_slice(&1_u16.to_be_bytes());
        let mut response_payload = query_payload.clone();
        response_payload[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response_payload[10..12].copy_from_slice(&1_u16.to_be_bytes());
        // The OPT record changes the full RCODE to EDNS_BADVERS and is split
        // between the two IP fragments.
        response_payload.extend_from_slice(&[0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0]);

        let query = make_udp_dns_packet_with_payload(
            [10, 0, 0, 1],
            [8, 8, 8, 8],
            53_000,
            53,
            &query_payload,
        );
        let response = make_udp_dns_packet_with_payload(
            [8, 8, 8, 8],
            [10, 0, 0, 1],
            53,
            53_000,
            &response_payload,
        );
        let padding = make_udp_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 123);
        let first_end = 14 + 20 + 40;
        let mut first_fragment = response[..first_end].to_vec();
        first_fragment[16..18].copy_from_slice(&60_u16.to_be_bytes());
        first_fragment[18..20].copy_from_slice(&0x4321_u16.to_be_bytes());
        first_fragment[20..22].copy_from_slice(&0x2000_u16.to_be_bytes());
        let mut final_fragment = response[..34].to_vec();
        final_fragment[16..18]
            .copy_from_slice(&(20_u16 + (response.len() - first_end) as u16).to_be_bytes());
        final_fragment[18..20].copy_from_slice(&0x4321_u16.to_be_bytes());
        final_fragment[20..22].copy_from_slice(&5_u16.to_be_bytes());
        final_fragment.extend_from_slice(&response[first_end..]);

        let mut packets = Vec::with_capacity(PACKET_BATCH_SIZE + 1);
        packets.push((1, 0, query.as_slice()));
        packets.push((1, 100_000, first_fragment.as_slice()));
        packets.extend(std::iter::repeat_n(
            (1, 150_000, padding.as_slice()),
            PACKET_BATCH_SIZE - packets.len(),
        ));
        packets.push((1, 200_000, final_fragment.as_slice()));
        fs::write(&path, classic_pcap_bytes(&packets)).expect("test pcap written");

        // A pending first fragment holds the monotonic matcher watermark at
        // its timestamp even when later unrelated packets fill the batch.
        let mut cap_parser =
            PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
        let first_batch = cap_parser
            .next_batch(PACKET_BATCH_SIZE)
            .expect("batch reads")
            .expect("first batch exists");
        let mut reassembler = Ipv4FragmentReassembler::new(1_200_000, true);
        let routed = route_batch_with_reassembly(
            first_batch,
            &ShardRoutingPlan::new(1, 1),
            &mut reassembler,
        );
        assert_eq!(routed.batch_max_timestamp_micros, Some(1_100_000));

        for available_cpus in [1, 5] {
            let mut parser =
                PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
            let packet_count = Arc::new(AtomicUsize::new(0));
            let (output_tx, output_rx) = crossbeam::channel::unbounded();
            let counters = DnsProcessor::dns_processing_loop(
                Arc::new(
                    DnsProcessor::new_with_runtime_options(None, true, 1_200_000, true)
                        .expect("processor initializes")
                        .with_full_fragments(true),
                ),
                &mut parser,
                &packet_count,
                &output_tx,
                PipelineExecutionConfig {
                    execution_budget: ExecutionBudget::from_available_cpus(available_cpus),
                    affinity_plan: AffinityPlan::disabled(),
                    shard_parallelism_enabled: true,
                },
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            )
            .expect("pipeline completes");

            assert_eq!(
                counters.total_packets_processed,
                PACKET_BATCH_SIZE + 1,
                "available_cpus={available_cpus}"
            );
            assert_eq!(
                counters.dns_query_count, 1,
                "available_cpus={available_cpus}"
            );
            assert_eq!(
                counters.dns_response_count, 1,
                "available_cpus={available_cpus}"
            );
            assert_eq!(
                counters.matched_query_response_count, 1,
                "available_cpus={available_cpus}"
            );
            assert_eq!(
                counters.timeout_query_count, 0,
                "available_cpus={available_cpus}"
            );
            assert_eq!(parser.non_monotonic_timestamp_count(), 0);

            drop(output_tx);
            let records = output_rx
                .into_iter()
                .flat_map(|message| match message {
                    OutputMessage::Records(records) => records,
                    other => panic!("unexpected output message: {other:?}"),
                })
                .collect::<Vec<_>>();
            assert_eq!(records.len(), 1, "available_cpus={available_cpus}");
            assert_eq!(records[0].request_timestamp, 1_000_000);
            assert_eq!(records[0].response_timestamp, Some(1_200_000));
            assert_eq!(
                records[0].response_code.map(|code| code.to_string()),
                Some("EDNS_BADVERS".to_string())
            );
        }

        fs::remove_file(path).expect("test pcap removed");
    }

    #[test]
    fn routed_worker_batches_use_global_batch_max_timestamp() {
        let path = temp_test_path("pipeline-routed-batch-watermark", "pcap");
        let later_packet = make_udp_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53);
        let earlier_packet = make_udp_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53);
        fs::write(
            &path,
            classic_pcap_bytes(&[(2, 0, &later_packet), (1, 0, &earlier_packet)]),
        )
        .expect("test pcap written");

        let mut parser =
            PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
        let batch = parser
            .next_batch(2)
            .expect("batch read succeeds")
            .expect("packets are present");
        fs::remove_file(&path).expect("test pcap removed");

        let RoutedWorkerBatches {
            batch_max_timestamp_micros,
            worker_batches,
        } = route_batch_to_worker_batches(batch, &ShardRoutingPlan::new(4, 1), false);

        let ordered_packets = worker_batches[0]
            .iter()
            .flat_map(|routed_packets| {
                routed_packets
                    .packets
                    .iter()
                    .zip(routed_packets.metas.iter())
                    .map(|(packet, meta)| {
                        (
                            packet.timestamp_micros,
                            packet.packet_ordinal,
                            meta.is_response,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        assert_eq!(batch_max_timestamp_micros, Some(2_000_000));
        assert_eq!(
            ordered_packets,
            vec![(1_000_000, 1, false), (2_000_000, 0, false)]
        );
    }

    #[test]
    fn phase_worker_finalizes_pending_queries_without_signal_shutdown() {
        let dns_processor = Arc::new(DnsProcessor::new(None).expect("processor initializes"));
        let (batch_tx, batch_rx) = crossbeam::channel::bounded(1);
        let (output_tx, output_rx) = crossbeam::channel::unbounded();

        batch_tx
            .send(unresolved_query_batch(
                "phase-worker-finalization-without-signal",
            ))
            .expect("batch is sent");
        drop(batch_tx);

        let counters = run_phase_processing_worker(
            dns_processor,
            batch_rx,
            output_tx,
            1,
            false,
            test_worker_signals(false),
        )
        .expect("phase worker completes");

        assert_eq!(counters.dns_query_count, 1);
        assert_eq!(counters.timeout_query_count, 1);

        let output_records = output_rx
            .try_iter()
            .flat_map(|message| match message {
                OutputMessage::Records(records) => records,
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();
        assert_eq!(output_records.len(), 1);
        assert_eq!(output_records[0].response_timestamp, None);
        assert_eq!(output_records[0].response_code, None);
    }

    #[test]
    fn phase_worker_counts_dns_message_rejected_for_oversized_qname() {
        let dns_processor = Arc::new(DnsProcessor::new(None).expect("processor initializes"));
        let (batch_tx, batch_rx) = crossbeam::channel::bounded(1);
        let (output_tx, output_rx) = crossbeam::channel::unbounded();

        batch_tx
            .send(oversized_qname_batch("phase-worker-oversized-qname"))
            .expect("batch is sent");
        drop(batch_tx);

        let counters = run_phase_processing_worker(
            dns_processor,
            batch_rx,
            output_tx,
            1,
            false,
            test_worker_signals(false),
        )
        .expect("phase worker completes");

        assert_eq!(counters.oversized_qname_message_count, 1);
        assert_eq!(counters.dns_query_count, 0);
        assert_eq!(counters.dns_response_count, 0);
        assert!(output_rx.try_iter().next().is_none());
    }

    #[test]
    fn phase_worker_skips_pending_query_finalization_on_signal_shutdown() {
        let dns_processor = Arc::new(DnsProcessor::new(None).expect("processor initializes"));
        let (batch_tx, batch_rx) = crossbeam::channel::bounded(1);
        let (output_tx, output_rx) = crossbeam::channel::unbounded();

        batch_tx
            .send(unresolved_query_batch("phase-worker-signal-shutdown"))
            .expect("batch is sent");
        drop(batch_tx);

        let counters = run_phase_processing_worker(
            dns_processor,
            batch_rx,
            output_tx,
            1,
            false,
            test_worker_signals(true),
        )
        .expect("phase worker completes");

        assert_eq!(counters.dns_query_count, 1);
        assert_eq!(counters.timeout_query_count, 0);
        assert!(output_rx.try_iter().next().is_none());
    }

    #[test]
    fn matcher_worker_counts_dns_message_rejected_for_oversized_qname() {
        let dns_processor = Arc::new(DnsProcessor::new(None).expect("processor initializes"));
        let worker_range = 0..1;
        let RoutedWorkerBatches {
            batch_max_timestamp_micros,
            mut worker_batches,
        } = route_batch_to_worker_batches(
            oversized_qname_batch("matcher-worker-oversized-qname"),
            &ShardRoutingPlan::new(1, 1),
            false,
        );
        let shard_packets = worker_batches.pop().expect("worker batch exists");
        let (batch_tx, batch_rx) = crossbeam::channel::bounded(1);
        let (result_tx, result_rx) = crossbeam::channel::unbounded();

        batch_tx
            .send(MatcherBatchWork {
                batch_seq: 0,
                batch_max_timestamp_micros,
                shard_packets,
            })
            .expect("worker batch is sent");
        drop(batch_tx);

        run_matcher_worker(
            dns_processor,
            0,
            worker_range,
            batch_rx,
            result_tx,
            test_worker_signals(false),
        )
        .expect("matcher worker completes");

        let events = result_rx.try_iter().collect::<Vec<_>>();
        assert_eq!(events.len(), 2);

        let batch_result = match &events[0] {
            MatcherWorkerEvent::BatchResult { result, .. } => result,
            _ => panic!("expected batch result before finalization"),
        };
        assert_eq!(batch_result.oversized_qname_message_count, 1);
        assert_eq!(batch_result.dns_query_count, 0);
        assert_eq!(batch_result.dns_response_count, 0);
        assert!(batch_result.output_records.is_empty());
    }

    #[test]
    fn matcher_worker_skips_pending_query_finalization_on_signal_shutdown() {
        let dns_processor = Arc::new(DnsProcessor::new(None).expect("processor initializes"));
        let worker_range = 0..1;
        let RoutedWorkerBatches {
            batch_max_timestamp_micros,
            mut worker_batches,
        } = route_batch_to_worker_batches(
            unresolved_query_batch("matcher-worker-signal-shutdown"),
            &ShardRoutingPlan::new(1, 1),
            false,
        );
        let shard_packets = worker_batches.pop().expect("worker batch exists");
        let (batch_tx, batch_rx) = crossbeam::channel::bounded(1);
        let (result_tx, result_rx) = crossbeam::channel::unbounded();

        batch_tx
            .send(MatcherBatchWork {
                batch_seq: 0,
                batch_max_timestamp_micros,
                shard_packets,
            })
            .expect("worker batch is sent");
        drop(batch_tx);

        run_matcher_worker(
            dns_processor,
            0,
            worker_range,
            batch_rx,
            result_tx,
            test_worker_signals(true),
        )
        .expect("matcher worker completes");

        let events = result_rx.try_iter().collect::<Vec<_>>();
        assert_eq!(events.len(), 2);

        let batch_result = match &events[0] {
            MatcherWorkerEvent::BatchResult { result, .. } => result,
            _ => panic!("expected batch result before finalization"),
        };
        assert_eq!(batch_result.dns_query_count, 1);

        let finalization = match &events[1] {
            MatcherWorkerEvent::Finalization { result, .. } => result,
            _ => panic!("expected finalization result"),
        };
        assert_eq!(finalization.timeout_query_count, 0);
        assert!(finalization.output_records.is_empty());
    }

    #[test]
    fn pipeline_counters_stop_emitting_after_output_channel_closes() {
        let (output_tx, output_rx) = crossbeam::channel::bounded(1);
        drop(output_rx);
        let output_closed = AtomicBool::new(false);

        let mut counters = PipelineCounters::default();
        assert!(!counters.absorb(
            &output_tx,
            ShardProcessingResult {
                output_records: OutputRecordBatches::from_records(vec![
                    test_dns_record(),
                    test_dns_record(),
                ]),
                dns_query_count: 1,
                ..Default::default()
            },
            &output_closed,
        ));
        assert!(!counters.absorb(
            &output_tx,
            ShardProcessingResult {
                output_records: OutputRecordBatches::from_records(vec![test_dns_record()]),
                timeout_query_count: 2,
                ..Default::default()
            },
            &output_closed,
        ));

        assert!(!counters.output_channel_open);
        assert!(output_closed.load(AtomicOrdering::Relaxed));
        assert_eq!(counters.dns_query_count, 1);
        assert_eq!(counters.timeout_query_count, 2);
    }

    #[test]
    fn output_record_batches_chunk_large_record_vectors() {
        let (output_tx, output_rx) = crossbeam::channel::unbounded();
        let output_closed = AtomicBool::new(false);
        let records = (0..=OUTPUT_RECORD_BATCH_SIZE)
            .map(|idx| {
                let mut record = test_dns_record();
                record.id = idx as u16;
                record
            })
            .collect::<Vec<_>>();
        let output_records = OutputRecordBatches::from_records(records);

        assert!(emit_record_batches(
            &output_tx,
            output_records,
            &output_closed
        ));
        drop(output_tx);

        let output_batches = output_rx
            .try_iter()
            .map(|message| match message {
                OutputMessage::Records(records) => records,
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();

        assert_eq!(output_batches.len(), 2);
        assert_eq!(output_batches[0].len(), OUTPUT_RECORD_BATCH_SIZE);
        assert_eq!(output_batches[1].len(), 1);
        assert_eq!(output_batches[0][0].id, 0);
        assert_eq!(
            output_batches[0][OUTPUT_RECORD_BATCH_SIZE - 1].id,
            (OUTPUT_RECORD_BATCH_SIZE - 1) as u16
        );
        assert_eq!(output_batches[1][0].id, OUTPUT_RECORD_BATCH_SIZE as u16);
    }

    #[test]
    fn output_record_batches_pack_sparse_appends() {
        let (output_tx, output_rx) = crossbeam::channel::unbounded();
        let output_closed = AtomicBool::new(false);
        let mut output_records = OutputRecordBatches::default();

        for idx in 0..8 {
            let mut record = test_dns_record();
            record.id = idx;
            output_records.append(OutputRecordBatches::from_records(vec![record]));
        }

        assert!(emit_record_batches(
            &output_tx,
            output_records,
            &output_closed
        ));
        drop(output_tx);

        let output_batches = output_rx
            .try_iter()
            .map(|message| match message {
                OutputMessage::Records(records) => records,
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();

        assert_eq!(output_batches.len(), 1);
        assert_eq!(
            output_batches[0]
                .iter()
                .map(|record| record.id)
                .collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
    }
}

#[cfg(test)]
mod buffered_flow_hash_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn assert_flow_hash_matches_reference(flow: CanonicalFlowKey) {
        let identity = (flow.client_ip, flow.client_port, flow.resolver_ip);
        let mut reference = SeaHasher::new();
        identity.hash(&mut reference);
        let expected = reference.finish();
        let mut buffered = BufferedFlowHasher::default();
        identity.hash(&mut buffered);
        assert_eq!(buffered.finish(), expected, "{flow:?}");
        for shard_count in [1, 2, 3, 4, 7, 16, 64, 257, 1024] {
            assert_eq!(
                shard_map_index(flow, shard_count),
                (expected as usize) % shard_count,
                "{flow:?}, shard_count={shard_count}"
            );
        }
    }

    #[test]
    fn buffered_flow_hash_preserves_address_families_ports_and_shards() {
        let addresses = [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::BROADCAST),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::from(u128::MAX)),
            IpAddr::V6(Ipv6Addr::from(
                0x2001_0db8_0001_0203_0405_0607_0809_0a0b_u128,
            )),
            IpAddr::V6(Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped()),
        ];
        for client_ip in addresses {
            for resolver_ip in addresses {
                for client_port in [0, 1, 53, 1023, 1024, 32768, 65535] {
                    assert_flow_hash_matches_reference(CanonicalFlowKey {
                        client_ip,
                        client_port,
                        resolver_ip,
                    });
                }
            }
        }
    }

    #[test]
    fn buffered_flow_hash_matches_many_deterministic_flows() {
        fn next(state: &mut u64) -> u64 {
            *state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *state
        }
        let mut state = 0x0123_4567_89ab_cdef;
        for index in 0..4096 {
            let client_v4 = Ipv4Addr::from(next(&mut state) as u32);
            let client_v6 =
                Ipv6Addr::from((u128::from(next(&mut state)) << 64) | u128::from(next(&mut state)));
            let resolver_v4 = Ipv4Addr::from(next(&mut state) as u32);
            let resolver_v6 =
                Ipv6Addr::from((u128::from(next(&mut state)) << 64) | u128::from(next(&mut state)));
            assert_flow_hash_matches_reference(CanonicalFlowKey {
                client_ip: if index & 1 == 0 {
                    client_v4.into()
                } else {
                    client_v6.into()
                },
                client_port: next(&mut state) as u16,
                resolver_ip: if index & 2 == 0 {
                    resolver_v4.into()
                } else {
                    resolver_v6.into()
                },
            });
        }
    }

    #[test]
    fn buffered_flow_hash_preserves_integer_write_encodings() {
        macro_rules! check {
            ($method:ident, $value:expr) => {
                for prefix_len in [0, 63, 65] {
                    let prefix = [0x37; 65];
                    let mut reference = SeaHasher::new();
                    let mut buffered = BufferedFlowHasher::default();
                    reference.write(&prefix[..prefix_len]);
                    buffered.write(&prefix[..prefix_len]);
                    reference.$method($value);
                    buffered.$method($value);
                    assert_eq!(buffered.finish(), reference.finish(), stringify!($method));
                }
            };
        }
        check!(write_u8, 0xef);
        check!(write_u16, 0x1234);
        check!(write_u32, 0x1234_5678);
        check!(write_u64, 0x1234_5678_9abc_def0);
        check!(write_usize, 0x1234_5678);
        check!(write_i8, -17);
        check!(write_i16, -0x1234);
        check!(write_i32, -0x1234_5678);
        check!(write_i64, -0x1234_5678_9abc_def0);
        check!(write_isize, -0x1234_5678);
        check!(write_u128, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210);
        check!(write_i128, -0x0123_4567_89ab_cdef_fedc_ba98_7654_3210);
    }

    #[test]
    fn buffered_flow_hash_preserves_streaming_overflow_and_finish_semantics() {
        let bytes: Vec<u8> = (0..257).map(|index| (index * 73 + 19) as u8).collect();
        for length in [
            0, 1, 7, 8, 9, 31, 32, 33, 63, 64, 65, 66, 127, 128, 129, 256, 257,
        ] {
            for chunk_size in [1, 2, 3, 7, 8, 15, 16, 31, 63, 64, 65, 97, 257] {
                let mut reference = SeaHasher::new();
                let mut buffered = BufferedFlowHasher::default();
                for chunk in bytes[..length].chunks(chunk_size) {
                    reference.write(chunk);
                    buffered.write(chunk);
                    assert_eq!(buffered.finish(), reference.finish());
                    // finish is nondestructive, and an empty write cannot alter the stream.
                    buffered.write(&[]);
                    assert_eq!(buffered.finish(), reference.finish());
                }
                assert_eq!(buffered.finish(), reference.finish());
                reference.write(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
                buffered.write(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
                assert_eq!(buffered.finish(), reference.finish());
            }
        }
    }
}
