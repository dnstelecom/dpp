/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crossbeam::channel::{Receiver, Sender};
use rayon::prelude::*;
use seahash::SeaHasher;
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::IpAddr;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::thread;

use super::DnsProcessor;
use super::parser::{CanonicalFlowKey, ParsedUdpDnsMeta};
use super::types::{ProcessedDnsRecord, QueryMap, ResponseMap, ShardProcessingResult};
use crate::config::{ExecutionBudget, MATCHER_SHARD_FACTOR, PACKET_BATCH_SIZE};
use crate::output::OutputMessage;
use crate::packet_parser::{PacketBatch, PacketData, PacketParser, sort_packet_batch};

const BATCH_PREFETCH_DEPTH: usize = 2;
const MATCHER_WORKER_QUEUE_DEPTH: usize = 2;
const AGGREGATOR_REORDER_BUFFER_CAPACITY: usize =
    BATCH_PREFETCH_DEPTH + MATCHER_WORKER_QUEUE_DEPTH + 2;

#[derive(Default)]
struct PipelineCounters {
    dns_query_count: usize,
    duplicated_query_count: usize,
    dns_response_count: usize,
    matched_query_response_count: usize,
    timeout_query_count: usize,
    matched_rtt_sum_micros: u64,
    out_of_order_combined_count: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ProcessingCounters {
    pub(crate) total_packets_processed: usize,
    pub(crate) dns_query_count: usize,
    pub(crate) duplicated_query_count: usize,
    pub(crate) dns_response_count: usize,
    pub(crate) matched_query_response_count: usize,
    pub(crate) timeout_query_count: usize,
    pub(crate) matched_rtt_sum_micros: u64,
}

impl PipelineCounters {
    fn absorb(&mut self, tx: &Sender<OutputMessage>, shard_result: ShardProcessingResult) {
        self.dns_query_count += shard_result.dns_query_count;
        self.duplicated_query_count += shard_result.duplicated_query_count;
        self.dns_response_count += shard_result.dns_response_count;
        self.matched_query_response_count += shard_result.matched_query_response_count;
        self.timeout_query_count += shard_result.timeout_query_count;
        self.matched_rtt_sum_micros += shard_result.matched_rtt_sum_micros;
        self.out_of_order_combined_count += shard_result.out_of_order_combined_count;

        for record in shard_result.output_records {
            emit_record(tx, record);
        }
    }

    fn finalize(self, total_packets_processed: usize) -> ProcessingCounters {
        ProcessingCounters {
            total_packets_processed,
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

fn map_index(flow_key: Option<CanonicalFlowKey>, shard_count: usize, per_thread: bool) -> usize {
    if per_thread {
        let mut hasher = SeaHasher::new();
        let flow_key = flow_key.unwrap_or(CanonicalFlowKey {
            client_ip: IpAddr::from([0, 0, 0, 0]),
            client_port: 0,
            resolver_ip: IpAddr::from([0, 0, 0, 0]),
        });
        (
            flow_key.client_ip,
            flow_key.client_port,
            flow_key.resolver_ip,
        )
            .hash(&mut hasher);
        (hasher.finish() as usize) % shard_count
    } else {
        0
    }
}

fn emit_record(tx: &Sender<OutputMessage>, record: crate::record::DnsRecord) {
    if let Err(err) = tx.send(OutputMessage::Record(record)) {
        tracing::error!("Failed to send DnsRecord: {}", err);
    }
}

fn join_thread<T>(handle: thread::JoinHandle<anyhow::Result<T>>, label: &str) -> anyhow::Result<T> {
    handle
        .join()
        .map_err(|err| io::Error::other(format!("{label} panicked: {:?}", err)))?
}

fn logical_shard_count(num_threads: usize, per_thread: bool) -> usize {
    if per_thread {
        num_threads.saturating_mul(MATCHER_SHARD_FACTOR).max(1)
    } else {
        1
    }
}

fn matcher_worker_count(
    execution_budget: ExecutionBudget,
    per_thread: bool,
    shard_count: usize,
) -> usize {
    if per_thread && execution_budget.uses_staged_pipeline() {
        execution_budget
            .staged_worker_budget
            .min(shard_count)
            .max(1)
    } else {
        1
    }
}

fn worker_shard_ranges(shard_count: usize, worker_count: usize) -> Vec<Range<usize>> {
    (0..worker_count)
        .map(|worker_idx| {
            let start = worker_idx * shard_count / worker_count;
            let end = (worker_idx + 1) * shard_count / worker_count;
            start..end
        })
        .collect()
}

fn worker_for_shard(shard_idx: usize, worker_ranges: &[Range<usize>]) -> usize {
    worker_ranges
        .iter()
        .position(|range| range.contains(&shard_idx))
        .unwrap_or(worker_ranges.len().saturating_sub(1))
}

fn merge_shard_results(merged: &mut ShardProcessingResult, shard_result: ShardProcessingResult) {
    merged.dns_query_count += shard_result.dns_query_count;
    merged.duplicated_query_count += shard_result.duplicated_query_count;
    merged.dns_response_count += shard_result.dns_response_count;
    merged.matched_query_response_count += shard_result.matched_query_response_count;
    merged.timeout_query_count += shard_result.timeout_query_count;
    merged.matched_rtt_sum_micros += shard_result.matched_rtt_sum_micros;
    merged.out_of_order_combined_count += shard_result.out_of_order_combined_count;
    merged.output_records.extend(shard_result.output_records);
}

fn route_batch_to_worker_batches(
    mut packet_batch: PacketBatch,
    shard_count: usize,
    worker_ranges: &[Range<usize>],
) -> RoutedWorkerBatches {
    sort_packet_batch(packet_batch.as_mut_slice());
    let batch_max_timestamp_micros = packet_batch.last().map(|packet| packet.timestamp_micros);

    let mut worker_batches: Vec<Vec<RoutedDnsPackets>> = worker_ranges
        .iter()
        .map(|range| {
            (0..range.len())
                .map(|_| {
                    RoutedDnsPackets::with_capacity((packet_batch.len() / shard_count.max(1)) + 1)
                })
                .collect()
        })
        .collect();

    for packet_data in packet_batch {
        let Some(udp_dns_meta) = DnsProcessor::packet_routing_meta(packet_data.data.as_slice())
        else {
            continue;
        };

        let shard_idx = map_index(Some(udp_dns_meta.flow_key), shard_count, true);
        let worker_idx = worker_for_shard(shard_idx, worker_ranges);
        let local_shard_idx = shard_idx - worker_ranges[worker_idx].start;
        worker_batches[worker_idx][local_shard_idx].push(packet_data, udp_dns_meta);
    }

    RoutedWorkerBatches {
        batch_max_timestamp_micros,
        worker_batches,
    }
}

fn parse_shard_packets(
    dns_processor: &DnsProcessor,
    shard_packets: RoutedDnsPackets,
) -> Vec<ProcessedDnsRecord> {
    debug_assert_eq!(shard_packets.packets.len(), shard_packets.metas.len());
    let mut shard_records = Vec::with_capacity(shard_packets.packets.len());

    for (packet, udp_dns_meta) in shard_packets.packets.into_iter().zip(shard_packets.metas) {
        let Some(records) = dns_processor.process_packet_batch_with_meta(
            &packet.data,
            packet.timestamp_micros,
            udp_dns_meta,
        ) else {
            continue;
        };

        for (record_ordinal, mut record) in records.into_iter().enumerate() {
            record.packet_ordinal = packet.packet_ordinal;
            record.record_ordinal = record_ordinal as u32;
            shard_records.push(record);
        }
    }

    shard_records
}

fn run_phase_processing_worker(
    dns_processor: Arc<DnsProcessor>,
    batch_rx: Receiver<PacketBatch>,
    tx: Sender<OutputMessage>,
    shard_count: usize,
    per_thread: bool,
    shutdown_requested: Arc<AtomicBool>,
) -> anyhow::Result<PipelineCounters> {
    let (mut query_maps, mut response_maps): (Vec<QueryMap>, Vec<ResponseMap>) = if per_thread {
        (
            (0..shard_count).map(|_| QueryMap::new()).collect(),
            (0..shard_count).map(|_| ResponseMap::new()).collect(),
        )
    } else {
        (vec![QueryMap::new()], vec![ResponseMap::new()])
    };

    let mut counters = PipelineCounters::default();
    while let Ok(packet_batch) = batch_rx.recv() {
        let RoutedWorkerBatches {
            batch_max_timestamp_micros,
            worker_batches: shard_batches,
        } = route_batch_to_worker_batches(
            packet_batch,
            shard_count,
            &worker_shard_ranges(shard_count, shard_count),
        );

        let mut shard_results: Vec<(usize, ShardProcessingResult)> = shard_batches
            .into_par_iter()
            .map(|mut by_local_shard| by_local_shard.pop().unwrap_or_default())
            .zip(query_maps.par_iter_mut())
            .zip(response_maps.par_iter_mut())
            .enumerate()
            .map(|(map_idx, ((shard_records, query_map), response_map))| {
                let shard_result = dns_processor.process_shard_records_with_batch_watermark(
                    parse_shard_packets(&dns_processor, shard_records),
                    query_map,
                    response_map,
                    batch_max_timestamp_micros,
                );
                (map_idx, shard_result)
            })
            .collect();

        shard_results.sort_by_key(|(map_idx, _)| *map_idx);

        for (_, shard_result) in shard_results {
            counters.absorb(&tx, shard_result);
        }
    }

    if !shutdown_requested.load(AtomicOrdering::SeqCst) {
        let mut finalization_results: Vec<(usize, ShardProcessingResult)> = query_maps
            .par_iter_mut()
            .zip(response_maps.par_iter_mut())
            .enumerate()
            .map(|(map_idx, (query_map, response_map))| {
                (
                    map_idx,
                    dns_processor.finalize_shard(query_map, response_map),
                )
            })
            .collect();

        finalization_results.sort_by_key(|(map_idx, _)| *map_idx);

        for (_, shard_result) in finalization_results {
            counters.absorb(&tx, shard_result);
        }
    }

    Ok(counters)
}

fn run_parser_stage(
    batch_rx: Receiver<PacketBatch>,
    worker_txs: Vec<Sender<MatcherBatchWork>>,
    shard_count: usize,
) -> anyhow::Result<()> {
    let worker_ranges = worker_shard_ranges(shard_count, worker_txs.len());
    let mut batch_seq = 0_u64;

    while let Ok(packet_batch) = batch_rx.recv() {
        let RoutedWorkerBatches {
            batch_max_timestamp_micros,
            worker_batches,
        } = route_batch_to_worker_batches(packet_batch, shard_count, &worker_ranges);

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
                })?;
        }

        batch_seq = batch_seq.wrapping_add(1);
    }

    Ok(())
}

fn run_matcher_worker(
    dns_processor: Arc<DnsProcessor>,
    worker_idx: usize,
    shard_range: Range<usize>,
    batch_rx: Receiver<MatcherBatchWork>,
    result_tx: Sender<MatcherWorkerEvent>,
    shutdown_requested: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let logical_shard_count = shard_range.end.saturating_sub(shard_range.start);
    let mut query_maps: Vec<QueryMap> = (0..logical_shard_count).map(|_| QueryMap::new()).collect();
    let mut response_maps: Vec<ResponseMap> = (0..logical_shard_count)
        .map(|_| ResponseMap::new())
        .collect();

    while let Ok(work) = batch_rx.recv() {
        let mut merged = ShardProcessingResult::default();

        for ((shard_packets, query_map), response_map) in work
            .shard_packets
            .into_iter()
            .zip(query_maps.iter_mut())
            .zip(response_maps.iter_mut())
        {
            merge_shard_results(
                &mut merged,
                dns_processor.process_shard_records_with_batch_watermark(
                    parse_shard_packets(&dns_processor, shard_packets),
                    query_map,
                    response_map,
                    work.batch_max_timestamp_micros,
                ),
            );
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
            })?;
    }

    let mut finalization = ShardProcessingResult::default();
    if !shutdown_requested.load(AtomicOrdering::SeqCst) {
        for (query_map, response_map) in query_maps.iter_mut().zip(response_maps.iter_mut()) {
            merge_shard_results(
                &mut finalization,
                dns_processor.finalize_shard(query_map, response_map),
            );
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
        })?;

    Ok(())
}

fn run_aggregator(
    result_rx: Receiver<MatcherWorkerEvent>,
    tx: Sender<OutputMessage>,
    worker_count: usize,
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
                        counters.absorb(&tx, shard_result);
                    }
                }
            }
            MatcherWorkerEvent::Finalization { worker_idx, result } => {
                finalizations[worker_idx] = Some(result);
            }
        }
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
        counters.absorb(&tx, shard_result);
    }

    Ok(counters)
}

fn run_staged_processing_pipeline(
    dns_processor: Arc<DnsProcessor>,
    batch_rx: Receiver<PacketBatch>,
    tx: Sender<OutputMessage>,
    shard_count: usize,
    worker_count: usize,
    shutdown_requested: Arc<AtomicBool>,
) -> anyhow::Result<PipelineCounters> {
    let worker_ranges = worker_shard_ranges(shard_count, worker_count);
    let (result_tx, result_rx) =
        crossbeam::channel::bounded(MATCHER_WORKER_QUEUE_DEPTH * worker_count.max(1));

    let mut worker_txs = Vec::with_capacity(worker_count);
    let mut worker_handles = Vec::with_capacity(worker_count);

    for (worker_idx, shard_range) in worker_ranges.iter().cloned().enumerate() {
        let (worker_tx, worker_rx) = crossbeam::channel::bounded(MATCHER_WORKER_QUEUE_DEPTH);
        worker_txs.push(worker_tx);

        worker_handles.push(
            thread::Builder::new()
                .name(format!("DPP_Matcher_{}", worker_idx))
                .spawn({
                    let dns_processor = Arc::clone(&dns_processor);
                    let result_tx = result_tx.clone();
                    let shutdown_requested = Arc::clone(&shutdown_requested);
                    move || {
                        run_matcher_worker(
                            dns_processor,
                            worker_idx,
                            shard_range,
                            worker_rx,
                            result_tx,
                            shutdown_requested,
                        )
                    }
                })?,
        );
    }
    drop(result_tx);

    let parser_handle = thread::Builder::new()
        .name("DPP_Parser".to_string())
        .spawn(move || run_parser_stage(batch_rx, worker_txs, shard_count))?;

    let aggregator_result = run_aggregator(result_rx, tx, worker_count);

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
        execution_budget: ExecutionBudget,
        per_thread: bool,
        shutdown_requested: Arc<AtomicBool>,
    ) -> anyhow::Result<ProcessingCounters> {
        let shard_count = logical_shard_count(execution_budget.available_cpus, per_thread);
        let worker_count = matcher_worker_count(execution_budget, per_thread, shard_count);
        let (batch_tx, batch_rx) = crossbeam::channel::bounded(BATCH_PREFETCH_DEPTH);

        if execution_budget.uses_staged_pipeline() {
            tracing::info!(
                "Execution budget: auto using {} CPUs, staged worker budget: {} shard workers, {} reserved service threads",
                execution_budget.available_cpus,
                worker_count,
                execution_budget.staged_reserved_service_threads
            );
        } else {
            tracing::info!(
                "Execution budget: auto using {} CPUs, phase-parallel pipeline selected for low-core host, Rayon worker budget: {}",
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
                    move || {
                        run_staged_processing_pipeline(
                            dns_processor,
                            batch_rx,
                            output_tx,
                            shard_count,
                            worker_count,
                            shutdown_requested,
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
                    move || {
                        run_phase_processing_worker(
                            dns_processor,
                            batch_rx,
                            output_tx,
                            shard_count,
                            per_thread,
                            shutdown_requested,
                        )
                    }
                })?
        };

        let mut processed_packet_count = 0usize;
        while !shutdown_requested.load(AtomicOrdering::SeqCst) {
            let Some(packet_batch) = packet_parser.next_batch(PACKET_BATCH_SIZE)? else {
                break;
            };

            if shutdown_requested.load(AtomicOrdering::SeqCst) {
                break;
            }

            processed_packet_count += packet_batch.len();
            batch_tx.send(packet_batch).map_err(|err| {
                anyhow::anyhow!(
                    "Failed to hand off packet batch to processing pipeline: {}",
                    err
                )
            })?;
        }

        if shutdown_requested.load(AtomicOrdering::SeqCst) {
            tracing::warn!(
                "Termination signal received. DPP will stop accepting new batches, drain already accepted work, skip synthetic timeout finalization for pending unmatched queries, and discard any still-buffered output tail before exit."
            );
        }

        drop(batch_tx);

        let counters = join_thread(pipeline_handle, "Processing pipeline")?;
        packet_count.store(processed_packet_count, AtomicOrdering::Relaxed);

        Ok(counters.finalize(processed_packet_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_parser::PacketParser;
    use crate::test_support::{
        classic_pcap_bytes, encode_dns_header, make_udp_dns_packet,
        make_udp_dns_packet_with_payload, temp_test_path,
    };
    use std::fs;
    use std::sync::atomic::AtomicBool;

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

        let mut parser = PacketParser::new(&path, false).expect("parser opens");
        let batch = parser
            .next_batch(1)
            .expect("batch read succeeds")
            .expect("query packet is present");
        fs::remove_file(&path).expect("test pcap removed");

        batch
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
    fn non_parallel_mode_collapses_to_single_worker() {
        let staged_budget = ExecutionBudget::from_available_cpus(16);

        assert_eq!(matcher_worker_count(staged_budget, false, 64), 1);
    }

    #[test]
    fn worker_for_shard_handles_uneven_ranges() {
        let ranges = vec![0..1, 1..4, 4..7];

        assert_eq!(worker_for_shard(0, &ranges), 0);
        assert_eq!(worker_for_shard(1, &ranges), 1);
        assert_eq!(worker_for_shard(3, &ranges), 1);
        assert_eq!(worker_for_shard(4, &ranges), 2);
        assert_eq!(worker_for_shard(6, &ranges), 2);
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
    fn routed_worker_batches_use_global_batch_max_timestamp() {
        let path = temp_test_path("pipeline-routed-batch-watermark", "pcap");
        let later_packet = make_udp_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53);
        let earlier_packet = make_udp_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53);
        fs::write(
            &path,
            classic_pcap_bytes(&[(2, 0, &later_packet), (1, 0, &earlier_packet)]),
        )
        .expect("test pcap written");

        let mut parser = PacketParser::new(&path, false).expect("parser opens");
        let batch = parser
            .next_batch(2)
            .expect("batch read succeeds")
            .expect("packets are present");
        fs::remove_file(&path).expect("test pcap removed");

        let RoutedWorkerBatches {
            batch_max_timestamp_micros,
            worker_batches,
        } = {
            let whole_batch = 0..4;
            route_batch_to_worker_batches(batch, 4, std::slice::from_ref(&whole_batch))
        };

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
            Arc::new(AtomicBool::new(false)),
        )
        .expect("phase worker completes");

        assert_eq!(counters.dns_query_count, 1);
        assert_eq!(counters.timeout_query_count, 1);

        let output_records = output_rx
            .try_iter()
            .filter_map(|message| match message {
                OutputMessage::Record(record) => Some(record),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(output_records.len(), 1);
        assert_eq!(output_records[0].response_timestamp, 0);
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
            Arc::new(AtomicBool::new(true)),
        )
        .expect("phase worker completes");

        assert_eq!(counters.dns_query_count, 1);
        assert_eq!(counters.timeout_query_count, 0);
        assert!(output_rx.try_iter().next().is_none());
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
            1,
            std::slice::from_ref(&worker_range),
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
            Arc::new(AtomicBool::new(true)),
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
}
