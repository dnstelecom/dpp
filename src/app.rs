/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::config::{AppConfig, OutputFormat, ReportFormat};
use crate::dns_processor::{DnsProcessor, ProcessingCounters};
use crate::error::{AppRunError, OutputError};
use crate::output::OutputMessage;
use crate::packet_parser::{NonMonotonicTimestampSample, PacketParser};
use crate::{output, runtime};
use crossbeam::channel;
use num_format::{Locale, ToFormattedString};
use serde::Serialize;
use std::borrow::Cow;
use std::fs::canonicalize;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::Instant;
use tracing::info;

fn processing_mode_info() {
    info!("Processing mode: forward sorting with response-query matching");
}

#[must_use]
fn channel_info(args: &AppConfig) -> String {
    let capacity = args.output_channel_capacity();
    if args.uses_default_output_channel_capacity() {
        format!(
            "BOUNDED with {} elements (default)",
            capacity.to_formatted_string(&Locale::en)
        )
    } else {
        format!(
            "BONDED with {} elements",
            capacity.to_formatted_string(&Locale::en)
        )
    }
}

fn display_channel_info(args: &AppConfig) {
    info!("IO channel: {}", channel_info(args));
}

#[must_use]
fn packets_per_second(packet_count: usize, processing_completed_seconds: f64) -> u64 {
    (packet_count as f64 / processing_completed_seconds.max(f64::MIN_POSITIVE)) as u64
}

fn finalize_output_shutdown(
    shutdown_result: Result<(), crossbeam::channel::SendError<OutputMessage>>,
    writer_result: Result<(), OutputError>,
) -> Result<(), OutputError> {
    writer_result?;
    shutdown_result.map_err(|source| OutputError::OutputControlSend {
        source: Box::new(source),
    })
}

#[must_use]
fn format_information(args: &AppConfig) -> &'static str {
    match (args.format, args.v2, args.zstd) {
        (OutputFormat::Parquet, true, true) => "PARQUET V2 with ZSTD compression",
        (OutputFormat::Parquet, true, false) => "PARQUET V2",
        (OutputFormat::Parquet, false, true) => "PARQUET with ZSTD compression",
        (OutputFormat::Parquet, false, false) => "PARQUET",
        _ => "CSV",
    }
}

fn shutdown_output_message(graceful_signal_shutdown: bool) -> OutputMessage {
    if graceful_signal_shutdown {
        OutputMessage::Abort
    } else {
        OutputMessage::Shutdown
    }
}

fn display_parquet_format_information(args: &AppConfig) {
    info!("Format is: {}", format_information(args));
}

fn anonymization_status(args: &AppConfig) -> Cow<'static, str> {
    match args.anonymize_key_path() {
        None => Cow::Borrowed("False"),
        Some(path) => Cow::Owned(format!("True, key file {}", canonical_path_string(path))),
    }
}

fn display_anonymization(args: &AppConfig) {
    info!("Anonymization: {}", anonymization_status(args));
}

fn display_parser_mode(args: &AppConfig) {
    if args.dns_wire_fast_path {
        info!("DNS wire fast path: enabled (question-only decoder with hickory fallback)");
    } else {
        info!("DNS wire fast path: disabled");
    }
}

fn display_match_timeout(args: &AppConfig) {
    info!("DNS match timeout: {} ms", args.match_timeout_ms);
}

fn display_monotonic_capture_mode(args: &AppConfig) {
    if args.monotonic_capture {
        info!(
            "Monotonic capture mode: enabled (batched timeout eviction active; timestamp regressions abort the run)"
        );
    }
}

#[derive(Serialize)]
struct RunBuildSummary {
    version_hash: Option<&'static str>,
    git_commit_author: Option<&'static str>,
    git_timestamp: Option<&'static str>,
    build_timestamp: Option<&'static str>,
    build_hostname: Option<&'static str>,
    allocator: &'static str,
    os: &'static str,
    arch: &'static str,
    pid: u32,
}

#[derive(Serialize)]
struct RunConfigSummary {
    input_filename: String,
    output_filename: String,
    output_format: OutputFormat,
    report_format: ReportFormat,
    match_timeout_ms: u64,
    monotonic_capture: bool,
    dns_wire_fast_path: bool,
    anonymization_enabled: bool,
    anonymize_key_path: Option<String>,
    zstd: bool,
    v2: bool,
    silent: bool,
    affinity: bool,
    output_channel_capacity: usize,
    uses_default_output_channel_capacity: bool,
}

#[derive(Serialize)]
struct RunExecutionSummary {
    available_cpus: usize,
    model: crate::config::ExecutionModel,
    rayon_threads: Option<usize>,
    staged_reserved_service_threads: usize,
    staged_worker_budget: usize,
}

#[derive(Serialize)]
struct NonMonotonicTimestampWarningSummary {
    count: usize,
    previous_packet_ordinal: u64,
    previous_timestamp_micros: i64,
    current_packet_ordinal: u64,
    current_timestamp_micros: i64,
    recommendation: &'static str,
}

#[derive(Serialize, Default)]
struct RunWarningsSummary {
    non_monotonic_capture_timestamps: Option<NonMonotonicTimestampWarningSummary>,
    graceful_signal_shutdown: bool,
}

#[derive(Serialize)]
struct RunMetricsSummary {
    total_packets_processed: usize,
    total_dns_queries_processed: usize,
    deduplicated_duplicate_queries: usize,
    total_dns_responses_processed: usize,
    total_matched_query_response_pairs: usize,
    timed_out_queries: usize,
    timed_out_query_ratio: f64,
    average_matched_rtt_ms: Option<f64>,
    processing_seconds: f64,
    processing_speed_pps: u64,
    final_write_post_processing_seconds: f64,
    max_memory_usage_kib: usize,
    total_runtime_seconds: f64,
}

#[derive(Serialize)]
struct RunSummary {
    build: RunBuildSummary,
    config: RunConfigSummary,
    execution: RunExecutionSummary,
    metrics: RunMetricsSummary,
    warnings: RunWarningsSummary,
}

fn canonical_path_string(path: &Path) -> String {
    canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn non_monotonic_timestamp_warning(
    packet_parser: &PacketParser,
) -> Option<NonMonotonicTimestampWarningSummary> {
    let count = packet_parser.non_monotonic_timestamp_count();
    let sample = packet_parser.first_non_monotonic_timestamp()?;

    Some(non_monotonic_timestamp_warning_from_sample(count, sample))
}

fn non_monotonic_timestamp_warning_from_sample(
    count: usize,
    sample: NonMonotonicTimestampSample,
) -> NonMonotonicTimestampWarningSummary {
    NonMonotonicTimestampWarningSummary {
        count,
        previous_packet_ordinal: sample.previous_packet_ordinal,
        previous_timestamp_micros: sample.previous_timestamp_micros,
        current_packet_ordinal: sample.current_packet_ordinal,
        current_timestamp_micros: sample.current_timestamp_micros,
        recommendation: "Normalize the capture first with Wireshark's reordercap tool, for example: reordercap input.pcap normalized.pcap.",
    }
}

fn display_non_monotonic_timestamp_warning(warning: &NonMonotonicTimestampWarningSummary) {
    tracing::warn!(
        "{}",
        runtime::emphasize_warning(format!(
            "Detected {} non-monotonic packet timestamps in capture order. First regression: packet {} at {}us followed packet {} at {}us. Matching remains deterministic, but timestamp-based pairing quality may degrade. {}",
            warning.count,
            warning.current_packet_ordinal,
            warning.current_timestamp_micros,
            warning.previous_packet_ordinal,
            warning.previous_timestamp_micros,
            warning.recommendation,
        ))
    );
}

fn max_memory_usage_kib(max_memory_usage: Option<&Arc<AtomicUsize>>) -> usize {
    max_memory_usage
        .map(|usage| usage.load(AtomicOrdering::SeqCst))
        .unwrap_or(0)
}

fn timed_out_query_ratio(timeout_query_count: usize, dns_query_count: usize) -> f64 {
    if dns_query_count == 0 {
        0.0
    } else {
        timeout_query_count as f64 / dns_query_count as f64
    }
}

fn average_matched_rtt_ms(
    matched_query_response_count: usize,
    matched_rtt_sum_micros: u64,
) -> Option<f64> {
    if matched_query_response_count == 0 {
        None
    } else {
        Some(matched_rtt_sum_micros as f64 / matched_query_response_count as f64 / 1_000.0)
    }
}

fn build_run_summary(
    args: &AppConfig,
    execution_budget: crate::config::ExecutionBudget,
    counters: ProcessingCounters,
    warnings: RunWarningsSummary,
    max_memory_usage_kib: usize,
    processing_seconds: f64,
    final_write_post_processing_seconds: f64,
    total_runtime_seconds: f64,
) -> RunSummary {
    let processing_speed_pps =
        packets_per_second(counters.total_packets_processed, processing_seconds);

    RunSummary {
        build: RunBuildSummary {
            version_hash: option_env!("VERGEN_GIT_SHA"),
            git_commit_author: option_env!("VERGEN_GIT_COMMIT_AUTHOR_EMAIL"),
            git_timestamp: option_env!("VERGEN_GIT_COMMIT_TIMESTAMP"),
            build_timestamp: option_env!("VERGEN_BUILD_TIMESTAMP"),
            build_hostname: option_env!("BUILD_HOSTNAME"),
            allocator: crate::allocator::ALLOCATOR_NAME,
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            pid: std::process::id(),
        },
        config: RunConfigSummary {
            input_filename: canonical_path_string(&args.filename),
            output_filename: canonical_path_string(&args.output_filename),
            output_format: args.format,
            report_format: args.report_format,
            match_timeout_ms: args.match_timeout_ms,
            monotonic_capture: args.monotonic_capture,
            dns_wire_fast_path: args.dns_wire_fast_path,
            anonymization_enabled: args.anonymize_key_path().is_some(),
            anonymize_key_path: args.anonymize_key_path().map(canonical_path_string),
            zstd: args.zstd,
            v2: args.v2,
            silent: args.silent,
            affinity: args.affinity,
            output_channel_capacity: args.output_channel_capacity(),
            uses_default_output_channel_capacity: args.uses_default_output_channel_capacity(),
        },
        execution: RunExecutionSummary {
            available_cpus: execution_budget.available_cpus,
            model: execution_budget.model,
            rayon_threads: execution_budget.rayon_threads,
            staged_reserved_service_threads: execution_budget.staged_reserved_service_threads,
            staged_worker_budget: execution_budget.staged_worker_budget,
        },
        metrics: RunMetricsSummary {
            total_packets_processed: counters.total_packets_processed,
            total_dns_queries_processed: counters.dns_query_count,
            deduplicated_duplicate_queries: counters.duplicated_query_count,
            total_dns_responses_processed: counters.dns_response_count,
            total_matched_query_response_pairs: counters.matched_query_response_count,
            timed_out_queries: counters.timeout_query_count,
            timed_out_query_ratio: timed_out_query_ratio(
                counters.timeout_query_count,
                counters.dns_query_count,
            ),
            average_matched_rtt_ms: average_matched_rtt_ms(
                counters.matched_query_response_count,
                counters.matched_rtt_sum_micros,
            ),
            processing_seconds,
            processing_speed_pps,
            final_write_post_processing_seconds,
            max_memory_usage_kib,
            total_runtime_seconds,
        },
        warnings,
    }
}

fn display_text_summary(summary: &RunSummary) {
    info!(
        "Total packets processed: {}",
        summary
            .metrics
            .total_packets_processed
            .to_formatted_string(&Locale::en)
    );
    info!(
        "Total DNS queries processed: {}",
        summary
            .metrics
            .total_dns_queries_processed
            .to_formatted_string(&Locale::en)
    );
    info!(
        "Deduplicated duplicate queries: {}",
        summary
            .metrics
            .deduplicated_duplicate_queries
            .to_formatted_string(&Locale::en)
    );
    info!(
        "Total DNS responses processed: {}",
        summary
            .metrics
            .total_dns_responses_processed
            .to_formatted_string(&Locale::en)
    );
    info!(
        "Total matched Query-Response pairs: {}",
        summary
            .metrics
            .total_matched_query_response_pairs
            .to_formatted_string(&Locale::en)
    );
    info!(
        "Timed-out queries: {} ({:.2}%)",
        summary
            .metrics
            .timed_out_queries
            .to_formatted_string(&Locale::en),
        summary.metrics.timed_out_query_ratio * 100.0
    );

    match summary.metrics.average_matched_rtt_ms {
        Some(average_rtt_ms) => info!("Average matched RTT: {:.3} ms", average_rtt_ms),
        None => info!("Average matched RTT: n/a"),
    }

    if let Some(warning) = &summary.warnings.non_monotonic_capture_timestamps {
        display_non_monotonic_timestamp_warning(warning);
    }

    if summary.warnings.graceful_signal_shutdown {
        tracing::warn!(
            "{}",
            runtime::emphasize_warning(
                "A termination signal was received. DPP stopped accepting new batches, drained already accepted work, skipped synthetic timeout finalization for pending unmatched queries, and discarded any still-buffered output tail before exit."
            )
        );
    }

    info!(
        "Processing speed: {} packets per second",
        summary
            .metrics
            .processing_speed_pps
            .to_formatted_string(&Locale::en)
    );
    info!(
        "Final write post-processing completed in +{:.3} seconds",
        summary.metrics.final_write_post_processing_seconds
    );
    info!(
        "Max memory usage (RSS): {} KiB",
        summary
            .metrics
            .max_memory_usage_kib
            .to_formatted_string(&Locale::en)
    );
    info!(
        "Processing completed in: {:?}",
        runtime::format_duration(std::time::Duration::from_secs_f64(
            summary.metrics.total_runtime_seconds,
        ))
    );
}

fn emit_json_summary(summary: &RunSummary) -> anyhow::Result<()> {
    serde_json::to_writer(std::io::stdout(), summary)?;
    println!();
    Ok(())
}

pub(crate) fn run(args: AppConfig) -> Result<(), AppRunError> {
    let start_time = Instant::now();
    let shutdown_requested = runtime::install_shutdown_signal_handler()?;
    let execution_budget = args.execution_budget();
    if let Some(rayon_threads) = execution_budget.rayon_threads {
        runtime::create_thread_pool(rayon_threads, args.affinity)?;
    }

    let packet_count = Arc::new(AtomicUsize::new(0));

    if let Some(requested_threads) = args.requested_threads {
        tracing::warn!(
            "Ignoring deprecated thread override {}. DPP now auto-sizes execution from all available CPUs.",
            requested_threads
        );
    }

    runtime::log_build_messages()?;
    runtime::log_system_info(&args)?;
    runtime::log_accessible_input_file(&args)?;

    processing_mode_info();
    display_channel_info(&args);

    let (tx, rx) = channel::bounded(args.output_channel_capacity());

    display_parquet_format_information(&args);
    display_anonymization(&args);
    display_parser_mode(&args);
    display_match_timeout(&args);
    display_monotonic_capture_mode(&args);

    let (max_memory_usage, memory_thread) = runtime::maybe_start_memory_monitoring(args.silent)?;
    let writer_thread = output::create_writer_thread(&args, rx)?;
    info!(
        "Results will be written to: {}",
        canonical_path_string(&args.output_filename)
    );

    let dns_processor = Arc::new(
        DnsProcessor::new_with_runtime_options(
            args.anonymize_key_path(),
            args.dns_wire_fast_path,
            args.match_timeout_micros(),
            args.monotonic_capture,
        )
        .map_err(|source| AppRunError::DnsProcessorInit { source })?,
    );
    let mut packet_parser = PacketParser::new(&args.filename, args.monotonic_capture)
        .map_err(|source| AppRunError::PacketParserInit { source })?;

    let counters = DnsProcessor::dns_processing_loop(
        dns_processor,
        &mut packet_parser,
        &packet_count,
        &tx,
        execution_budget,
        true,
        Arc::clone(&shutdown_requested),
    )
    .map_err(|source| AppRunError::Processing { source })?;
    let processing_seconds = start_time.elapsed().as_secs_f64();

    let io_flush_start = Instant::now();
    let graceful_signal_shutdown = shutdown_requested.load(AtomicOrdering::SeqCst);
    let shutdown_result = tx.send(shutdown_output_message(graceful_signal_shutdown));
    drop(tx);

    if let Some(memory_thread) = memory_thread {
        memory_thread.stop();
        memory_thread
            .join()
            .map_err(|source| AppRunError::MemoryMonitorShutdown { source })?;
    }

    let writer_result = writer_thread
        .join()
        .map_err(|e| OutputError::WriterThreadPanic(format!("{:?}", e)))?;
    finalize_output_shutdown(
        shutdown_result,
        writer_result.map_err(|source| OutputError::WriterThreadFailure { source }),
    )?;

    if !args.writes_output_to_stdout() {
        let final_write_post_processing_seconds = io_flush_start.elapsed().as_secs_f64();
        let total_runtime_seconds = start_time.elapsed().as_secs_f64();
        let max_memory_kib = max_memory_usage_kib(max_memory_usage.as_ref());
        let warnings = RunWarningsSummary {
            non_monotonic_capture_timestamps: non_monotonic_timestamp_warning(&packet_parser),
            graceful_signal_shutdown,
        };
        let summary = build_run_summary(
            &args,
            execution_budget,
            counters,
            warnings,
            max_memory_kib,
            processing_seconds,
            final_write_post_processing_seconds,
            total_runtime_seconds,
        );

        match args.report_format {
            ReportFormat::Text => display_text_summary(&summary),
            ReportFormat::Json => {
                emit_json_summary(&summary).map_err(|source| AppRunError::JsonSummary { source })?
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        classic_pcap_bytes, encode_dns_header, make_udp_dns_packet_with_payload, temp_test_path,
    };
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};

    fn test_config() -> AppConfig {
        AppConfig {
            filename: PathBuf::from("input.pcap"),
            output_filename: PathBuf::from("output.csv"),
            format: OutputFormat::Csv,
            report_format: crate::config::ReportFormat::Text,
            match_timeout_ms: crate::config::DEFAULT_MATCH_TIMEOUT_MS,
            monotonic_capture: false,
            zstd: false,
            v2: false,
            silent: true,
            num_cpus: 1,
            requested_threads: None,
            affinity: false,
            bonded: 0,
            anonymize: None,
            dns_wire_fast_path: false,
        }
    }

    #[test]
    fn channel_info_uses_safe_default_for_zero_bonded() {
        let config = test_config();

        assert_eq!(
            channel_info(&config),
            "BOUNDED with 131,072 elements (default)"
        );
    }

    #[test]
    fn finalize_output_shutdown_prefers_writer_failure() {
        let (tx, rx) = crossbeam::channel::bounded(1);
        drop(rx);

        let shutdown_result = tx.send(OutputMessage::Shutdown);
        let result = finalize_output_shutdown(
            shutdown_result,
            Err(OutputError::WriterThreadPanic("boom".to_string())),
        );

        assert!(
            matches!(result, Err(OutputError::WriterThreadPanic(message)) if message == "boom")
        );
    }

    #[test]
    fn finalize_output_shutdown_reports_send_failure_when_writer_succeeds() {
        let (tx, rx) = crossbeam::channel::bounded(1);
        drop(rx);

        let shutdown_result = tx.send(OutputMessage::Shutdown);
        let result = finalize_output_shutdown(shutdown_result, Ok(()));

        assert!(matches!(result, Err(OutputError::OutputControlSend { .. })));
    }

    #[test]
    fn canonical_path_string_falls_back_to_original_path_when_missing() {
        let path = Path::new("does-not-exist-yet/output.csv");

        assert_eq!(canonical_path_string(path), path.display().to_string());
    }

    fn example_question() -> Vec<u8> {
        let mut question = Vec::new();
        question.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        question.extend_from_slice(&1_u16.to_be_bytes());
        question.extend_from_slice(&1_u16.to_be_bytes());
        question
    }

    fn write_query_response_pcap(path: &Path) {
        let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
        query_payload.extend_from_slice(&example_question());

        let mut response_payload = encode_dns_header(0x1234, 0x8180, 1);
        response_payload.extend_from_slice(&example_question());

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

        fs::write(
            path,
            classic_pcap_bytes(&[(1, 0, &query_packet), (1, 200_000, &response_packet)]),
        )
        .expect("test pcap written");
    }

    fn integration_config(
        filename: PathBuf,
        output_filename: PathBuf,
        format: OutputFormat,
    ) -> AppConfig {
        AppConfig {
            filename,
            output_filename,
            format,
            report_format: crate::config::ReportFormat::Text,
            match_timeout_ms: crate::config::DEFAULT_MATCH_TIMEOUT_MS,
            monotonic_capture: false,
            zstd: false,
            v2: false,
            silent: true,
            num_cpus: 5,
            requested_threads: None,
            affinity: false,
            bonded: 0,
            anonymize: None,
            dns_wire_fast_path: false,
        }
    }

    #[test]
    fn run_summary_separates_processing_speed_from_total_runtime() {
        let config = test_config();
        let summary = build_run_summary(
            &config,
            config.execution_budget(),
            ProcessingCounters {
                total_packets_processed: 4_000,
                ..ProcessingCounters::default()
            },
            RunWarningsSummary::default(),
            123,
            2.0,
            0.75,
            2.75,
        );

        assert_eq!(summary.metrics.processing_speed_pps, 2_000);
        assert_eq!(summary.metrics.processing_seconds, 2.0);
        assert_eq!(summary.metrics.final_write_post_processing_seconds, 0.75);
        assert_eq!(summary.metrics.total_runtime_seconds, 2.75);
    }

    #[test]
    fn run_summary_serializes_memory_metric_as_kib() {
        let config = test_config();
        let summary = build_run_summary(
            &config,
            config.execution_budget(),
            ProcessingCounters::default(),
            RunWarningsSummary::default(),
            123,
            1.0,
            0.5,
            1.5,
        );

        let serialized = serde_json::to_value(&summary).expect("summary serializes");
        let metrics = serialized
            .get("metrics")
            .and_then(serde_json::Value::as_object)
            .expect("metrics object is present");

        assert_eq!(
            metrics.get("max_memory_usage_kib"),
            Some(&serde_json::json!(123))
        );
        assert!(!metrics.contains_key("max_memory_usage_kb"));
    }

    #[test]
    fn run_summary_serializes_graceful_signal_shutdown_warning() {
        let config = test_config();
        let summary = build_run_summary(
            &config,
            config.execution_budget(),
            ProcessingCounters::default(),
            RunWarningsSummary {
                graceful_signal_shutdown: true,
                ..RunWarningsSummary::default()
            },
            0,
            1.0,
            0.5,
            1.5,
        );

        let serialized = serde_json::to_value(&summary).expect("summary serializes");
        let warnings = serialized
            .get("warnings")
            .and_then(serde_json::Value::as_object)
            .expect("warnings object is present");

        assert_eq!(
            warnings.get("graceful_signal_shutdown"),
            Some(&serde_json::json!(true))
        );
    }

    #[test]
    fn run_summary_serializes_non_monotonic_capture_warning() {
        let config = test_config();
        let summary = build_run_summary(
            &config,
            config.execution_budget(),
            ProcessingCounters::default(),
            RunWarningsSummary {
                non_monotonic_capture_timestamps: Some(
                    non_monotonic_timestamp_warning_from_sample(
                        2,
                        NonMonotonicTimestampSample {
                            previous_packet_ordinal: 10,
                            previous_timestamp_micros: 2_000_000,
                            current_packet_ordinal: 11,
                            current_timestamp_micros: 1_500_000,
                        },
                    ),
                ),
                ..RunWarningsSummary::default()
            },
            0,
            1.0,
            0.5,
            1.5,
        );

        let serialized = serde_json::to_value(&summary).expect("summary serializes");
        let warning = serialized
            .get("warnings")
            .and_then(|warnings| warnings.get("non_monotonic_capture_timestamps"))
            .and_then(serde_json::Value::as_object)
            .expect("non-monotonic warning is present");

        assert_eq!(warning.get("count"), Some(&serde_json::json!(2)));
        assert_eq!(
            warning.get("recommendation"),
            Some(&serde_json::json!(
                "Normalize the capture first with Wireshark's reordercap tool, for example: reordercap input.pcap normalized.pcap."
            ))
        );
    }

    #[test]
    fn run_summary_reports_timeout_ratio_and_average_rtt() {
        let config = test_config();
        let summary = build_run_summary(
            &config,
            config.execution_budget(),
            ProcessingCounters {
                dns_query_count: 10,
                matched_query_response_count: 8,
                timeout_query_count: 2,
                matched_rtt_sum_micros: 16_000,
                ..ProcessingCounters::default()
            },
            RunWarningsSummary::default(),
            0,
            1.0,
            0.5,
            1.5,
        );

        assert_eq!(summary.metrics.timed_out_queries, 2);
        assert!((summary.metrics.timed_out_query_ratio - 0.2).abs() < f64::EPSILON);
        assert_eq!(summary.metrics.average_matched_rtt_ms, Some(2.0));
    }

    #[test]
    fn signal_shutdown_uses_abort_message_for_output_teardown() {
        assert!(matches!(
            shutdown_output_message(true),
            OutputMessage::Abort
        ));

        assert!(matches!(
            shutdown_output_message(true),
            OutputMessage::Abort
        ));
    }

    #[test]
    fn normal_completion_keeps_shutdown_message_for_output_teardown() {
        assert!(matches!(
            shutdown_output_message(false),
            OutputMessage::Shutdown
        ));
    }

    #[test]
    fn run_writes_csv_from_real_pcap_input() {
        let input_path = temp_test_path("csv-input", "pcap");
        let output_path = temp_test_path("csv-output", "csv");
        write_query_response_pcap(&input_path);

        let config = integration_config(input_path.clone(), output_path.clone(), OutputFormat::Csv);
        run(config).expect("app run succeeds");

        let output = fs::read_to_string(&output_path).expect("csv output is readable");
        assert!(output.contains("request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code"));
        assert!(output.contains("1000000,1200000,10.0.0.1,53000,4660,example.com,A,No Error"));

        fs::remove_file(output_path).expect("removes csv output");
        fs::remove_file(input_path).expect("removes input pcap");
    }

    #[test]
    fn run_writes_parquet_from_real_pcap_input() {
        let input_path = temp_test_path("parquet-input", "pcap");
        let output_path = temp_test_path("parquet-output", "parquet");
        write_query_response_pcap(&input_path);

        let config = integration_config(
            input_path.clone(),
            output_path.clone(),
            OutputFormat::Parquet,
        );
        run(config).expect("app run succeeds");

        let reader =
            SerializedFileReader::new(File::open(&output_path).expect("opens parquet output"))
                .expect("parquet output is readable");
        assert_eq!(reader.metadata().file_metadata().num_rows(), 1);
        assert_eq!(reader.metadata().num_row_groups(), 1);

        fs::remove_file(output_path).expect("removes parquet output");
        fs::remove_file(input_path).expect("removes input pcap");
    }
}
