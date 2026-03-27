/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use anyhow::{Result, anyhow};
use serde::Serialize;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Batch size used when reading packets from the PCAP source.
pub(crate) const PACKET_BATCH_SIZE: usize = 65_536;

/// Default DNS match timeout, expressed in milliseconds.
pub(crate) const DEFAULT_MATCH_TIMEOUT_MS: u64 = 1_200;

/// Maximum supported DNS match timeout, expressed in milliseconds.
pub(crate) const MAX_MATCH_TIMEOUT_MS: u64 = 5_000;

/// Logical shard multiplier used to reduce hot-shard skew relative to worker count.
pub(crate) const MATCHER_SHARD_FACTOR: usize = 4;

/// Router/aggregator and parser threads reserved inside the staged pipeline budget.
pub(crate) const STAGED_PIPELINE_NON_WORKER_THREADS: usize = 2;

/// Minimum CPU budget at which the staged pipeline still leaves enough room for useful shard work.
pub(crate) const STAGED_PIPELINE_MIN_CPUS: usize = STAGED_PIPELINE_NON_WORKER_THREADS + 3;

/// Threshold at which buffered output records are flushed to disk.
pub(crate) const OUTPUT_FLUSH_THRESHOLD: usize = 65_536;

/// Safe default capacity for the handoff channel between processing and writers.
pub(crate) const DEFAULT_OUTPUT_CHANNEL_CAPACITY: usize = OUTPUT_FLUSH_THRESHOLD * 2;

/// Stack size for Rayon worker threads in release builds.
pub(crate) const WORKER_STACK_SIZE_MB: usize = 16;

/// Parquet row-group batch size.
pub(crate) const PARQUET_WRITE_BATCH_SIZE: usize = 65_536;

/// POSIX-style output path sentinel that directs exported records to standard output.
pub(crate) const STDOUT_OUTPUT_SENTINEL: &str = "-";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OutputFormat {
    Csv,
    Parquet,
}

impl OutputFormat {
    pub(crate) fn default_output_filename(self) -> &'static str {
        match self {
            OutputFormat::Csv => "dns_output.csv",
            OutputFormat::Parquet => "dns_output.parquet",
        }
    }
}

pub(crate) fn output_path_targets_stdout(path: &Path) -> bool {
    path == Path::new(STDOUT_OUTPUT_SENTINEL)
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Csv => write!(f, "csv"),
            OutputFormat::Parquet => write!(f, "parquet"),
        }
    }
}

impl FromStr for OutputFormat {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "csv" => Ok(OutputFormat::Csv),
            "parquet" | "pq" => Ok(OutputFormat::Parquet),
            _ => Err(anyhow!("Unsupported output format '{value}'")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ReportFormat {
    Text,
    Json,
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReportFormat::Text => write!(f, "text"),
            ReportFormat::Json => write!(f, "json"),
        }
    }
}

impl FromStr for ReportFormat {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "text" => Ok(ReportFormat::Text),
            "json" => Ok(ReportFormat::Json),
            _ => Err(anyhow!("Unsupported report format '{value}'")),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AppConfig {
    pub(crate) filename: PathBuf,
    pub(crate) output_filename: PathBuf,
    pub(crate) format: OutputFormat,
    pub(crate) report_format: ReportFormat,
    pub(crate) match_timeout_ms: u64,
    pub(crate) monotonic_capture: bool,
    pub(crate) zstd: bool,
    pub(crate) v2: bool,
    pub(crate) silent: bool,
    pub(crate) num_cpus: usize,
    pub(crate) requested_threads: Option<usize>,
    pub(crate) affinity: bool,
    pub(crate) bonded: usize,
    pub(crate) anonymize: Option<PathBuf>,
    pub(crate) dns_wire_fast_path: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExecutionModel {
    PhaseParallel,
    Staged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecutionBudget {
    pub(crate) available_cpus: usize,
    pub(crate) model: ExecutionModel,
    pub(crate) rayon_threads: Option<usize>,
    pub(crate) staged_reserved_service_threads: usize,
    pub(crate) staged_worker_budget: usize,
}

impl ExecutionBudget {
    pub(crate) fn from_available_cpus(available_cpus: usize) -> Self {
        let available_cpus = available_cpus.max(1);

        if available_cpus < STAGED_PIPELINE_MIN_CPUS {
            return Self {
                available_cpus,
                model: ExecutionModel::PhaseParallel,
                rayon_threads: Some(available_cpus),
                staged_reserved_service_threads: 0,
                staged_worker_budget: 0,
            };
        }

        Self {
            available_cpus,
            model: ExecutionModel::Staged,
            rayon_threads: None,
            staged_reserved_service_threads: STAGED_PIPELINE_NON_WORKER_THREADS,
            staged_worker_budget: available_cpus
                .saturating_sub(STAGED_PIPELINE_NON_WORKER_THREADS)
                .max(1),
        }
    }

    pub(crate) fn uses_staged_pipeline(self) -> bool {
        matches!(self.model, ExecutionModel::Staged)
    }
}

impl AppConfig {
    pub(crate) fn writes_output_to_stdout(&self) -> bool {
        output_path_targets_stdout(&self.output_filename)
    }

    pub(crate) fn match_timeout_micros(&self) -> i64 {
        i64::try_from(self.match_timeout_ms)
            .expect("validated timeout milliseconds fit into i64")
            .checked_mul(1_000)
            .expect("validated timeout milliseconds fit into microseconds")
    }

    pub(crate) fn anonymize_key_path(&self) -> Option<&Path> {
        self.anonymize.as_deref()
    }

    pub(crate) fn output_channel_capacity(&self) -> usize {
        if self.bonded == 0 {
            DEFAULT_OUTPUT_CHANNEL_CAPACITY
        } else {
            self.bonded
        }
    }

    pub(crate) fn uses_default_output_channel_capacity(&self) -> bool {
        self.bonded == 0
    }

    pub(crate) fn execution_budget(&self) -> ExecutionBudget {
        ExecutionBudget::from_available_cpus(self.num_cpus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AppConfig {
        AppConfig {
            filename: PathBuf::from("input.pcap"),
            output_filename: PathBuf::from("output.csv"),
            format: OutputFormat::Csv,
            report_format: ReportFormat::Text,
            match_timeout_ms: DEFAULT_MATCH_TIMEOUT_MS,
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
    fn zero_bonded_uses_safe_default_capacity() {
        let config = test_config();

        assert_eq!(
            config.output_channel_capacity(),
            DEFAULT_OUTPUT_CHANNEL_CAPACITY
        );
        assert!(config.uses_default_output_channel_capacity());
    }

    #[test]
    fn explicit_bonded_capacity_overrides_default() {
        let mut config = test_config();
        config.bonded = 4096;

        assert_eq!(config.output_channel_capacity(), 4096);
        assert!(!config.uses_default_output_channel_capacity());
    }

    #[test]
    fn low_core_hosts_use_phase_parallel_budget() {
        let budget = ExecutionBudget::from_available_cpus(4);

        assert_eq!(budget.model, ExecutionModel::PhaseParallel);
        assert_eq!(budget.rayon_threads, Some(4));
        assert_eq!(budget.staged_reserved_service_threads, 0);
        assert_eq!(budget.staged_worker_budget, 0);
        assert!(!budget.uses_staged_pipeline());
    }

    #[test]
    fn match_timeout_milliseconds_convert_to_microseconds() {
        let config = test_config();

        assert_eq!(config.match_timeout_micros(), 1_200_000);
    }

    #[test]
    fn stdout_output_sentinel_is_detected() {
        assert!(output_path_targets_stdout(Path::new("-")));
        assert!(!output_path_targets_stdout(Path::new("dns_output.csv")));

        let mut config = test_config();
        config.output_filename = PathBuf::from("-");
        assert!(config.writes_output_to_stdout());
    }

    #[test]
    fn larger_hosts_use_staged_budget() {
        let budget = ExecutionBudget::from_available_cpus(16);

        assert_eq!(budget.model, ExecutionModel::Staged);
        assert_eq!(budget.rayon_threads, None);
        assert_eq!(budget.staged_reserved_service_threads, 2);
        assert_eq!(budget.staged_worker_budget, 14);
        assert!(budget.uses_staged_pipeline());
    }
}
