/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::allocator;
use crate::config::{AppConfig, InputSource, ReportFormat, WORKER_STACK_SIZE_MB};
use crate::error::RuntimeError;
use crate::monitor_memory;
use crate::pipeio::BrokenPipeTolerantMakeWriter;
use core_affinity::CoreId;
use num_format::{Locale, ToFormattedString};
use rayon::ThreadPoolBuilder;
use std::fs::File;
use std::io;
use std::io::IsTerminal;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::time::Duration;
use sysinfo::System;
use tracing::Level;
use tracing::{debug, error, info, warn};
use tracing_log::LogTracer;
use tracing_subscriber::FmtSubscriber;
use tracing_subscriber::fmt::time::ChronoLocal;

fn rayon_thread_name(index: usize) -> String {
    format!("DPP_Rayon_{index}")
}

type PinCurrentThread = dyn Fn(CoreId) -> bool + Send + Sync;

#[derive(Clone)]
pub(crate) struct AffinityPlan {
    core_ids: Option<Arc<[CoreId]>>,
    pin_current_thread: Arc<PinCurrentThread>,
}

impl AffinityPlan {
    pub(crate) fn resolve(enabled: bool) -> Result<Self, RuntimeError> {
        #[cfg(target_os = "macos")]
        if enabled {
            // macOS does not expose supported per-core thread pinning through
            // the core_affinity backend, so avoid one failed syscall per worker.
            return Ok(Self {
                core_ids: None,
                pin_current_thread: Arc::new(|_| true),
            });
        }

        Self::resolve_with(
            enabled,
            core_affinity::get_core_ids,
            core_affinity::set_for_current,
        )
    }

    fn resolve_with<GetCoreIds, PinCurrent>(
        enabled: bool,
        get_core_ids: GetCoreIds,
        pin_current_thread: PinCurrent,
    ) -> Result<Self, RuntimeError>
    where
        GetCoreIds: FnOnce() -> Option<Vec<CoreId>>,
        PinCurrent: Fn(CoreId) -> bool + Send + Sync + 'static,
    {
        let core_ids = if enabled {
            let core_ids = get_core_ids()
                .filter(|core_ids| !core_ids.is_empty())
                .ok_or(RuntimeError::CoreIdsUnavailable)?;
            Some(Arc::<[CoreId]>::from(core_ids))
        } else {
            None
        };

        Ok(Self {
            core_ids,
            pin_current_thread: Arc::new(pin_current_thread),
        })
    }

    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self::resolve(false).expect("disabled affinity does not query the operating system")
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.core_ids.is_some()
    }

    fn core_id_for_slot(&self, slot: usize) -> Option<CoreId> {
        self.core_ids
            .as_ref()
            .map(|core_ids| core_ids[slot % core_ids.len()])
    }

    pub(crate) fn apply_to_current_thread(&self, slot: usize, role: &str) -> bool {
        let Some(core_id) = self.core_id_for_slot(slot) else {
            return true;
        };

        if (self.pin_current_thread)(core_id) {
            debug!(
                "Applied CPU affinity to {role} using OS affinity ID {}",
                core_id.id
            );
            true
        } else {
            warn!(
                "Unable to apply CPU affinity to {role} using OS affinity ID {}",
                core_id.id
            );
            false
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test<PinCurrent>(
        core_ids: Vec<usize>,
        pin_current_thread: PinCurrent,
    ) -> Result<Self, RuntimeError>
    where
        PinCurrent: Fn(usize) -> bool + Send + Sync + 'static,
    {
        Self::resolve_with(
            true,
            || Some(core_ids.into_iter().map(|id| CoreId { id }).collect()),
            move |core_id| pin_current_thread(core_id.id),
        )
    }
}

fn pipe_tolerant_stderr() -> BrokenPipeTolerantMakeWriter<fn() -> io::Stderr> {
    BrokenPipeTolerantMakeWriter::new(io::stderr)
}

pub(crate) fn maybe_start_memory_monitoring(
    silent: bool,
) -> Result<
    (
        Option<Arc<AtomicUsize>>,
        Option<monitor_memory::MemoryMonitorHandle>,
    ),
    RuntimeError,
> {
    if silent {
        Ok((None, None))
    } else {
        let (usage, handle) = monitor_memory::start_tracking()
            .map_err(|source| RuntimeError::MemoryMonitorStart { source })?;
        Ok((Some(usage), Some(handle)))
    }
}

pub(crate) fn create_thread_pool(
    num_threads: usize,
    affinity_plan: AffinityPlan,
) -> Result<(), RuntimeError> {
    let mut builder = ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .thread_name(rayon_thread_name)
        .stack_size(WORKER_STACK_SIZE_MB * 1024 * 1024);

    if affinity_plan.is_enabled() {
        builder = builder.start_handler(move |index| {
            affinity_plan.apply_to_current_thread(index, "Rayon worker");
        });
    }

    builder.build_global()?;
    Ok(())
}

pub(crate) fn log_accessible_input_file(args: &AppConfig) -> Result<(), RuntimeError> {
    match &args.input_source {
        InputSource::Stdin => info!("Starting to process PCAP stream from stdin"),
        InputSource::File(path) => {
            File::open(path).map_err(|error| {
                error!(
                    "Error: Unable to open the specified pcap file '{}'. {}",
                    path.display(),
                    error
                );
                RuntimeError::InputFileOpen {
                    path: path.clone(),
                    source: io::Error::other(format!(
                        "Unable to open the specified pcap file '{}': {}",
                        path.display(),
                        error
                    )),
                }
            })?;

            let canonical_path = std::fs::canonicalize(path).map_err(|source| {
                RuntimeError::InputPathCanonicalize {
                    path: path.clone(),
                    source,
                }
            })?;
            info!(
                "Starting to process PCAP file: {}",
                canonical_path.display()
            );
        }
    }

    Ok(())
}

pub(crate) fn log_system_info(
    args: &AppConfig,
    affinity_effective: bool,
) -> Result<(), RuntimeError> {
    if args.silent {
        return Ok(());
    }

    let mut system = System::new_all();
    system.refresh_all();
    let available_memory_mb = system.available_memory() as usize / (1024 * 1024);
    let available_memory_mb_formatted = available_memory_mb.to_formatted_string(&Locale::en);

    let formatted_os = format_os_name(std::env::consts::OS);

    info!("OS: {}, ARCH: {}", formatted_os, std::env::consts::ARCH);
    info!(
        "Available parallelism: {}, execution budget: auto (all available CPUs), affinity requested: {}, effective: {}",
        args.num_cpus, args.affinity, affinity_effective,
    );
    info!(
        "Available memory (system reported): {} MB",
        available_memory_mb_formatted
    );

    #[cfg(target_os = "macos")]
    if args.affinity && !affinity_effective {
        warn!("CPU affinity is not supported on macOS; continuing without affinity");
    }

    Ok(())
}

pub(crate) fn log_build_messages() -> Result<(), RuntimeError> {
    let common_name = "DNS Packet Parser (DPP) community edition";

    if let Some(git_hash) = option_env!("VERGEN_GIT_SHA") {
        if let Some(git_author) = option_env!("VERGEN_GIT_COMMIT_AUTHOR_EMAIL") {
            info!("{}, version hash: {}", common_name, git_hash);
            info!("Git Commit Author: {}", git_author);
        } else {
            info!(
                "{}, version hash: {}, author: unknown",
                common_name, git_hash
            );
        }
    } else {
        info!("{}, version hash: unknown", common_name);
    }

    if let Some(git_timestamp) = option_env!("VERGEN_GIT_COMMIT_TIMESTAMP") {
        info!("Git Timestamp: {git_timestamp}");
    }

    if let Some(timestamp) = option_env!("VERGEN_BUILD_TIMESTAMP") {
        info!("Build Timestamp: {timestamp}");
    }

    if let Some(hostname) = option_env!("BUILD_HOSTNAME") {
        info!("Build Hostname: {hostname}");
    }

    info!("Allocator: {}", allocator::ALLOCATOR_NAME);

    info!("> This software is licensed under GNU GPLv3.");
    info!("> Commercial licensing options: carrier-support@dnstele.com");
    info!("> Nameto Oy (c) 2026. All rights reserved.");

    Ok(())
}

static LOGGER: std::sync::OnceLock<()> = std::sync::OnceLock::new();
static SHUTDOWN_SIGNAL: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();
static SHUTDOWN_SIGNAL_INSTALL_LOCK: Mutex<()> = Mutex::new(());
pub(crate) fn configure_logger(
    silent: bool,
    report_format: ReportFormat,
) -> Result<(), RuntimeError> {
    if LOGGER.get().is_some() {
        return Ok(());
    }

    let level = if silent || matches!(report_format, ReportFormat::Json) {
        Level::ERROR
    } else {
        Level::INFO
    };

    LogTracer::init().map_err(|error| RuntimeError::LoggerInit {
        source: io::Error::other(format!("initializing logger failed: {error}")),
    })?;

    let timer =
        ChronoLocal::new(
            "%H:%M:%S%.3f"
                .parse()
                .map_err(|error| RuntimeError::LoggerInit {
                    source: io::Error::other(format!("invalid log timer format: {error}")),
                })?,
        );

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_timer(timer)
        .with_thread_names(false)
        .with_target(false)
        .with_thread_ids(false)
        .with_writer(pipe_tolerant_stderr())
        .finish();

    tracing::subscriber::set_global_default(subscriber).map_err(|error| {
        RuntimeError::LoggerInit {
            source: io::Error::other(format!("setting default subscriber failed: {error}")),
        }
    })?;

    LOGGER.set(()).map_err(|_| RuntimeError::LoggerInit {
        source: io::Error::other("logger already initialized"),
    })?;

    Ok(())
}

pub(crate) fn install_shutdown_signal_handler() -> Result<Arc<AtomicBool>, RuntimeError> {
    if let Some(flag) = SHUTDOWN_SIGNAL.get() {
        // SAFETY: Caller must ensure no concurrent run() is still draining before resetting
        // the shared shutdown flag for a new invocation.
        flag.store(false, AtomicOrdering::SeqCst);
        return Ok(Arc::clone(flag));
    }

    let _install_guard =
        SHUTDOWN_SIGNAL_INSTALL_LOCK
            .lock()
            .map_err(|_| RuntimeError::SignalHandler {
                source: io::Error::other("signal handler installation lock poisoned"),
            })?;

    if let Some(flag) = SHUTDOWN_SIGNAL.get() {
        flag.store(false, AtomicOrdering::SeqCst);
        return Ok(Arc::clone(flag));
    }

    let flag = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&flag);
    ctrlc::set_handler(move || {
        handler_flag.store(true, AtomicOrdering::SeqCst);
    })
    .map_err(|error| RuntimeError::SignalHandler {
        source: io::Error::other(format!("installing signal handler failed: {error}")),
    })?;

    let _ = SHUTDOWN_SIGNAL.set(Arc::clone(&flag));
    Ok(flag)
}

/// Formats a duration into a `HH:MM:SS.mmm` string.
pub(crate) fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;
    let milliseconds = duration.subsec_millis();

    format!("{hours:02}:{minutes:02}:{seconds:02}.{milliseconds:03}")
}

pub(crate) fn emphasize_warning(message: impl AsRef<str>) -> String {
    let message = message.as_ref();
    if io::stderr().is_terminal() {
        format!("\x1b[31m{message}\x1b[0m")
    } else {
        message.to_string()
    }
}

fn format_os_name(os: &str) -> String {
    if os.eq_ignore_ascii_case("macos") {
        return "MacOS".to_string();
    }

    let mut chars = os.chars();
    match chars.next() {
        Some(first) => {
            let mut formatted = first.to_uppercase().collect::<String>();
            formatted.push_str(chars.as_str());
            formatted
        }
        None => "Unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AffinityPlan, CoreId, RuntimeError, format_duration, format_os_name, rayon_thread_name,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[test]
    fn disabled_affinity_plan_does_not_query_or_pin_cores() {
        let getter_called = Arc::new(AtomicBool::new(false));
        let setter_called = Arc::new(AtomicBool::new(false));
        let plan = AffinityPlan::resolve_with(
            false,
            {
                let getter_called = Arc::clone(&getter_called);
                move || {
                    getter_called.store(true, Ordering::Relaxed);
                    Some(vec![CoreId { id: 2 }])
                }
            },
            {
                let setter_called = Arc::clone(&setter_called);
                move |_| {
                    setter_called.store(true, Ordering::Relaxed);
                    true
                }
            },
        )
        .expect("disabled plan resolves");

        assert!(plan.apply_to_current_thread(0, "test worker"));
        assert!(!getter_called.load(Ordering::Relaxed));
        assert!(!setter_called.load(Ordering::Relaxed));
    }

    #[test]
    fn affinity_plan_rejects_missing_or_empty_core_ids() {
        for core_ids in [None, Some(Vec::new())] {
            let result = AffinityPlan::resolve_with(true, move || core_ids, |_| true);
            assert!(matches!(result, Err(RuntimeError::CoreIdsUnavailable)));
        }
    }

    #[test]
    fn affinity_plan_preserves_sparse_ids_and_wraps_slots() {
        let applied_core = Arc::new(std::sync::Mutex::new(None));
        let plan = AffinityPlan::resolve_with(
            true,
            || Some(vec![CoreId { id: 2 }, CoreId { id: 5 }, CoreId { id: 9 }]),
            {
                let applied_core = Arc::clone(&applied_core);
                move |core_id| {
                    *applied_core.lock().expect("applied core lock") = Some(core_id.id);
                    false
                }
            },
        )
        .expect("affinity plan resolves");

        assert_eq!(plan.core_id_for_slot(0).map(|core_id| core_id.id), Some(2));
        assert_eq!(plan.core_id_for_slot(1).map(|core_id| core_id.id), Some(5));
        assert_eq!(plan.core_id_for_slot(3).map(|core_id| core_id.id), Some(2));
        assert!(!plan.apply_to_current_thread(4, "test worker"));
        assert_eq!(*applied_core.lock().expect("applied core lock"), Some(5));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_affinity_request_is_disabled_before_worker_startup() {
        let plan = AffinityPlan::resolve(true).expect("macOS affinity fallback resolves");

        assert!(!plan.is_enabled());
        assert!(plan.apply_to_current_thread(0, "test worker"));
    }

    #[test]
    fn format_duration_supports_more_than_twenty_four_hours() {
        let duration = Duration::from_secs(27 * 3_600 + 4 * 60 + 5) + Duration::from_millis(678);

        assert_eq!(format_duration(duration), "27:04:05.678");
    }

    #[test]
    fn format_os_name_handles_empty_strings() {
        assert_eq!(format_os_name(""), "Unknown");
        assert_eq!(format_os_name("linux"), "Linux");
        assert_eq!(format_os_name("macos"), "MacOS");
    }

    #[test]
    fn rayon_thread_names_follow_dpp_prefix() {
        assert_eq!(rayon_thread_name(0), "DPP_Rayon_0");
        assert_eq!(rayon_thread_name(7), "DPP_Rayon_7");
    }
}
