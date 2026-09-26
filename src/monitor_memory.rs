/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;
use sysinfo::{ProcessesToUpdate, System};
use tracing::info;

/// Starts tracking the maximum Resident Set Size (RSS) memory usage of the current process.
///
/// This function initializes a separate thread that periodically (every 100 milliseconds)
/// checks the current RSS memory usage of the running process. It maintains the highest
/// observed memory usage in an `AtomicUsize`, allowing other threads to access this
/// information concurrently.
///
/// # Returns
///
/// A tuple containing:
/// - An `Arc<AtomicUsize>` that holds the maximum memory usage in kibibytes (KiB).
/// - A `MemoryMonitorHandle` representing the spawned monitoring thread.
///
/// # Example
///
/// ```rust
/// let (max_memory, memory_thread) = start_tracking().expect("monitor starts");
/// // ... your application logic ...
/// // To retrieve the maximum memory usage:
/// let peak_memory = max_memory.load(AtomicOrdering::SeqCst);
/// println!("Peak memory usage: {} KiB", peak_memory);
/// // Stop and join the monitoring thread before exiting:
/// memory_thread.stop();
/// memory_thread.join().expect("Memory monitoring thread panicked");
/// ```
pub struct MemoryMonitorHandle {
    stop: Arc<StopSignal>,
    join_handle: Option<JoinHandle<()>>,
}

struct StopSignal {
    stopped: Mutex<bool>,
    wake: Condvar,
}

impl StopSignal {
    fn new() -> Self {
        Self {
            stopped: Mutex::new(false),
            wake: Condvar::new(),
        }
    }

    fn lock_stopped(&self) -> MutexGuard<'_, bool> {
        self.stopped.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn stop(&self) {
        *self.lock_stopped() = true;
        self.wake.notify_one();
    }

    fn is_stopped(&self) -> bool {
        *self.lock_stopped()
    }

    fn wait_for_next_sample(&self, interval: Duration) -> bool {
        let (stopped, _) = self
            .wake
            .wait_timeout_while(self.lock_stopped(), interval, |stopped| !*stopped)
            .unwrap_or_else(PoisonError::into_inner);
        *stopped
    }
}

impl MemoryMonitorHandle {
    pub fn stop(&self) {
        self.stop.stop();
    }

    pub fn join(mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(join_handle) = self.join_handle.take() {
            join_handle.join().map_err(|err| {
                Box::<dyn Error + Send + Sync>::from(std::io::Error::other(format!(
                    "Memory monitoring thread panicked: {:?}",
                    err
                )))
            })?;
        }

        Ok(())
    }
}

impl Drop for MemoryMonitorHandle {
    fn drop(&mut self) {
        self.stop();

        if let Some(join_handle) = self.join_handle.take()
            && let Err(err) = join_handle.join()
        {
            tracing::warn!("Memory monitoring thread panicked during drop: {:?}", err);
        }
    }
}

pub fn start_tracking()
-> Result<(Arc<AtomicUsize>, MemoryMonitorHandle), Box<dyn Error + Send + Sync>> {
    // Initialize an atomic variable to store the maximum memory usage observed.
    let max_memory_usage = Arc::new(AtomicUsize::new(0));

    // Clone the Arc to move into the monitoring thread.
    let memory_usage_clone = Arc::clone(&max_memory_usage);
    let stop = Arc::new(StopSignal::new());
    let stop_clone = Arc::clone(&stop);

    // Spawn a new thread dedicated to monitoring memory usage.
    let memory_thread = std::thread::Builder::new()
        .name("DPP_Memory_Monitor".to_string())
        .spawn(move || {
            // Initialize the System struct for process monitoring.
            let mut sys = System::new();

            // Retrieve the current process ID (PID).
            let pid = match sysinfo::get_current_pid() {
                Ok(pid) => pid,
                Err(err) => {
                    tracing::error!("Failed to get current PID for memory monitoring: {}", err);
                    return;
                }
            };

            // Log the PID for debugging purposes.
            info!("PID: {}", pid);

            // Create a list containing only the current PID to limit monitoring scope.
            let pid_list = vec![pid];

            while !stop_clone.is_stopped() {
                // Specify that only the processes in `pid_list` should be refreshed.
                let processes_to_update = ProcessesToUpdate::Some(&pid_list);

                // Refresh the process information for the specified PIDs.
                sys.refresh_processes(processes_to_update, true);

                // Attempt to retrieve information about the current process.
                if let Some(process) = sys.process(pid) {
                    // Convert RSS from bytes to kibibytes (KiB) for reporting.
                    let current_rss_kib = (process.memory() / 1024) as usize;

                    // Atomically keep the highest observed RSS even if update patterns change later.
                    memory_usage_clone.fetch_max(current_rss_kib, AtomicOrdering::SeqCst);
                }

                // Wait between samples, but wake immediately when shutdown is requested.
                if stop_clone.wait_for_next_sample(Duration::from_millis(100)) {
                    break;
                }
            }
        })?;

    // Return the Arc pointing to the maximum memory usage and the thread handle.
    Ok((
        max_memory_usage,
        MemoryMonitorHandle {
            stop,
            join_handle: Some(memory_thread),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    #[test]
    fn memory_monitor_can_stop_and_join() {
        let (_usage, monitor) = start_tracking().expect("monitor starts");
        monitor.stop();
        monitor.join().expect("monitor joins");
    }

    #[test]
    fn stop_wakes_waiter_before_sampling_timeout() {
        let stop = Arc::new(StopSignal::new());
        let waiter_stop = Arc::clone(&stop);
        let (ready_tx, ready_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            ready_tx.send(()).expect("waiter is ready");
            waiter_stop.wait_for_next_sample(Duration::from_secs(5))
        });

        ready_rx.recv().expect("waiter starts");
        let started = Instant::now();
        stop.stop();
        assert!(waiter.join().expect("waiter joins"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
