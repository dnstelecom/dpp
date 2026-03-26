/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::config::OutputFormat;
use crate::output::OutputMessage;
use std::error::Error as StdError;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum RuntimeError {
    #[error("failed to start memory monitor")]
    MemoryMonitorStart {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("failed to determine CPU affinity core IDs")]
    CoreIdsUnavailable,
    #[error("failed to build the global Rayon thread pool")]
    ThreadPoolBuild(#[from] rayon::ThreadPoolBuildError),
    #[error("cannot open input PCAP file '{path}'")]
    InputFileOpen {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to canonicalize input PCAP path '{path}'")]
    InputPathCanonicalize {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("logger initialization failed")]
    LoggerInit {
        #[source]
        source: io::Error,
    },
    #[error("failed to install the shutdown signal handler")]
    SignalHandler {
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Error)]
pub(crate) enum OutputError {
    #[error("failed to create the CSV output file '{path}'")]
    CreateCsvFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create the Parquet writer for '{path}'")]
    CreateParquetWriter {
        path: PathBuf,
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("failed to spawn the {format} writer thread")]
    SpawnWriterThread {
        format: OutputFormat,
        #[source]
        source: io::Error,
    },
    #[error("writer thread panicked: {0}")]
    WriterThreadPanic(String),
    #[error("writer thread failed")]
    WriterThreadFailure {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("failed to send output control message")]
    OutputControlSend {
        #[source]
        source: Box<crossbeam::channel::SendError<OutputMessage>>,
    },
}

#[derive(Debug, Error)]
pub(crate) enum AppRunError {
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error("failed to initialize the DNS processor")]
    DnsProcessorInit {
        #[source]
        source: io::Error,
    },
    #[error("failed to initialize the packet parser")]
    PacketParserInit {
        #[source]
        source: anyhow::Error,
    },
    #[error("DNS processing failed")]
    Processing {
        #[source]
        source: anyhow::Error,
    },
    #[error("memory monitor shutdown failed")]
    MemoryMonitorShutdown {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("output pipeline failed")]
    Output {
        #[source]
        source: Box<OutputError>,
    },
    #[error("failed to emit the JSON run summary")]
    JsonSummary {
        #[source]
        source: anyhow::Error,
    },
}

impl From<OutputError> for AppRunError {
    fn from(source: OutputError) -> Self {
        Self::Output {
            source: Box::new(source),
        }
    }
}
