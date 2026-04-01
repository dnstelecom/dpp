/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::config::{AppConfig, OUTPUT_FLUSH_THRESHOLD, OutputFormat};
use crate::error::OutputError;
use crate::error::error_chain_contains_broken_pipe;
use crate::{csv_writer, parquet_writer};
use crossbeam::channel::Receiver;
use std::error::Error;
use std::fs::File;
use std::io::{self, Write};
use std::thread::{self, JoinHandle};

pub(crate) use crate::record::DnsRecord;

/// Control messages accepted by output writers.
#[derive(Debug)]
pub(crate) enum OutputMessage {
    Record(DnsRecord),
    Shutdown,
    Abort,
}

impl From<DnsRecord> for OutputMessage {
    fn from(record: DnsRecord) -> Self {
        OutputMessage::Record(record)
    }
}

pub(crate) fn drain_output_messages<FlushFn>(
    rx: Receiver<OutputMessage>,
    buffer: &mut Vec<DnsRecord>,
    mut flush_buffer: FlushFn,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    FlushFn: FnMut(&mut Vec<DnsRecord>) -> Result<(), Box<dyn Error + Send + Sync>>,
{
    while let Ok(message) = rx.recv() {
        match message {
            OutputMessage::Record(record) => {
                buffer.push(record);
                if buffer.len() >= OUTPUT_FLUSH_THRESHOLD {
                    flush_buffer(buffer)?;
                }
            }
            OutputMessage::Shutdown => break,
            OutputMessage::Abort => {
                buffer.clear();
                return Ok(());
            }
        }
    }

    if !buffer.is_empty() {
        flush_buffer(buffer)?;
    }

    Ok(())
}

pub(crate) fn create_writer_thread(
    config: &AppConfig,
    rx: crossbeam::channel::Receiver<OutputMessage>,
) -> Result<JoinHandle<Result<(), OutputError>>, OutputError> {
    match config.format {
        OutputFormat::Csv => {
            let sink = create_output_sink(config).map_err(|source| OutputError::CreateCsvFile {
                path: config.output_filename.clone(),
                source,
            })?;
            let writes_to_stdout = config.writes_output_to_stdout();

            Ok(thread::Builder::new()
                .name("DPP_CSV_Writer".to_string())
                .spawn(move || {
                    csv_writer::csv_writer(sink, rx)
                        .map_err(|source| classify_writer_failure(source, writes_to_stdout))
                })
                .map_err(|source| OutputError::SpawnWriterThread {
                    format: OutputFormat::Csv,
                    source,
                })?)
        }
        OutputFormat::Parquet => {
            let sink =
                create_output_sink(config).map_err(|source| OutputError::CreateParquetWriter {
                    path: config.output_filename.clone(),
                    source: Box::new(source),
                })?;
            let parquet_writer =
                parquet_writer::create_parquet_writer(sink, config).map_err(|source| {
                    OutputError::CreateParquetWriter {
                        path: config.output_filename.clone(),
                        source,
                    }
                })?;

            Ok(thread::Builder::new()
                .name("DPP_PQ_Writer".to_string())
                .spawn(move || {
                    parquet_writer::parquet_writer(parquet_writer, rx)
                        .map_err(|source| classify_writer_failure(source, false))
                })
                .map_err(|source| OutputError::SpawnWriterThread {
                    format: OutputFormat::Parquet,
                    source,
                })?)
        }
    }
}

fn create_output_sink(config: &AppConfig) -> io::Result<Box<dyn Write + Send>> {
    if config.writes_output_to_stdout() {
        Ok(Box::new(io::stdout()))
    } else {
        File::create(&config.output_filename).map(|file| Box::new(file) as _)
    }
}

fn classify_writer_failure(
    source: Box<dyn Error + Send + Sync>,
    writes_to_stdout: bool,
) -> OutputError {
    if writes_to_stdout && error_chain_contains_broken_pipe(source.as_ref()) {
        OutputError::DownstreamClosed
    } else {
        OutputError::WriterThreadFailure { source }
    }
}

#[cfg(test)]
mod tests {
    use super::classify_writer_failure;
    use crate::error::OutputError;
    use std::error::Error;
    use std::io;

    #[test]
    fn stdout_broken_pipe_is_classified_as_downstream_closed() {
        let source: Box<dyn Error + Send + Sync> =
            Box::new(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"));

        assert!(matches!(
            classify_writer_failure(source, true),
            OutputError::DownstreamClosed
        ));
    }

    #[test]
    fn non_stdout_broken_pipe_remains_a_writer_failure() {
        let source: Box<dyn Error + Send + Sync> =
            Box::new(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"));

        assert!(matches!(
            classify_writer_failure(source, false),
            OutputError::WriterThreadFailure { .. }
        ));
    }
}
