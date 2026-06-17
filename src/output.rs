/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::config::{AppConfig, OUTPUT_FLUSH_THRESHOLD, OUTPUT_RECORD_BATCH_SIZE, OutputFormat};
use crate::error::OutputError;
use crate::error::error_chain_contains_broken_pipe;
use crate::{csv_writer, parquet_writer};
use crossbeam::channel::Receiver;
use std::error::Error;
use std::fs::File;
use std::io::{self, Write};
use std::mem;
#[cfg(test)]
use std::ops::Index;
use std::thread::{self, JoinHandle};

pub(crate) use crate::record::DnsRecord;

pub(crate) struct OutputRecordBatches {
    batches: Vec<Vec<DnsRecord>>,
    current: Vec<DnsRecord>,
    next_batch_capacity: usize,
}

impl Default for OutputRecordBatches {
    fn default() -> Self {
        Self {
            batches: Vec::new(),
            current: Vec::new(),
            next_batch_capacity: OUTPUT_RECORD_BATCH_SIZE,
        }
    }
}

impl OutputRecordBatches {
    pub(crate) fn with_capacity(record_capacity: usize) -> Self {
        let batch_capacity = record_capacity.min(OUTPUT_RECORD_BATCH_SIZE);
        let batch_count = record_capacity.div_ceil(OUTPUT_RECORD_BATCH_SIZE);

        Self {
            batches: Vec::with_capacity(batch_count.saturating_sub(1)),
            current: Vec::new(),
            next_batch_capacity: batch_capacity,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_records(records: Vec<DnsRecord>) -> Self {
        let mut output_records = Self::with_capacity(records.len());
        for record in records {
            output_records.push(record);
        }
        output_records
    }

    pub(crate) fn push(&mut self, record: DnsRecord) {
        if self.current.len() == OUTPUT_RECORD_BATCH_SIZE {
            self.flush_current_for_more();
        }

        self.ensure_current_capacity();
        self.current.push(record);
    }

    pub(crate) fn append(&mut self, other: Self) {
        if other.is_empty() {
            return;
        }

        let OutputRecordBatches {
            batches,
            current,
            next_batch_capacity: _,
        } = other;

        for batch in batches {
            self.push_batch(batch);
        }

        if !current.is_empty() {
            self.push_batch(current);
        }
    }

    pub(crate) fn into_batch_iter(self) -> OutputRecordBatchIter {
        let OutputRecordBatches {
            batches,
            current,
            next_batch_capacity: _,
        } = self;

        OutputRecordBatchIter {
            batches: batches.into_iter(),
            current: (!current.is_empty()).then_some(current),
        }
    }

    #[cfg(test)]
    pub(crate) fn into_batches(self) -> Vec<Vec<DnsRecord>> {
        self.into_batch_iter().collect()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.batches.is_empty() && self.current.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.batches.iter().map(Vec::len).sum::<usize>() + self.current.len()
    }

    fn ensure_current_capacity(&mut self) {
        if self.current.capacity() == 0 {
            self.current.reserve_exact(self.next_batch_capacity.max(1));
        }
    }

    fn flush_current_for_more(&mut self) {
        if self.current.is_empty() {
            return;
        }

        let batch = mem::replace(
            &mut self.current,
            Vec::with_capacity(OUTPUT_RECORD_BATCH_SIZE),
        );
        self.batches.push(batch);
        self.next_batch_capacity = OUTPUT_RECORD_BATCH_SIZE;
    }

    fn flush_current_final(&mut self) {
        if !self.current.is_empty() {
            self.batches.push(mem::take(&mut self.current));
        }
    }

    fn push_batch(&mut self, batch: Vec<DnsRecord>) {
        debug_assert!(!batch.is_empty());
        debug_assert!(batch.len() <= OUTPUT_RECORD_BATCH_SIZE);

        if batch.len() == OUTPUT_RECORD_BATCH_SIZE {
            if !self.current.is_empty() {
                self.flush_current_final();
            }
            self.batches.push(batch);
            return;
        }

        if self.current.len().saturating_add(batch.len()) > OUTPUT_RECORD_BATCH_SIZE {
            self.flush_current_final();
        }

        if self.current.is_empty() && batch.capacity() <= OUTPUT_RECORD_BATCH_SIZE {
            self.current = batch;
        } else {
            self.ensure_current_capacity();
            self.current.extend(batch);
        }
    }
}

pub(crate) struct OutputRecordBatchIter {
    batches: std::vec::IntoIter<Vec<DnsRecord>>,
    current: Option<Vec<DnsRecord>>,
}

impl Iterator for OutputRecordBatchIter {
    type Item = Vec<DnsRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        self.batches.next().or_else(|| self.current.take())
    }
}

#[cfg(test)]
impl Index<usize> for OutputRecordBatches {
    type Output = DnsRecord;

    fn index(&self, index: usize) -> &Self::Output {
        let mut remaining = index;

        for batch in &self.batches {
            if remaining < batch.len() {
                return &batch[remaining];
            }
            remaining -= batch.len();
        }

        &self.current[remaining]
    }
}

#[cfg(test)]
impl IntoIterator for OutputRecordBatches {
    type Item = DnsRecord;
    type IntoIter = std::vec::IntoIter<DnsRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_batches()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// Control messages accepted by output writers.
#[derive(Debug)]
pub(crate) enum OutputMessage {
    Records(Vec<DnsRecord>),
    Shutdown,
    Abort,
}

impl From<DnsRecord> for OutputMessage {
    fn from(record: DnsRecord) -> Self {
        OutputMessage::Records(vec![record])
    }
}

impl From<Vec<DnsRecord>> for OutputMessage {
    fn from(records: Vec<DnsRecord>) -> Self {
        OutputMessage::Records(records)
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
    drain_output_messages_with_threshold(rx, buffer, OUTPUT_FLUSH_THRESHOLD, &mut flush_buffer)
}

fn drain_output_messages_with_threshold<FlushFn>(
    rx: Receiver<OutputMessage>,
    buffer: &mut Vec<DnsRecord>,
    flush_threshold: usize,
    flush_buffer: &mut FlushFn,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    FlushFn: FnMut(&mut Vec<DnsRecord>) -> Result<(), Box<dyn Error + Send + Sync>>,
{
    while let Ok(message) = rx.recv() {
        match message {
            OutputMessage::Records(records) => {
                if buffer.len().saturating_add(records.len()) <= flush_threshold {
                    buffer.extend(records);
                    if buffer.len() >= flush_threshold {
                        flush_buffer(buffer)?;
                    }
                } else {
                    for record in records {
                        buffer.push(record);
                        if buffer.len() >= flush_threshold {
                            flush_buffer(buffer)?;
                        }
                    }
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
    use super::{
        OutputMessage, classify_writer_failure, drain_output_messages,
        drain_output_messages_with_threshold,
    };
    use crate::error::OutputError;
    use crate::test_support::test_dns_record;
    use crossbeam::channel;
    use std::error::Error;
    use std::io;

    #[test]
    fn drain_output_messages_appends_batched_records() {
        let (tx, rx) = channel::unbounded();
        let mut first = test_dns_record();
        first.id = 41;
        let mut second = test_dns_record();
        second.id = 42;

        tx.send(OutputMessage::Records(vec![first, second]))
            .expect("records are sent");
        tx.send(OutputMessage::Shutdown).expect("shutdown is sent");

        let mut buffer = Vec::new();
        let mut flushed = Vec::new();
        drain_output_messages(rx, &mut buffer, |buffer| {
            flushed.append(buffer);
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
        .expect("messages drain");

        assert_eq!(
            flushed.iter().map(|record| record.id).collect::<Vec<_>>(),
            vec![41, 42]
        );
    }

    #[test]
    fn drain_output_messages_flushes_large_batch_at_threshold() {
        let (tx, rx) = channel::unbounded();
        let records = (0..5)
            .map(|idx| {
                let mut record = test_dns_record();
                record.id = idx;
                record
            })
            .collect::<Vec<_>>();

        tx.send(OutputMessage::Records(records))
            .expect("records are sent");
        tx.send(OutputMessage::Shutdown).expect("shutdown is sent");

        let mut buffer = Vec::new();
        let mut flushed_ids = Vec::new();
        drain_output_messages_with_threshold(rx, &mut buffer, 2, &mut |buffer| {
            flushed_ids.push(buffer.iter().map(|record| record.id).collect::<Vec<_>>());
            buffer.clear();
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
        .expect("messages drain");

        assert_eq!(flushed_ids, vec![vec![0, 1], vec![2, 3], vec![4]]);
    }

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
