/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::config::{AppConfig, OUTPUT_FLUSH_THRESHOLD, PARQUET_WRITE_BATCH_SIZE};
use crate::output::{OutputMessage, drain_output_messages};
use crate::record::DnsRecord;
use arrayvec::ArrayString;
use crossbeam::channel::Receiver;
use parquet::data_type::{ByteArray, ByteArrayType, DataType, Int32Type, Int64Type};
use parquet::file::properties::EnabledStatistics;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use parquet::schema::types::ColumnPath;
use parquet::schema::types::TypePtr;
use std::error::Error;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::IpAddr;
use std::sync::Arc;

/// Constructs the Parquet schema for DNS records.
pub fn build_dns_schema() -> Result<TypePtr, Box<dyn Error + Send + Sync>> {
    let message_type = "
    message schema {
        REQUIRED INT64 request_timestamp (TIMESTAMP(MICROS,true));
        REQUIRED INT64 response_timestamp (TIMESTAMP(MICROS,true));
        REQUIRED BYTE_ARRAY source_ip (UTF8);
        REQUIRED INT32 source_port;
        REQUIRED INT32 id;
        REQUIRED BYTE_ARRAY name (UTF8);
        REQUIRED BYTE_ARRAY query_type (UTF8);
        REQUIRED BYTE_ARRAY response_code (UTF8);
    }
    ";
    Ok(Arc::new(parse_message_type(message_type)?))
}

pub(crate) fn create_parquet_writer<W>(
    sink: W,
    config: &AppConfig,
) -> Result<SerializedFileWriter<W>, Box<dyn Error + Send + Sync>>
where
    W: Write + Send,
{
    let schema = build_dns_schema()?;

    let compression = if config.zstd {
        parquet::basic::Compression::ZSTD(parquet::basic::ZstdLevel::try_new(10)?)
    } else {
        parquet::basic::Compression::SNAPPY
    };

    let version = if config.v2 {
        parquet::file::properties::WriterVersion::PARQUET_2_0
    } else {
        parquet::file::properties::WriterVersion::PARQUET_1_0
    };

    let props = Arc::new(
        parquet::file::properties::WriterProperties::builder()
            .set_compression(compression)
            .set_write_batch_size(PARQUET_WRITE_BATCH_SIZE)
            .set_writer_version(version)
            .set_dictionary_enabled(false)
            .set_column_dictionary_enabled(ColumnPath::from("query_type"), true)
            .set_column_dictionary_enabled(ColumnPath::from("response_code"), true)
            .set_statistics_enabled(EnabledStatistics::Chunk)
            .set_statistics_truncate_length(None)
            .set_created_by("DPP community edition".parse()?)
            .build(),
    );

    Ok(SerializedFileWriter::new(sink, schema, props)?)
}

fn format_ip_address(ip: &IpAddr) -> ArrayString<45> {
    let mut formatted = ArrayString::<45>::new();
    write!(&mut formatted, "{ip}").expect("IpAddr display fits within 45 bytes");
    formatted
}

fn write_column<Type>(
    row_group_writer: &mut parquet::file::writer::SerializedRowGroupWriter<'_, impl Write + Send>,
    values: &[Type::T],
    missing_column_error: &'static str,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    Type: DataType,
{
    let mut column_writer = row_group_writer.next_column()?.ok_or_else(|| {
        Box::<dyn Error + Send + Sync>::from(io::Error::other(missing_column_error))
    })?;
    column_writer
        .typed::<Type>()
        .write_batch(values, None, None)?;
    column_writer.close()?;
    Ok(())
}

fn flush_buffer_async_parquet<W>(
    parquet_writer: &mut SerializedFileWriter<W>,
    buffer: &mut Vec<DnsRecord>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    W: Write + Send,
{
    let len = buffer.len();
    let mut request_timestamps = Vec::with_capacity(len);
    let mut response_timestamps = Vec::with_capacity(len);
    let mut source_ports = Vec::with_capacity(len);
    let mut ids = Vec::with_capacity(len);
    let mut source_ips = Vec::with_capacity(len);
    let mut names = Vec::with_capacity(len);
    let mut query_types = Vec::with_capacity(len);
    let mut response_codes = Vec::with_capacity(len);

    for record in buffer.iter() {
        request_timestamps.push(record.request_timestamp);
        response_timestamps.push(record.response_timestamp);
        source_ports.push(i32::from(record.source_port));
        ids.push(i32::from(record.id));

        let source_ip = format_ip_address(&record.source_ip);
        source_ips.push(ByteArray::from(source_ip.as_str()));
        names.push(ByteArray::from(record.name.as_str()));
        query_types.push(ByteArray::from(record.query_type.as_str()));
        response_codes.push(ByteArray::from(record.response_code.as_str()));
    }

    let mut row_group_writer = parquet_writer.next_row_group()?;
    write_column::<Int64Type>(
        &mut row_group_writer,
        &request_timestamps,
        "Missing Parquet INT64 column",
    )?;
    write_column::<Int64Type>(
        &mut row_group_writer,
        &response_timestamps,
        "Missing Parquet INT64 column",
    )?;
    write_column::<ByteArrayType>(
        &mut row_group_writer,
        &source_ips,
        "Missing Parquet BYTE_ARRAY column",
    )?;
    write_column::<Int32Type>(
        &mut row_group_writer,
        &source_ports,
        "Missing Parquet INT32 column",
    )?;
    write_column::<Int32Type>(&mut row_group_writer, &ids, "Missing Parquet INT32 column")?;
    write_column::<ByteArrayType>(
        &mut row_group_writer,
        &names,
        "Missing Parquet BYTE_ARRAY column",
    )?;
    write_column::<ByteArrayType>(
        &mut row_group_writer,
        &query_types,
        "Missing Parquet BYTE_ARRAY column",
    )?;
    write_column::<ByteArrayType>(
        &mut row_group_writer,
        &response_codes,
        "Missing Parquet BYTE_ARRAY column",
    )?;
    row_group_writer.close()?;

    buffer.clear();
    Ok(())
}

/// Parquet writer loop that owns its buffer and flushes on threshold or shutdown.
pub(crate) fn parquet_writer(
    mut parquet_writer: SerializedFileWriter<impl Write + Send>,
    rx: Receiver<OutputMessage>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut buffer = Vec::with_capacity(OUTPUT_FLUSH_THRESHOLD);

    drain_output_messages(rx, &mut buffer, |buffer| {
        flush_buffer_async_parquet(&mut parquet_writer, buffer)
    })?;

    parquet_writer.close()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutputFormat;
    use crate::test_support::{temp_test_path, test_dns_record};
    use crossbeam::channel;
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use std::fs;
    use std::fs::File;
    use std::io;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct SharedSink {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .expect("shared sink lock is healthy")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn parquet_writer_flushes_buffer_on_shutdown() {
        let filename = temp_test_path("parquet-writer-shutdown", "parquet");
        let config = AppConfig {
            filename: PathBuf::from("input.pcap"),
            output_filename: filename.clone(),
            format: OutputFormat::Parquet,
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
        };
        let file = File::create(&filename).expect("creates parquet file");
        let writer = create_parquet_writer(file, &config).expect("creates parquet writer");
        let (tx, rx) = channel::unbounded();

        tx.send(OutputMessage::Record(test_dns_record()))
            .expect("record is sent");
        tx.send(OutputMessage::Shutdown).expect("shutdown is sent");

        parquet_writer(writer, rx).expect("parquet writer completes successfully");

        let reader =
            SerializedFileReader::new(File::open(&filename).expect("opens parquet output"))
                .expect("parquet output is readable");
        assert_eq!(reader.metadata().num_row_groups(), 1);

        fs::remove_file(filename).expect("removes temp parquet file");
    }

    #[test]
    fn parquet_writer_flushes_buffer_when_channel_closes_without_explicit_shutdown() {
        let filename = temp_test_path("parquet-writer-channel-close", "parquet");
        let config = AppConfig {
            filename: PathBuf::from("input.pcap"),
            output_filename: filename.clone(),
            format: OutputFormat::Parquet,
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
        };
        let file = File::create(&filename).expect("creates parquet file");
        let writer = create_parquet_writer(file, &config).expect("creates parquet writer");
        let (tx, rx) = channel::unbounded();

        tx.send(OutputMessage::Record(test_dns_record()))
            .expect("record is sent");
        drop(tx);

        parquet_writer(writer, rx).expect("parquet writer completes successfully");

        let reader =
            SerializedFileReader::new(File::open(&filename).expect("opens parquet output"))
                .expect("parquet output is readable");
        assert_eq!(reader.metadata().file_metadata().num_rows(), 1);

        fs::remove_file(filename).expect("removes temp parquet file");
    }

    #[test]
    fn parquet_writer_supports_non_file_sinks() {
        let shared = Arc::new(Mutex::new(Vec::new()));
        let config = AppConfig {
            filename: PathBuf::from("input.pcap"),
            output_filename: PathBuf::from("-"),
            format: OutputFormat::Parquet,
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
        };
        let writer = create_parquet_writer(
            SharedSink {
                buffer: Arc::clone(&shared),
            },
            &config,
        )
        .expect("creates parquet writer");
        let (tx, rx) = channel::unbounded();

        tx.send(OutputMessage::Record(test_dns_record()))
            .expect("record is sent");
        tx.send(OutputMessage::Shutdown).expect("shutdown is sent");

        parquet_writer(writer, rx).expect("parquet writer completes successfully");

        let bytes = shared.lock().expect("shared sink lock is healthy");
        assert!(!bytes.is_empty());
        assert_eq!(&bytes[..4], b"PAR1");
    }

    #[test]
    fn parquet_writer_drops_buffered_rows_on_abort() {
        let filename = temp_test_path("parquet-writer-abort", "parquet");
        let config = AppConfig {
            filename: PathBuf::from("input.pcap"),
            output_filename: filename.clone(),
            format: OutputFormat::Parquet,
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
        };
        let file = File::create(&filename).expect("creates parquet file");
        let writer = create_parquet_writer(file, &config).expect("creates parquet writer");
        let (tx, rx) = channel::unbounded();

        tx.send(OutputMessage::Record(test_dns_record()))
            .expect("record is sent");
        tx.send(OutputMessage::Abort).expect("abort is sent");

        parquet_writer(writer, rx).expect("parquet writer completes successfully");

        let reader =
            SerializedFileReader::new(File::open(&filename).expect("opens parquet output"))
                .expect("parquet output is readable");
        assert_eq!(reader.metadata().num_row_groups(), 0);
        assert_eq!(reader.metadata().file_metadata().num_rows(), 0);

        fs::remove_file(filename).expect("removes temp parquet file");
    }
}
