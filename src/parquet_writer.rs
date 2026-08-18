/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::config::{AppConfig, OUTPUT_FLUSH_THRESHOLD, PARQUET_WRITE_BATCH_SIZE};
use crate::output::{OutputMessage, drain_output_messages};
use crate::record::DnsRecord;
use bytes::Bytes;
use crossbeam::channel::Receiver;
use parquet::data_type::{ByteArray, ByteArrayType, DataType, Int32Type, Int64Type};
use parquet::file::properties::EnabledStatistics;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use parquet::schema::types::ColumnPath;
use parquet::schema::types::TypePtr;
use std::error::Error;
use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::net::IpAddr;
use std::sync::Arc;

/// Constructs the Parquet schema for DNS records.
pub fn build_dns_schema() -> Result<TypePtr, Box<dyn Error + Send + Sync>> {
    let message_type = "
    message schema {
        REQUIRED INT64 request_timestamp (TIMESTAMP(MICROS,true));
        OPTIONAL INT64 response_timestamp (TIMESTAMP(MICROS,true));
        REQUIRED BYTE_ARRAY source_ip (UTF8);
        REQUIRED INT32 source_port;
        REQUIRED INT32 id;
        REQUIRED BYTE_ARRAY name (UTF8);
        REQUIRED BYTE_ARRAY query_type (UTF8);
        OPTIONAL BYTE_ARRAY response_code (UTF8);
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

struct PackedByteArrayBuilder {
    data: Vec<u8>,
    lengths: Vec<u16>,
}

impl PackedByteArrayBuilder {
    fn with_capacity(value_count: usize, byte_capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(byte_capacity),
            lengths: Vec::with_capacity(value_count),
        }
    }

    fn push_bytes(&mut self, value: &[u8]) {
        self.data.extend_from_slice(value);
        self.push_last_length(value.len());
    }

    fn push_display(&mut self, value: impl fmt::Display) {
        let start = self.data.len();
        write!(self, "{value}").expect("writing to a byte buffer cannot fail");
        self.push_last_length(self.data.len() - start);
    }

    fn push_last_length(&mut self, length: usize) {
        self.lengths
            .push(u16::try_from(length).expect("packed Parquet text values fit within u16 length"));
    }

    fn finish(self) -> Vec<ByteArray> {
        let data = Bytes::from(self.data);
        let mut offset = 0;
        let values = self
            .lengths
            .into_iter()
            .map(|length| {
                let length = usize::from(length);
                let value = ByteArray::from(data.slice(offset..offset + length));
                offset += length;
                value
            })
            .collect();
        debug_assert_eq!(offset, data.len());
        values
    }
}

impl fmt::Write for PackedByteArrayBuilder {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.data.extend_from_slice(value.as_bytes());
        Ok(())
    }
}

fn max_formatted_ip_length(ip: &IpAddr) -> usize {
    match ip {
        IpAddr::V4(_) => 15,
        IpAddr::V6(_) => 39,
    }
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

fn write_optional_column<Type>(
    row_group_writer: &mut parquet::file::writer::SerializedRowGroupWriter<'_, impl Write + Send>,
    values: &[Type::T],
    definition_levels: &[i16],
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
        .write_batch(values, Some(definition_levels), None)?;
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
    let mut response_timestamp_definition_levels = Vec::with_capacity(len);
    let mut source_ports = Vec::with_capacity(len);
    let mut ids = Vec::with_capacity(len);
    let mut query_types = Vec::with_capacity(len);
    let mut response_codes = Vec::with_capacity(len);
    let mut response_code_definition_levels = Vec::with_capacity(len);
    let (source_ip_byte_capacity, name_byte_capacity) =
        buffer
            .iter()
            .fold((0, 0), |(ip_bytes, name_bytes), record| {
                (
                    ip_bytes + max_formatted_ip_length(&record.source_ip),
                    name_bytes + record.name.as_bytes().len(),
                )
            });
    let mut source_ip_builder = PackedByteArrayBuilder::with_capacity(len, source_ip_byte_capacity);
    let mut name_builder = PackedByteArrayBuilder::with_capacity(len, name_byte_capacity);

    for record in buffer.iter() {
        request_timestamps.push(record.request_timestamp);
        if let Some(response_timestamp) = record.response_timestamp {
            response_timestamps.push(response_timestamp);
            response_timestamp_definition_levels.push(1);
        } else {
            response_timestamp_definition_levels.push(0);
        }
        source_ports.push(i32::from(record.source_port));
        ids.push(i32::from(record.id));

        source_ip_builder.push_display(record.source_ip);
        name_builder.push_bytes(record.name.as_bytes());
        query_types.push(ByteArray::from(Bytes::from_static(
            record.query_type.as_str().as_bytes(),
        )));
        if let Some(response_code) = &record.response_code {
            response_codes.push(ByteArray::from(Bytes::from_static(
                response_code.as_str().as_bytes(),
            )));
            response_code_definition_levels.push(1);
        } else {
            response_code_definition_levels.push(0);
        }
    }

    // The ByteArray values share row-group-owned backing storage. Parquet consumes them
    // synchronously before these vectors are dropped.
    let source_ips = source_ip_builder.finish();
    let names = name_builder.finish();

    let mut row_group_writer = parquet_writer.next_row_group()?;
    write_column::<Int64Type>(
        &mut row_group_writer,
        &request_timestamps,
        "Missing Parquet INT64 column",
    )?;
    write_optional_column::<Int64Type>(
        &mut row_group_writer,
        &response_timestamps,
        &response_timestamp_definition_levels,
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
    write_optional_column::<ByteArrayType>(
        &mut row_group_writer,
        &response_codes,
        &response_code_definition_levels,
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
    use crate::config::{InputSource, OutputFormat};
    use crate::custom_types::DnsNameBuf;
    use crate::test_support::{temp_test_path, test_dns_record};
    use crossbeam::channel;
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use parquet::record::Field;
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
            input_source: InputSource::File(PathBuf::from("input.pcap")),
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

        tx.send(OutputMessage::Records(vec![test_dns_record()]))
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
            input_source: InputSource::File(PathBuf::from("input.pcap")),
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

        tx.send(OutputMessage::Records(vec![test_dns_record()]))
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
            input_source: InputSource::File(PathBuf::from("input.pcap")),
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

        tx.send(OutputMessage::Records(vec![test_dns_record()]))
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
            input_source: InputSource::File(PathBuf::from("input.pcap")),
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

        tx.send(OutputMessage::Records(vec![test_dns_record()]))
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

    #[test]
    fn parquet_writer_preserves_null_response_fields_for_timeout_records() {
        let filename = temp_test_path("parquet-writer-timeout", "parquet");
        let config = AppConfig {
            input_source: InputSource::File(PathBuf::from("input.pcap")),
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
        let mut record = test_dns_record();
        record.response_timestamp = None;
        record.response_code = None;

        tx.send(OutputMessage::Records(vec![record]))
            .expect("record is sent");
        tx.send(OutputMessage::Shutdown).expect("shutdown is sent");

        parquet_writer(writer, rx).expect("parquet writer completes successfully");

        let reader =
            SerializedFileReader::new(File::open(&filename).expect("opens parquet output"))
                .expect("parquet output is readable");
        let schema = reader.metadata().file_metadata().schema_descr();
        assert_eq!(schema.column(1).max_def_level(), 1);
        assert_eq!(schema.column(7).max_def_level(), 1);

        let row = reader
            .get_row_iter(None)
            .expect("parquet rows are readable")
            .next()
            .expect("one row exists")
            .expect("row decodes");
        assert!(matches!(
            row.get_column_iter().nth(1),
            Some((_, Field::Null))
        ));
        assert!(matches!(
            row.get_column_iter().nth(7),
            Some((_, Field::Null))
        ));

        fs::remove_file(filename).expect("removes temp parquet file");
    }

    #[test]
    fn packed_text_columns_preserve_values_across_row_groups() {
        fn max_escaped_name(octet: u8) -> String {
            [63, 63, 63, 61]
                .map(|label_len| format!("\\{octet:03}").repeat(label_len))
                .join(".")
        }

        let filename = temp_test_path("parquet-writer-packed-text", "parquet");
        let config = AppConfig {
            input_source: InputSource::File(PathBuf::from("input.pcap")),
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
        let mut writer = create_parquet_writer(file, &config).expect("creates parquet writer");

        let mut empty_name = test_dns_record();
        empty_name.source_ip = "192.0.2.1".parse().expect("IPv4 address parses");
        empty_name.name = DnsNameBuf::new("").expect("empty presentation name fits");
        empty_name.response_timestamp = None;
        empty_name.response_code = None;

        let escaped_zero = max_escaped_name(0);
        let mut long_ipv6 = test_dns_record();
        long_ipv6.source_ip = "2001:db8::1".parse().expect("IPv6 address parses");
        long_ipv6.name = DnsNameBuf::new(&escaped_zero).expect("maximum presentation name fits");

        let mut buffer = vec![empty_name, long_ipv6];
        flush_buffer_async_parquet(&mut writer, &mut buffer).expect("first row group is written");
        assert!(buffer.is_empty());

        let escaped_one = max_escaped_name(1);
        let mut second_group = test_dns_record();
        second_group.source_ip = "2001:db8:ffff::ffff".parse().expect("IPv6 address parses");
        second_group.name = DnsNameBuf::new(&escaped_one).expect("maximum presentation name fits");
        buffer.push(second_group);
        flush_buffer_async_parquet(&mut writer, &mut buffer).expect("second row group is written");
        writer.close().expect("parquet writer closes");

        let reader = SerializedFileReader::new(File::open(&filename).expect("opens output"))
            .expect("parquet output is readable");
        assert_eq!(reader.metadata().num_row_groups(), 2);
        let rows = reader
            .get_row_iter(None)
            .expect("parquet rows are readable")
            .collect::<Result<Vec<_>, _>>()
            .expect("parquet rows decode");
        assert_eq!(rows.len(), 3);

        for (row, expected_ip, expected_name) in [
            (&rows[0], "192.0.2.1", ""),
            (&rows[1], "2001:db8::1", escaped_zero.as_str()),
            (&rows[2], "2001:db8:ffff::ffff", escaped_one.as_str()),
        ] {
            assert!(matches!(
                row.get_column_iter().nth(2),
                Some((_, Field::Str(value))) if value == expected_ip
            ));
            assert!(matches!(
                row.get_column_iter().nth(5),
                Some((_, Field::Str(value))) if value == expected_name
            ));
        }

        fs::remove_file(filename).expect("removes temp parquet file");
    }
}
