/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::config::OUTPUT_FLUSH_THRESHOLD;
use crate::output::{OutputMessage, drain_output_messages};
use crate::record::DnsRecord;
use crossbeam::channel::Receiver;
use memchr::{memchr, memchr3_iter};
use std::error::Error;
use std::fmt::Write as FmtWrite;
use std::io::{BufWriter, Write};

const CSV_HEADER: &[u8] =
    b"request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n";
const CSV_WRITER_BUFFER_CAPACITY: usize = 1 << 20;
const CSV_ROW_BUFFER_CAPACITY: usize = 384;

/// Asynchronously flushes buffered DNS records to a CSV file.
///
/// This function processes all DNS records stored in the buffer, encodes them into CSV rows, and
/// writes them to the provided buffered file writer. After writing, the writer is flushed to ensure
/// all buffered bytes are visible to the downstream reader.
///
/// # Arguments
///
/// * `writer` - A mutable reference to the buffered CSV output file.
/// * `buffer` - A mutable reference to a `Vec<DnsRecord>` containing the DNS records to be written.
///
/// # Errors
///
/// Returns an error if writing or flushing the CSV file fails.
fn append_csv_number<T: itoa::Integer>(buffer: &mut Vec<u8>, value: T) {
    let mut formatter = itoa::Buffer::new();
    buffer.extend_from_slice(formatter.format(value).as_bytes());
}

fn append_ip_addr(buffer: &mut Vec<u8>, value: std::net::IpAddr) {
    let mut ip_buffer = arrayvec::ArrayString::<45>::new();
    write!(&mut ip_buffer, "{value}").expect("ip address fits into stack buffer");
    buffer.extend_from_slice(ip_buffer.as_bytes());
}

fn append_csv_field(buffer: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    if memchr3_iter(b',', b'"', b'\n', bytes).next().is_none() && memchr(b'\r', bytes).is_none() {
        buffer.extend_from_slice(value.as_bytes());
        return;
    }

    buffer.push(b'"');
    let mut start = 0;
    for quote_index in memchr3_iter(b'"', b'\n', b'\r', bytes) {
        buffer.extend_from_slice(&bytes[start..quote_index]);
        if bytes[quote_index] == b'"' {
            buffer.extend_from_slice(br#""""#);
        } else {
            buffer.push(bytes[quote_index]);
        }
        start = quote_index + 1;
    }
    buffer.extend_from_slice(&bytes[start..]);
    buffer.push(b'"');
}

fn encode_csv_record(row_buffer: &mut Vec<u8>, record: &DnsRecord) {
    row_buffer.clear();
    append_csv_number(row_buffer, record.request_timestamp);
    row_buffer.push(b',');
    append_csv_number(row_buffer, record.response_timestamp);
    row_buffer.push(b',');
    append_ip_addr(row_buffer, record.source_ip);
    row_buffer.push(b',');
    append_csv_number(row_buffer, record.source_port);
    row_buffer.push(b',');
    append_csv_number(row_buffer, record.id);
    row_buffer.push(b',');
    append_csv_field(row_buffer, record.name.as_str());
    row_buffer.push(b',');
    row_buffer.extend_from_slice(record.query_type.as_str().as_bytes());
    row_buffer.push(b',');
    row_buffer.extend_from_slice(record.response_code.as_str().as_bytes());
    row_buffer.push(b'\n');
}

fn flush_buffer_async_csv(
    writer: &mut BufWriter<impl Write>,
    buffer: &mut Vec<DnsRecord>,
    row_buffer: &mut Vec<u8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for record in buffer.drain(..) {
        encode_csv_record(row_buffer, &record);
        writer.write_all(row_buffer)?;
    }

    writer.flush()?;
    Ok(())
}

/// CSV writer loop that owns its buffer and flushes on threshold or shutdown.
///
/// # Arguments
///
/// * `file` - The output file used to persist encoded CSV rows.
/// * `rx` - A `Receiver<OutputMessage>` carrying records and shutdown control.
///
/// # Example
///
/// ```no_run
/// let file = std::fs::File::create("output.csv").unwrap();
/// csv_writer(file, rx).expect("csv writer completes successfully");
/// ```
pub(crate) fn csv_writer<W>(
    sink: W,
    rx: Receiver<OutputMessage>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    W: Write,
{
    let mut csv_writer = BufWriter::with_capacity(CSV_WRITER_BUFFER_CAPACITY, sink);
    let mut buffer = Vec::with_capacity(OUTPUT_FLUSH_THRESHOLD);
    let mut row_buffer = Vec::with_capacity(CSV_ROW_BUFFER_CAPACITY);

    csv_writer.write_all(CSV_HEADER)?;

    drain_output_messages(rx, &mut buffer, |buffer| {
        flush_buffer_async_csv(&mut csv_writer, buffer, &mut row_buffer)
    })?;

    csv_writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom_types::DnsName255;
    use crate::test_support::{temp_test_path, test_dns_record};
    use crossbeam::channel;
    use std::fs;
    use std::fs::File;

    #[test]
    fn flushes_buffer_on_shutdown() {
        let filename = temp_test_path("csv-writer", "csv");
        let file = File::create(&filename).expect("creates csv file");
        let (tx, rx) = channel::unbounded();

        tx.send(OutputMessage::Record(test_dns_record()))
            .expect("record is sent");
        tx.send(OutputMessage::Shutdown).expect("shutdown is sent");

        csv_writer(file, rx).expect("csv writer completes successfully");

        let output = fs::read_to_string(&filename).expect("reads csv output");
        let mut lines = output.lines();
        assert_eq!(
            lines.next(),
            Some(
                "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code"
            )
        );
        assert!(output.contains("example.com"));

        fs::remove_file(filename).expect("removes temp csv file");
    }

    #[test]
    fn escapes_name_field_with_csv_special_characters() {
        let filename = temp_test_path("csv-writer-escape", "csv");
        let file = File::create(&filename).expect("creates csv file");
        let (tx, rx) = channel::unbounded();
        let mut record = test_dns_record();
        record.name = DnsName255::new("exa,mple\"name\nwrapped\rline").expect("test name fits");

        tx.send(OutputMessage::Record(record))
            .expect("record is sent");
        tx.send(OutputMessage::Shutdown).expect("shutdown is sent");

        csv_writer(file, rx).expect("csv writer completes successfully");

        let mut reader = csv::Reader::from_path(&filename).expect("opens csv reader");
        let headers = reader.headers().expect("reads csv headers").clone();
        assert_eq!(
            headers.iter().collect::<Vec<_>>(),
            vec![
                "request_timestamp",
                "response_timestamp",
                "source_ip",
                "source_port",
                "id",
                "name",
                "query_type",
                "response_code"
            ]
        );

        let row = reader
            .records()
            .next()
            .expect("one row exists")
            .expect("row parses");
        assert_eq!(&row[5], "exa,mple\"name\nwrapped\rline");

        fs::remove_file(filename).expect("removes temp csv file");
    }

    #[test]
    fn flushes_buffer_when_channel_closes_without_explicit_shutdown() {
        let filename = temp_test_path("csv-writer-channel-close", "csv");
        let file = File::create(&filename).expect("creates csv file");
        let (tx, rx) = channel::unbounded();

        tx.send(OutputMessage::Record(test_dns_record()))
            .expect("record is sent");
        drop(tx);

        csv_writer(file, rx).expect("csv writer completes successfully");

        let output = fs::read_to_string(&filename).expect("reads csv output");
        assert!(output.contains("example.com"));

        fs::remove_file(filename).expect("removes temp csv file");
    }

    #[test]
    fn writes_csv_to_an_in_memory_sink() {
        let (tx, rx) = channel::unbounded();

        tx.send(OutputMessage::Record(test_dns_record()))
            .expect("record is sent");
        tx.send(OutputMessage::Shutdown).expect("shutdown is sent");

        let mut output = Vec::new();
        csv_writer(&mut output, rx).expect("csv writer completes successfully");

        let output = String::from_utf8(output).expect("csv output is utf-8");
        assert!(output.starts_with(
            "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n"
        ));
        assert!(output.contains("example.com"));
    }

    #[test]
    fn drops_buffered_rows_on_abort() {
        let (tx, rx) = channel::unbounded();

        tx.send(OutputMessage::Record(test_dns_record()))
            .expect("record is sent");
        tx.send(OutputMessage::Abort).expect("abort is sent");

        let mut output = Vec::new();
        csv_writer(&mut output, rx).expect("csv writer completes successfully");

        let output = String::from_utf8(output).expect("csv output is utf-8");
        assert_eq!(
            output,
            "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n"
        );
    }
}
