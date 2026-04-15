/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::config::{InputSource, PACKET_BATCH_SIZE};
use anyhow::{Context, Result};
use pcap::{Capture, Error as LibpcapError, Offline};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use pcap_file::pcapng::{Block as PcapNgBlock, blocks::packet::PacketBlock};
use std::fs::File;
use std::io::{BufReader, Cursor, ErrorKind, Read};
use std::ops::Deref;
use std::path::Path;
use std::time::Duration;

/// Packet payload storage that remains valid after batch handoff to worker threads.
#[derive(Clone, Debug)]
pub struct PacketPayload(Box<[u8]>);

impl PacketPayload {
    fn owned(data: Box<[u8]>) -> Self {
        Self(data)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for PacketPayload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

/// Represents a network packet with its payload and capture timestamp.
#[derive(Clone, Debug)]
pub struct PacketData {
    pub data: PacketPayload,
    pub timestamp_micros: i64,
    pub packet_ordinal: u64,
}

/// Deterministic packet order used by the single supported matching mode.
pub(crate) fn sort_packet_batch(packet_batch: &mut [PacketData]) {
    packet_batch.sort_by(|a, b| {
        a.timestamp_micros
            .cmp(&b.timestamp_micros)
            .then_with(|| a.packet_ordinal.cmp(&b.packet_ordinal))
    });
}

/// A parser for reading packets from an offline capture source.
pub struct PacketParser {
    backend: PacketBackend,
    enforce_monotonic_timestamps: bool,
    packet_ordinal: u64,
    last_timestamp_micros: Option<i64>,
    first_non_monotonic_timestamp: Option<NonMonotonicTimestampSample>,
    non_monotonic_timestamp_count: usize,
}

pub(crate) type PacketBatch = Vec<PacketData>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NonMonotonicTimestampSample {
    pub(crate) previous_packet_ordinal: u64,
    pub(crate) previous_timestamp_micros: i64,
    pub(crate) current_packet_ordinal: u64,
    pub(crate) current_timestamp_micros: i64,
}

type StreamReader = Box<dyn Read + Send>;
type BufferedCaptureInput = BufReader<CaptureInputReader>;

enum PacketBackend {
    Classic(PcapReader<BufferedCaptureInput>),
    PcapNg(PcapNgReader<BufferedCaptureInput>),
    Libpcap(Capture<Offline>),
}

impl PacketBackend {
    fn from_input_source(input_source: &InputSource) -> Result<Self> {
        match input_source {
            InputSource::File(path) => Self::from_file(path),
            InputSource::Stdin => Self::from_stdin(),
        }
    }

    fn from_file(filename: &Path) -> Result<Self> {
        if is_classic_pcap(filename)? {
            let file = File::open(filename).with_context(|| {
                format!("Unable to open classic pcap file '{}'", filename.display())
            })?;
            let reader = PcapReader::new(BufReader::new(CaptureInputReader::File(file)))
                .with_context(|| {
                    format!(
                        "Unable to parse classic pcap header from '{}'",
                        filename.display()
                    )
                })?;
            return Ok(Self::Classic(reader));
        }

        Ok(Self::Libpcap(Capture::from_file(filename)?))
    }

    #[cfg(not(windows))]
    fn from_stdin() -> Result<Self> {
        Self::from_stream(Box::new(std::io::stdin()), "stdin")
    }

    #[cfg(windows)]
    fn from_stdin() -> Result<Self> {
        anyhow::bail!("Reading the input capture from stdin is not supported on Windows.")
    }

    fn from_stream(reader: StreamReader, source_name: &str) -> Result<Self> {
        let (reader, format) = probe_capture_stream(reader, source_name)?;

        match format {
            StreamFormat::ClassicPcap => {
                let reader = PcapReader::new(BufReader::new(CaptureInputReader::Stream(reader)))
                    .with_context(|| {
                        format!("Unable to parse classic pcap header from '{source_name}'")
                    })?;
                Ok(Self::Classic(reader))
            }
            StreamFormat::PcapNg => {
                let reader = PcapNgReader::new(BufReader::new(CaptureInputReader::Stream(reader)))
                    .with_context(|| {
                        format!("Unable to parse pcapng section header from '{source_name}'")
                    })?;
                Ok(Self::PcapNg(reader))
            }
            StreamFormat::Unknown => anyhow::bail!(
                "Unsupported capture stream format on '{source_name}'. Stdin supports classic PCAP and PCAPNG streams."
            ),
        }
    }

    fn next_packet_data(&mut self) -> Result<Option<PacketData>> {
        match self {
            PacketBackend::Classic(reader) => match reader.next_packet() {
                Some(Ok(packet)) => Ok(Some(PacketData {
                    data: PacketPayload::owned(packet.data.into_owned().into_boxed_slice()),
                    timestamp_micros: duration_to_micros(packet.timestamp),
                    packet_ordinal: 0,
                })),
                Some(Err(err)) => Err(err.into()),
                None => Ok(None),
            },
            PacketBackend::Libpcap(capture) => match capture.next_packet() {
                Ok(packet) => Ok(Some(PacketData {
                    data: PacketPayload::owned(Box::from(packet.data)),
                    timestamp_micros: libpcap_timeval_to_micros(
                        packet.header.ts.tv_sec,
                        packet.header.ts.tv_usec,
                    ),
                    packet_ordinal: 0,
                })),
                Err(LibpcapError::NoMorePackets) => Ok(None),
                Err(err) => Err(err.into()),
            },
            PacketBackend::PcapNg(reader) => loop {
                let next_block = reader
                    .next_block()
                    .map(|result| result.map(|block| block.into_owned()));
                match next_block {
                    Some(Ok(block)) => {
                        if let Some(packet) = pcapng_block_to_packet_data(reader, block)? {
                            break Ok(Some(packet));
                        }
                    }
                    Some(Err(err)) => break Err(err.into()),
                    None => break Ok(None),
                }
            },
        }
    }
}

impl PacketParser {
    /// Creates a new `PacketParser` instance by opening the specified capture source.
    ///
    /// Classic pcap files use a pure-Rust streaming reader. Other formats fall back to libpcap to
    /// preserve existing compatibility assumptions. Stdin uses libpcap's offline stream reader.
    pub fn new(input_source: &InputSource, enforce_monotonic_timestamps: bool) -> Result<Self> {
        Ok(Self {
            backend: PacketBackend::from_input_source(input_source)?,
            enforce_monotonic_timestamps,
            packet_ordinal: 0,
            last_timestamp_micros: None,
            first_non_monotonic_timestamp: None,
            non_monotonic_timestamp_count: 0,
        })
    }

    /// Reads the next packet batch from the offline capture source in capture order.
    ///
    /// The batch owns or references stable packet buffers, which allows callers to hand it off to
    /// another thread and overlap ingestion with downstream processing.
    pub fn next_batch(&mut self, chunk_size: usize) -> Result<Option<PacketBatch>> {
        let mut packet_buffer: PacketBatch = Vec::with_capacity(chunk_size.min(PACKET_BATCH_SIZE));

        while packet_buffer.len() < chunk_size {
            match self.backend.next_packet_data()? {
                Some(packet) => {
                    if let Some(previous_timestamp_micros) = self.last_timestamp_micros
                        && packet.timestamp_micros < previous_timestamp_micros
                    {
                        let sample = NonMonotonicTimestampSample {
                            previous_packet_ordinal: self.packet_ordinal.saturating_sub(1),
                            previous_timestamp_micros,
                            current_packet_ordinal: self.packet_ordinal,
                            current_timestamp_micros: packet.timestamp_micros,
                        };
                        self.non_monotonic_timestamp_count += 1;

                        if self.enforce_monotonic_timestamps {
                            return Err(anyhow::anyhow!(
                                "Detected non-monotonic packet timestamps while monotonic-capture mode is enabled. First regression: packet {} at {}us followed packet {} at {}us. Normalize the capture first with reordercap input.pcap normalized.pcap.",
                                sample.current_packet_ordinal,
                                sample.current_timestamp_micros,
                                sample.previous_packet_ordinal,
                                sample.previous_timestamp_micros,
                            ));
                        }

                        self.first_non_monotonic_timestamp.get_or_insert(sample);
                    }

                    self.last_timestamp_micros = Some(packet.timestamp_micros);
                    packet_buffer.push(PacketData {
                        packet_ordinal: self.packet_ordinal,
                        ..packet
                    });
                    self.packet_ordinal = self.packet_ordinal.wrapping_add(1);
                }
                None => break,
            }
        }

        if packet_buffer.is_empty() {
            Ok(None)
        } else {
            Ok(Some(packet_buffer))
        }
    }

    pub(crate) fn non_monotonic_timestamp_count(&self) -> usize {
        self.non_monotonic_timestamp_count
    }

    pub(crate) fn first_non_monotonic_timestamp(&self) -> Option<NonMonotonicTimestampSample> {
        self.first_non_monotonic_timestamp
    }
}

fn is_classic_pcap(filename: &Path) -> Result<bool> {
    let mut file = File::open(filename)
        .with_context(|| format!("Unable to probe capture file '{}'", filename.display()))?;
    let mut magic = [0_u8; 4];

    match file.read_exact(&mut magic) {
        Ok(()) => Ok(is_classic_pcap_magic(magic)),
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(false),
        Err(err) => {
            Err(err).with_context(|| format!("Unable to read magic from '{}'", filename.display()))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamFormat {
    ClassicPcap,
    PcapNg,
    Unknown,
}

enum CaptureInputReader {
    File(File),
    Stream(ReplayReader<StreamReader>),
}

impl Read for CaptureInputReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::File(file) => file.read(buf),
            Self::Stream(reader) => reader.read(buf),
        }
    }
}

struct ReplayReader<R> {
    prefix: Cursor<Vec<u8>>,
    inner: R,
}

impl<R> ReplayReader<R> {
    fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            inner,
        }
    }
}

impl<R: Read> Read for ReplayReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            let read = self.prefix.read(buf)?;
            if read != 0 {
                return Ok(read);
            }
        }

        self.inner.read(buf)
    }
}

fn probe_capture_stream(
    mut reader: StreamReader,
    source_name: &str,
) -> Result<(ReplayReader<StreamReader>, StreamFormat)> {
    let mut prefix = vec![0_u8; 4];
    let mut read = 0;

    while read < prefix.len() {
        match reader.read(&mut prefix[read..]) {
            Ok(0) => {
                prefix.truncate(read);
                break;
            }
            Ok(bytes_read) => read += bytes_read,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("Unable to probe capture stream format from '{source_name}'")
                });
            }
        }
    }

    let format = classify_stream_prefix(&prefix);
    Ok((ReplayReader::new(prefix, reader), format))
}

fn classify_stream_prefix(prefix: &[u8]) -> StreamFormat {
    if prefix.len() < 4 {
        return StreamFormat::Unknown;
    }

    let magic = [prefix[0], prefix[1], prefix[2], prefix[3]];
    if is_classic_pcap_magic(magic) {
        StreamFormat::ClassicPcap
    } else if is_pcapng_magic(magic) {
        StreamFormat::PcapNg
    } else {
        StreamFormat::Unknown
    }
}

fn is_classic_pcap_magic(magic: [u8; 4]) -> bool {
    matches!(
        magic,
        [0xa1, 0xb2, 0xc3, 0xd4]
            | [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d]
            | [0x4d, 0x3c, 0xb2, 0xa1]
    )
}

fn is_pcapng_magic(magic: [u8; 4]) -> bool {
    magic == [0x0a, 0x0d, 0x0d, 0x0a]
}

fn pcapng_block_to_packet_data(
    reader: &PcapNgReader<BufferedCaptureInput>,
    block: PcapNgBlock<'_>,
) -> Result<Option<PacketData>> {
    match block {
        PcapNgBlock::EnhancedPacket(packet) => Ok(Some(PacketData {
            data: PacketPayload::owned(packet.data.into_owned().into_boxed_slice()),
            timestamp_micros: duration_to_micros(packet.timestamp),
            packet_ordinal: 0,
        })),
        PcapNgBlock::Packet(packet) => Ok(Some(packet_block_to_packet_data(reader, packet)?)),
        PcapNgBlock::SimplePacket(_) => anyhow::bail!(
            "Unsupported pcapng Simple Packet Block: packet timestamps are required for offline DNS matching."
        ),
        _ => Ok(None),
    }
}

fn packet_block_to_packet_data(
    reader: &PcapNgReader<BufferedCaptureInput>,
    packet: PacketBlock<'_>,
) -> Result<PacketData> {
    let interface = reader
        .interfaces()
        .get(packet.interface_id as usize)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "pcapng packet references unknown interface {}",
                packet.interface_id
            )
        })?;
    let nanos_per_unit = u128::from(interface.ts_resolution()?.to_nano_secs());
    let timestamp_nanos = u128::from(packet.timestamp).saturating_mul(nanos_per_unit);
    let timestamp_micros = timestamp_nanos.saturating_div(1_000).min(i64::MAX as u128) as i64;

    Ok(PacketData {
        data: PacketPayload::owned(packet.data.into_owned().into_boxed_slice()),
        timestamp_micros,
        packet_ordinal: 0,
    })
}

fn duration_to_micros(duration: Duration) -> i64 {
    let seconds = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX / 1_000_000);
    seconds
        .saturating_mul(1_000_000)
        .saturating_add(i64::from(duration.subsec_micros()))
}

fn libpcap_timeval_to_micros<TSec, TUsec>(tv_sec: TSec, tv_usec: TUsec) -> i64
where
    TSec: Into<i64>,
    TUsec: Into<i64>,
{
    tv_sec
        .into()
        .saturating_mul(1_000_000)
        .saturating_add(tv_usec.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{classic_pcap_bytes, pcapng_bytes, temp_test_path};
    use std::fs;
    use std::io::Cursor;

    fn packet(timestamp_micros: i64, sequence: u64) -> PacketData {
        PacketData {
            data: PacketPayload::owned(Box::from([])),
            timestamp_micros,
            packet_ordinal: sequence,
        }
    }

    fn parser_from_stream(bytes: Vec<u8>) -> PacketParser {
        PacketParser {
            backend: PacketBackend::from_stream(Box::new(Cursor::new(bytes)), "test-stream")
                .expect("stream parser opens"),
            enforce_monotonic_timestamps: false,
            packet_ordinal: 0,
            last_timestamp_micros: None,
            first_non_monotonic_timestamp: None,
            non_monotonic_timestamp_count: 0,
        }
    }

    #[test]
    fn detects_classic_pcap_magic_numbers() {
        assert!(is_classic_pcap_magic([0xa1, 0xb2, 0xc3, 0xd4]));
        assert!(is_classic_pcap_magic([0xd4, 0xc3, 0xb2, 0xa1]));
        assert!(is_classic_pcap_magic([0xa1, 0xb2, 0x3c, 0x4d]));
        assert!(is_classic_pcap_magic([0x4d, 0x3c, 0xb2, 0xa1]));
        assert!(!is_classic_pcap_magic([0x0a, 0x0d, 0x0d, 0x0a]));
    }

    #[test]
    fn detects_pcapng_magic_number() {
        assert!(is_pcapng_magic([0x0a, 0x0d, 0x0d, 0x0a]));
        assert!(!is_pcapng_magic([0xd4, 0xc3, 0xb2, 0xa1]));
    }

    #[test]
    fn reads_classic_pcap_payload_via_pure_rust_reader() {
        let path = temp_test_path("packet-parser-classic", "pcap");
        fs::write(&path, classic_pcap_bytes(&[(1, 2, &[1, 2, 3, 4])])).expect("test pcap written");

        let mut parser =
            PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
        let batch = parser
            .next_batch(1)
            .expect("batch read succeeds")
            .expect("batch contains one packet");

        fs::remove_file(&path).expect("test pcap removed");

        let packet = &batch[0];
        assert_eq!(packet.timestamp_micros, 1_000_002);
        assert_eq!(packet.packet_ordinal, 0);
        assert_eq!(packet.data.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(packet.data.0.as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn reads_classic_pcap_payload_via_stream_native_reader() {
        let mut parser = parser_from_stream(classic_pcap_bytes(&[(1, 2, &[1, 2, 3, 4])]));
        assert!(matches!(parser.backend, PacketBackend::Classic(_)));

        let batch = parser
            .next_batch(1)
            .expect("batch read succeeds")
            .expect("batch contains one packet");

        let packet = &batch[0];
        assert_eq!(packet.timestamp_micros, 1_000_002);
        assert_eq!(packet.packet_ordinal, 0);
        assert_eq!(packet.data.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn reads_pcapng_payload_via_stream_native_reader() {
        let mut parser = parser_from_stream(pcapng_bytes(&[(1_000_002, &[1, 2, 3, 4])]));
        assert!(matches!(parser.backend, PacketBackend::PcapNg(_)));

        let batch = parser
            .next_batch(1)
            .expect("batch read succeeds")
            .expect("batch contains one packet");

        let packet = &batch[0];
        assert_eq!(packet.timestamp_micros, 1_000_002);
        assert_eq!(packet.packet_ordinal, 0);
        assert_eq!(packet.data.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn empty_classic_pcap_returns_no_batches() {
        let path = temp_test_path("packet-parser-empty", "pcap");
        fs::write(&path, classic_pcap_bytes(&[])).expect("test pcap written");

        let mut parser =
            PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
        let batch = parser.next_batch(8).expect("batch read succeeds");

        fs::remove_file(&path).expect("test pcap removed");

        assert!(batch.is_none());
        assert_eq!(parser.non_monotonic_timestamp_count(), 0);
        assert_eq!(parser.first_non_monotonic_timestamp(), None);
    }

    #[test]
    fn tracks_non_monotonic_capture_timestamps() {
        let path = temp_test_path("packet-parser-non-monotonic", "pcap");
        fs::write(
            &path,
            classic_pcap_bytes(&[(2, 0, &[1]), (1, 500_000, &[2]), (3, 0, &[3])]),
        )
        .expect("test pcap written");

        let mut parser =
            PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
        let _ = parser.next_batch(8).expect("batch read succeeds");

        fs::remove_file(&path).expect("test pcap removed");

        assert_eq!(parser.non_monotonic_timestamp_count(), 1);
        assert_eq!(
            parser.first_non_monotonic_timestamp(),
            Some(NonMonotonicTimestampSample {
                previous_packet_ordinal: 0,
                previous_timestamp_micros: 2_000_000,
                current_packet_ordinal: 1,
                current_timestamp_micros: 1_500_000,
            })
        );
    }

    #[test]
    fn preserves_first_non_monotonic_sample_across_multiple_regressions() {
        let path = temp_test_path("packet-parser-multiple-non-monotonic", "pcap");
        fs::write(
            &path,
            classic_pcap_bytes(&[(3, 0, &[1]), (2, 0, &[2]), (1, 0, &[3])]),
        )
        .expect("test pcap written");

        let mut parser =
            PacketParser::new(&InputSource::File(path.clone()), false).expect("parser opens");
        let _ = parser.next_batch(8).expect("batch read succeeds");

        fs::remove_file(&path).expect("test pcap removed");

        assert_eq!(parser.non_monotonic_timestamp_count(), 2);
        assert_eq!(
            parser.first_non_monotonic_timestamp(),
            Some(NonMonotonicTimestampSample {
                previous_packet_ordinal: 0,
                previous_timestamp_micros: 3_000_000,
                current_packet_ordinal: 1,
                current_timestamp_micros: 2_000_000,
            })
        );
    }

    #[test]
    fn rejects_non_monotonic_capture_when_enforced() {
        let path = temp_test_path("packet-parser-non-monotonic-enforced", "pcap");
        fs::write(
            &path,
            classic_pcap_bytes(&[(2, 0, &[1]), (1, 500_000, &[2])]),
        )
        .expect("test pcap written");

        let mut parser =
            PacketParser::new(&InputSource::File(path.clone()), true).expect("parser opens");
        let error = parser
            .next_batch(8)
            .expect_err("non-monotonic capture must fail");

        assert!(
            error
                .to_string()
                .contains("Normalize the capture first with reordercap"),
            "unexpected error: {error}"
        );

        fs::remove_file(&path).expect("test pcap removed");
    }

    #[test]
    fn converts_libpcap_timestamps_to_microseconds() {
        assert_eq!(libpcap_timeval_to_micros(12, 345_678), 12_345_678);
        assert_eq!(libpcap_timeval_to_micros(12_i64, 345_678_i64), 12_345_678);
    }

    #[test]
    fn saturates_large_durations_when_converting_to_microseconds() {
        let duration = Duration::new(u64::MAX, 999_999_999);

        assert_eq!(duration_to_micros(duration), i64::MAX);
    }

    #[test]
    fn sorts_batches_by_timestamp_then_sequence() {
        let mut packets = vec![packet(10, 2), packet(10, 1), packet(20, 4), packet(20, 3)];

        sort_packet_batch(&mut packets);

        assert_eq!(
            packets
                .into_iter()
                .map(|p| (p.timestamp_micros, p.packet_ordinal))
                .collect::<Vec<_>>(),
            vec![(10, 1), (10, 2), (20, 3), (20, 4)]
        );
    }
}
