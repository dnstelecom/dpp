/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::config::{InputSource, PACKET_BATCH_SIZE};
use anyhow::{Context, Result};
use byteorder_slice::{BigEndian, LittleEndian};
use pcap::{Capture, Error as LibpcapError, Linktype, Offline};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{
    Block as PcapNgBlock,
    blocks::interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption},
};
use pcap_file::{DataLink, Endianness};
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, ErrorKind, Read};
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
    PcapNg(PcapNgStreamReader),
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
            ensure_classic_pcap_ethernet_linktype(reader.header().datalink, filename.display())?;
            return Ok(Self::Classic(reader));
        }

        let capture = Capture::from_file(filename)?;
        ensure_libpcap_ethernet_linktype(capture.get_datalink(), filename.display())?;
        Ok(Self::Libpcap(capture))
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
                ensure_classic_pcap_ethernet_linktype(reader.header().datalink, source_name)?;
                Ok(Self::Classic(reader))
            }
            StreamFormat::PcapNg => {
                let reader =
                    PcapNgStreamReader::new(BufReader::new(CaptureInputReader::Stream(reader)))
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
            PacketBackend::PcapNg(reader) => reader.next_packet_data(),
        }
    }
}

impl PacketParser {
    /// Creates a new `PacketParser` instance by opening the specified capture source.
    ///
    /// Classic pcap files use a pure-Rust streaming reader. Other formats fall back to libpcap to
    /// preserve existing compatibility assumptions. Stdin uses parser-owned streaming readers.
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

fn ensure_ethernet_datalink(datalink: DataLink, source: impl std::fmt::Display) -> Result<()> {
    if datalink != DataLink::ETHERNET {
        anyhow::bail!(
            "Unsupported link-layer type {datalink:?} in '{source}'; only Ethernet is supported."
        );
    }

    Ok(())
}

fn ensure_classic_pcap_ethernet_linktype(
    datalink_and_metadata: DataLink,
    source: impl std::fmt::Display,
) -> Result<()> {
    let raw = u32::from(datalink_and_metadata);
    // Reserved3 (bits 16-25) and R (bit 27) must be zero; P/FCS metadata is valid.
    if raw & 0x0BFF_0000 != 0 {
        anyhow::bail!(
            "Invalid classic pcap link-layer field 0x{raw:08x} in '{source}': reserved bits must be zero."
        );
    }

    let linktype = DataLink::from(raw & u32::from(u16::MAX));
    ensure_ethernet_datalink(linktype, source)
}

fn ensure_libpcap_ethernet_linktype(
    linktype: Linktype,
    source: impl std::fmt::Display,
) -> Result<()> {
    if linktype != Linktype::ETHERNET {
        anyhow::bail!(
            "Unsupported link-layer type {linktype:?} in '{source}'; only Ethernet is supported."
        );
    }

    Ok(())
}

/// Owns stdin PCAPNG framing and its sole section-local interface table. The dependency's
/// stateful reader converts timestamps incorrectly; even `next_raw_block` rejects valid
/// resolutions while updating interfaces. Only its stateless block validation is used here.
struct PcapNgStreamReader {
    input: BufferedCaptureInput,
    endianness: Endianness,
    interfaces: Vec<PcapNgInterface>,
    block_bytes: Vec<u8>,
}

impl PcapNgStreamReader {
    fn new(input: BufferedCaptureInput) -> Result<Self> {
        let mut reader = Self {
            input,
            endianness: Endianness::Big,
            interfaces: Vec::new(),
            block_bytes: Vec::new(),
        };
        anyhow::ensure!(reader.read_block_bytes()?, "Missing pcapng section header");
        anyhow::ensure!(
            matches!(reader.decode_block()?, PcapNgBlock::SectionHeader(_)),
            "Missing pcapng section header"
        );
        Ok(reader)
    }

    fn read_block_bytes(&mut self) -> Result<bool> {
        if self.input.fill_buf()?.is_empty() {
            return Ok(false);
        }

        // Read only the fixed prefix before trusting the declared block length. The body
        // grows with bytes actually received, so a huge length in a truncated stream cannot
        // force an equally huge allocation. Memory remains bounded by the largest read block.
        let mut prefix = [0_u8; 12];
        self.input.read_exact(&mut prefix)?;
        if is_pcapng_magic(prefix[..4].try_into().expect("four-byte block type")) {
            self.endianness = match &prefix[8..12] {
                [0x1a, 0x2b, 0x3c, 0x4d] => Endianness::Big,
                [0x4d, 0x3c, 0x2b, 0x1a] => Endianness::Little,
                _ => anyhow::bail!("Invalid pcapng section byte-order magic"),
            };
        }
        let block_len = self.u32(&prefix[4..8]);
        anyhow::ensure!(
            block_len >= 12 && block_len.is_multiple_of(4),
            "Invalid pcapng block length {block_len}: expected a multiple of four, at least 12"
        );
        self.block_bytes.clear();
        self.block_bytes.extend_from_slice(&prefix);
        self.input
            .by_ref()
            .take(u64::from(block_len - 12))
            .read_to_end(&mut self.block_bytes)?;
        anyhow::ensure!(
            self.block_bytes.len() == block_len as usize,
            "Truncated pcapng block: expected {block_len} bytes, read {}",
            self.block_bytes.len()
        );
        Ok(true)
    }

    fn decode_block(&self) -> Result<PcapNgBlock<'_>> {
        // Retain upstream validation of the trailing block length, body bounds, options,
        // and all known non-packet blocks, without invoking timestamp-resolution conversion.
        let (_, block) = match self.endianness {
            Endianness::Big => PcapNgBlock::from_slice::<BigEndian>(&self.block_bytes)?,
            Endianness::Little => PcapNgBlock::from_slice::<LittleEndian>(&self.block_bytes)?,
        };
        Ok(block)
    }

    fn u32(&self, bytes: &[u8]) -> u32 {
        let bytes = bytes.try_into().expect("validated four-byte pcapng field");
        match self.endianness {
            Endianness::Big => u32::from_be_bytes(bytes),
            Endianness::Little => u32::from_le_bytes(bytes),
        }
    }

    fn next_packet_data(&mut self) -> Result<Option<PacketData>> {
        while self.read_block_bytes()? {
            match self.decode_block()? {
                PcapNgBlock::SectionHeader(_) => self.interfaces.clear(),
                PcapNgBlock::InterfaceDescription(interface) => {
                    let interface = PcapNgInterface::new(&interface)?;
                    self.interfaces.push(interface);
                }
                PcapNgBlock::EnhancedPacket(packet) => {
                    return self
                        .packet_data(packet.interface_id, packet.original_len, &packet.data)
                        .map(Some);
                }
                PcapNgBlock::Packet(packet) => {
                    return self
                        .packet_data(
                            u32::from(packet.interface_id),
                            packet.original_len,
                            &packet.data,
                        )
                        .map(Some);
                }
                PcapNgBlock::SimplePacket(_) => anyhow::bail!(
                    "Unsupported pcapng Simple Packet Block: packet timestamps are required for offline DNS matching."
                ),
                _ => {}
            }
        }
        Ok(None)
    }

    fn packet_data(&self, interface_id: u32, original_len: u32, data: &[u8]) -> Result<PacketData> {
        let interface = self.interfaces.get(interface_id as usize).ok_or_else(|| {
            anyhow::anyhow!("pcapng packet references unknown interface {interface_id}")
        })?;
        ensure_ethernet_datalink(
            interface.linktype,
            format_args!("pcapng interface {interface_id}"),
        )?;
        anyhow::ensure!(
            data.len() <= original_len as usize,
            "pcapng captured packet length exceeds original packet length"
        );
        anyhow::ensure!(
            interface.snaplen == 0 || data.len() <= interface.snaplen as usize,
            "pcapng captured packet length exceeds interface snaplen"
        );

        // Both EPB and legacy PB store two section-endian u32 words, high then low.
        // The stateless decoder has already validated this fixed header and the payload.
        // Ignore its timestamp representation: legacy PB incorrectly decodes a single u64.
        let ticks = (u64::from(self.u32(&self.block_bytes[12..16])) << 32)
            | u64::from(self.u32(&self.block_bytes[16..20]));
        Ok(PacketData {
            data: PacketPayload::owned(Box::from(data)),
            timestamp_micros: interface.timestamp_micros(ticks),
            packet_ordinal: 0,
        })
    }
}

struct PcapNgInterface {
    linktype: DataLink,
    snaplen: u32,
    // None means 10^exponent exceeds u128. Even u64::MAX ticks then round down to 0us.
    units_per_second: Option<u128>,
    offset_seconds: i64,
}

impl PcapNgInterface {
    fn new(interface: &InterfaceDescriptionBlock<'_>) -> Result<Self> {
        let mut resolution = None;
        let mut offset_seconds = None;
        for option in &interface.options {
            match option {
                InterfaceDescriptionOption::IfTsResol(value) => {
                    anyhow::ensure!(resolution.is_none(), "Duplicate pcapng if_tsresol option");
                    resolution = Some(*value);
                }
                InterfaceDescriptionOption::IfTsOffset(value) => {
                    anyhow::ensure!(
                        offset_seconds.is_none(),
                        "Duplicate pcapng if_tsoffset option"
                    );
                    // The dependency exposes u64, but the option is a signed two's-complement i64.
                    offset_seconds = Some(*value as i64);
                }
                _ => {}
            }
        }
        let resolution = resolution.unwrap_or(6);
        let exponent = u32::from(resolution & 0x7f);
        let units_per_second = if resolution & 0x80 == 0 {
            10_u128.checked_pow(exponent)
        } else {
            Some(1_u128 << exponent)
        };
        Ok(Self {
            linktype: interface.linktype,
            snaplen: interface.snaplen,
            units_per_second,
            offset_seconds: offset_seconds.unwrap_or(0),
        })
    }

    fn timestamp_micros(&self, ticks: u64) -> i64 {
        // Scale the full counter before division: fractional nanosecond units, including
        // every binary resolution, must not be rounded individually before multiplication.
        let micros = self
            .units_per_second
            .map_or(0, |units| u128::from(ticks) * 1_000_000 / units);
        let adjusted = micros as i128 + i128::from(self.offset_seconds) * 1_000_000;
        adjusted.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
    }
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
    use pcap_file::pcapng::PcapNgWriter;
    use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    use std::borrow::Cow;
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

    fn classic_pcap_bytes_with_network_field(
        network: u32,
        packets: &[(u32, u32, &[u8])],
    ) -> Vec<u8> {
        let mut bytes = classic_pcap_bytes(packets);
        bytes[20..24].copy_from_slice(&network.to_le_bytes());
        bytes
    }

    fn enhanced_pcapng_bytes(linktypes: &[DataLink], packets: &[(u32, u64, &[u8])]) -> Vec<u8> {
        let mut writer = PcapNgWriter::new(Vec::new()).expect("pcapng writer initializes");
        for linktype in linktypes {
            writer
                .write_pcapng_block(InterfaceDescriptionBlock::new(*linktype, 0xFFFF))
                .expect("pcapng interface block writes");
        }

        for (interface_id, timestamp_micros, payload) in packets {
            let mut packet = EnhancedPacketBlock::default();
            packet.interface_id = *interface_id;
            packet.timestamp = Duration::from_micros(*timestamp_micros);
            packet.original_len = payload.len() as u32;
            packet.data = Cow::Borrowed(*payload);
            writer
                .write_pcapng_block(packet)
                .expect("pcapng enhanced packet block writes");
        }

        writer.into_inner()
    }

    fn legacy_packet_pcapng_bytes(
        linktypes: &[DataLink],
        interface_id: u16,
        timestamp_micros: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        super::wire_tests::legacy_packet_bytes(linktypes, interface_id, timestamp_micros, payload)
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
    fn rejects_non_ethernet_classic_pcap_file_at_open() {
        let path = temp_test_path("packet-parser-classic-raw", "pcap");
        fs::write(
            &path,
            classic_pcap_bytes_with_network_field(
                u32::from(DataLink::RAW),
                &[(1, 2, &[1, 2, 3, 4])],
            ),
        )
        .expect("test pcap written");

        let error = match PacketParser::new(&InputSource::File(path.clone()), false) {
            Ok(_) => panic!("RAW classic pcap must be rejected"),
            Err(error) => error,
        };
        fs::remove_file(&path).expect("test pcap removed");

        assert!(
            error.to_string().contains("link-layer type RAW"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_non_ethernet_classic_pcap_stream_at_open() {
        let error = match PacketBackend::from_stream(
            Box::new(Cursor::new(classic_pcap_bytes_with_network_field(
                u32::from(DataLink::RAW),
                &[],
            ))),
            "test-stream",
        ) {
            Ok(_) => panic!("RAW classic pcap stream must be rejected"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("link-layer type RAW"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn accepts_classic_pcap_ethernet_with_fcs_metadata() {
        // The FCS length is encoded in 16-bit words; the P bit marks it as present.
        let ethernet_with_four_byte_fcs =
            (2_u32 << 28) | (1_u32 << 26) | u32::from(DataLink::ETHERNET);
        let mut parser = parser_from_stream(classic_pcap_bytes_with_network_field(
            ethernet_with_four_byte_fcs,
            &[(1, 2, &[1, 2, 3, 4])],
        ));

        let batch = parser
            .next_batch(1)
            .expect("Ethernet capture with FCS metadata reads")
            .expect("batch contains one packet");

        assert_eq!(batch[0].timestamp_micros, 1_000_002);
        assert_eq!(batch[0].data.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn rejects_classic_pcap_with_reserved_linktype_bits() {
        let ethernet_with_reserved_bit = 0x0001_0000 | u32::from(DataLink::ETHERNET);
        let error = match PacketBackend::from_stream(
            Box::new(Cursor::new(classic_pcap_bytes_with_network_field(
                ethernet_with_reserved_bit,
                &[],
            ))),
            "test-stream",
        ) {
            Ok(_) => panic!("classic pcap with reserved linktype bits must be rejected"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("reserved bits must be zero"),
            "unexpected error: {error}"
        );
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
    fn rejects_non_ethernet_pcapng_enhanced_packet() {
        let mut parser = parser_from_stream(enhanced_pcapng_bytes(
            &[DataLink::RAW],
            &[(0, 1_000_002, &[1, 2, 3, 4])],
        ));

        let error = parser
            .next_batch(1)
            .expect_err("RAW pcapng packet must be rejected");

        assert!(
            error.to_string().contains("link-layer type RAW"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_non_ethernet_libpcap_file_at_open() {
        let path = temp_test_path("packet-parser-libpcap-raw", "pcapng");
        fs::write(
            &path,
            enhanced_pcapng_bytes(&[DataLink::RAW], &[(0, 1_000_002, &[1, 2, 3, 4])]),
        )
        .expect("test pcapng written");

        let error = match PacketParser::new(&InputSource::File(path.clone()), false) {
            Ok(_) => panic!("RAW libpcap capture must be rejected"),
            Err(error) => error,
        };
        fs::remove_file(&path).expect("test pcapng removed");

        assert!(
            error.to_string().contains("only Ethernet is supported"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validates_each_referenced_pcapng_interface() {
        let mut parser = parser_from_stream(enhanced_pcapng_bytes(
            &[DataLink::ETHERNET, DataLink::RAW],
            &[(0, 1_000_002, &[1]), (1, 2_000_003, &[2])],
        ));

        let batch = parser
            .next_batch(1)
            .expect("Ethernet packet read succeeds")
            .expect("batch contains Ethernet packet");
        assert_eq!(batch[0].timestamp_micros, 1_000_002);
        assert_eq!(batch[0].data.as_slice(), &[1]);

        let error = parser
            .next_batch(1)
            .expect_err("packet on RAW interface must be rejected");
        assert!(
            error.to_string().contains("pcapng interface 1"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn reads_ethernet_pcapng_legacy_packet_with_original_timestamp() {
        let mut parser = parser_from_stream(legacy_packet_pcapng_bytes(
            &[DataLink::ETHERNET],
            0,
            1_000_002,
            &[1, 2, 3, 4],
        ));

        let batch = parser
            .next_batch(1)
            .expect("legacy packet read succeeds")
            .expect("batch contains legacy packet");

        assert_eq!(batch[0].timestamp_micros, 1_000_002);
        assert_eq!(batch[0].data.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn rejects_non_ethernet_pcapng_legacy_packet() {
        let mut parser = parser_from_stream(legacy_packet_pcapng_bytes(
            &[DataLink::ETHERNET, DataLink::RAW],
            1,
            1_000_002,
            &[1, 2, 3, 4],
        ));

        let error = parser
            .next_batch(1)
            .expect_err("legacy RAW pcapng packet must be rejected");

        assert!(
            error.to_string().contains("link-layer type RAW"),
            "unexpected error: {error}"
        );
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

#[cfg(test)]
#[path = "packet_parser_wire_tests.rs"]
mod wire_tests;
