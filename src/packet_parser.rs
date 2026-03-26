/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::config::PACKET_BATCH_SIZE;
use anyhow::{Context, Result};
use pcap::{Capture, Error as LibpcapError, Offline};
use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::io::{BufReader, ErrorKind, Read};
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

enum PacketBackend {
    Classic(PcapReader<BufReader<File>>),
    Libpcap(Capture<Offline>),
}

impl PacketBackend {
    fn from_file(filename: &Path) -> Result<Self> {
        if is_classic_pcap(filename)? {
            let file = File::open(filename).with_context(|| {
                format!("Unable to open classic pcap file '{}'", filename.display())
            })?;
            let reader = PcapReader::new(BufReader::new(file)).with_context(|| {
                format!(
                    "Unable to parse classic pcap header from '{}'",
                    filename.display()
                )
            })?;
            return Ok(Self::Classic(reader));
        }

        Ok(Self::Libpcap(Capture::from_file(filename)?))
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
        }
    }
}

impl PacketParser {
    /// Creates a new `PacketParser` instance by opening the specified capture file.
    ///
    /// Classic pcap files use a pure-Rust streaming reader. Other formats fall back to libpcap to
    /// preserve existing compatibility assumptions.
    pub fn new(filename: &Path, enforce_monotonic_timestamps: bool) -> Result<Self> {
        Ok(Self {
            backend: PacketBackend::from_file(filename)?,
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

fn is_classic_pcap_magic(magic: [u8; 4]) -> bool {
    matches!(
        magic,
        [0xa1, 0xb2, 0xc3, 0xd4]
            | [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d]
            | [0x4d, 0x3c, 0xb2, 0xa1]
    )
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
    use crate::test_support::{classic_pcap_bytes, temp_test_path};
    use std::fs;

    fn packet(timestamp_micros: i64, sequence: u64) -> PacketData {
        PacketData {
            data: PacketPayload::owned(Box::from([])),
            timestamp_micros,
            packet_ordinal: sequence,
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
    fn reads_classic_pcap_payload_via_pure_rust_reader() {
        let path = temp_test_path("packet-parser-classic", "pcap");
        fs::write(&path, classic_pcap_bytes(&[(1, 2, &[1, 2, 3, 4])])).expect("test pcap written");

        let mut parser = PacketParser::new(&path, false).expect("parser opens");
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
    fn empty_classic_pcap_returns_no_batches() {
        let path = temp_test_path("packet-parser-empty", "pcap");
        fs::write(&path, classic_pcap_bytes(&[])).expect("test pcap written");

        let mut parser = PacketParser::new(&path, false).expect("parser opens");
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

        let mut parser = PacketParser::new(&path, false).expect("parser opens");
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

        let mut parser = PacketParser::new(&path, false).expect("parser opens");
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

        let mut parser = PacketParser::new(&path, true).expect("parser opens");
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
