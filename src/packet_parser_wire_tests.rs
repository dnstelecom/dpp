/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use super::*;

// Independent wire fixtures: do not round-trip the pcap-file writer, which shares the
// timestamp decoding bugs these tests guard against.
#[derive(Clone, Copy)]
enum Order {
    Little,
    Big,
}

impl Order {
    fn u16(self, value: u16) -> [u8; 2] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }

    fn u32(self, value: u32) -> [u8; 4] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }

    fn u64(self, value: u64) -> [u8; 8] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
}

struct WireCapture {
    order: Order,
    bytes: Vec<u8>,
}

impl WireCapture {
    fn new(order: Order) -> Self {
        let mut capture = Self {
            order,
            bytes: Vec::new(),
        };
        let mut section = order.u32(0x1a2b3c4d).to_vec();
        section.extend(order.u16(1));
        section.extend(order.u16(0));
        section.extend(order.u64(u64::MAX));
        capture.block(0x0a0d0d0a, &section);
        capture
    }

    fn block(&mut self, kind: u32, body: &[u8]) {
        let length = (body.len() + 12) as u32;
        self.bytes.extend(self.order.u32(kind));
        self.bytes.extend(self.order.u32(length));
        self.bytes.extend(body);
        self.bytes.extend(self.order.u32(length));
    }

    fn option(&self, code: u16, value: &[u8]) -> Vec<u8> {
        let mut option = self.order.u16(code).to_vec();
        option.extend(self.order.u16(value.len() as u16));
        option.extend(value);
        option.resize(option.len().next_multiple_of(4), 0);
        option
    }

    fn interface_options(&mut self, linktype: u16, snaplen: u32, options: &[u8]) {
        let mut body = self.order.u16(linktype).to_vec();
        body.extend(self.order.u16(0));
        body.extend(self.order.u32(snaplen));
        body.extend(options);
        self.block(1, &body);
    }

    fn interface(
        &mut self,
        linktype: u16,
        snaplen: u32,
        resolution: Option<u8>,
        offset: Option<i64>,
    ) {
        let mut options = Vec::new();
        if let Some(resolution) = resolution {
            options.extend(self.option(9, &[resolution]));
        }
        if let Some(offset) = offset {
            options.extend(self.option(14, &self.order.u64(offset as u64)));
        }
        if !options.is_empty() {
            options.extend([0; 4]);
        }
        self.interface_options(linktype, snaplen, &options);
    }

    fn packet(&mut self, kind: u32, interface_id: u32, ticks: u64, payload: &[u8]) {
        let mut body = if kind == 2 {
            let mut fields = self.order.u16(interface_id as u16).to_vec();
            fields.extend(self.order.u16(0xffff));
            fields
        } else {
            self.order.u32(interface_id).to_vec()
        };
        body.extend(self.order.u32((ticks >> 32) as u32));
        body.extend(self.order.u32(ticks as u32));
        body.extend(self.order.u32(payload.len() as u32));
        body.extend(self.order.u32(payload.len() as u32));
        body.extend(payload);
        body.resize(body.len().next_multiple_of(4), 0);
        self.block(kind, &body);
    }
}

fn parser(bytes: Vec<u8>) -> PacketParser {
    PacketParser {
        backend: PacketBackend::from_stream(Box::new(Cursor::new(bytes)), "wire-fixture")
            .expect("stream opens"),
        stdin_shutdown: None,
        enforce_monotonic_timestamps: false,
        packet_ordinal: 0,
        last_timestamp_micros: None,
        first_non_monotonic_timestamp: None,
        non_monotonic_timestamp_count: 0,
    }
}

pub(super) fn legacy_packet_bytes(
    linktypes: &[DataLink],
    interface_id: u16,
    timestamp_micros: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut capture = WireCapture::new(Order::Little);
    for linktype in linktypes {
        capture.interface(u32::from(*linktype) as u16, 65535, None, None);
    }
    capture.packet(2, u32::from(interface_id), timestamp_micros, payload);
    capture.bytes
}

#[test]
fn reads_all_timestamp_resolution_boundaries_in_both_packet_formats_and_byte_orders() {
    let cases = [
        (None, 1_234_567, 1_234_567),
        (Some(0), 1, 1_000_000),
        (Some(3), 12_345, 12_345_000),
        (Some(6), 1_234_567, 1_234_567),
        (Some(9), 1_234_567_890, 1_234_567),
        (Some(9), u64::MAX, 18_446_744_073_709_551),
        (Some(10), 10_000_000_000, 1_000_000),
        (Some(24), u64::MAX, 18),
        (Some(25), u64::MAX, 1),
        (Some(26), u64::MAX, 0),
        (Some(38), u64::MAX, 0),
        (Some(39), u64::MAX, 0),
        (Some(127), u64::MAX, 0),
        (Some(0x80), 1, 1_000_000),
        (Some(0x8a), 1024, 1_000_000),
        (Some(0x8a), 2201, 2_149_414),
        (Some(0x9e), 1 << 30, 1_000_000),
        (Some(0x9f), 1 << 31, 1_000_000),
        (Some(0xbf), 1 << 63, 1_000_000),
        (Some(0xc0), u64::MAX, 999_999),
        (Some(0xff), u64::MAX, 0),
    ];
    for order in [Order::Little, Order::Big] {
        for kind in [2, 6] {
            for (resolution, ticks, expected_micros) in cases {
                let mut capture = WireCapture::new(order);
                capture.interface(1, 65535, resolution, None);
                capture.packet(kind, 0, ticks, &[1, 2, 3]);
                let mut parser = parser(capture.bytes);
                let batch = parser.next_batch(8).unwrap().unwrap();
                assert_eq!(batch.len(), 1);
                assert_eq!(
                    batch[0].timestamp_micros, expected_micros,
                    "resolution {resolution:?}"
                );
                assert_eq!(batch[0].data.as_slice(), &[1, 2, 3]);
                assert!(parser.next_batch(8).unwrap().is_none());
            }
        }
    }
}

#[test]
fn applies_signed_offsets_per_interface_before_monotonic_checks() {
    for order in [Order::Little, Order::Big] {
        for kind in [2, 6] {
            let mut capture = WireCapture::new(order);
            capture.interface(1, 65535, None, Some(100));
            capture.interface(1, 65535, None, Some(101));
            capture.interface(1, 65535, None, Some(-1));
            capture.packet(kind, 0, 1_000_000, &[1]);
            capture.packet(kind, 1, 100_000, &[2]);
            capture.packet(kind, 2, 102_200_000, &[3]);
            let mut parser = parser(capture.bytes);
            parser.enforce_monotonic_timestamps = true;
            let batch = parser.next_batch(8).unwrap().unwrap();
            assert_eq!(
                batch.iter().map(|p| p.timestamp_micros).collect::<Vec<_>>(),
                [101_000_000, 101_100_000, 101_200_000]
            );
        }
    }
}

#[test]
fn preserves_negative_timestamps_and_saturates_only_after_adding_offset() {
    let cases = [
        (6, 100_000, -1, -900_000),
        (0, 1, -1, 0),
        (0, u64::MAX, i64::MIN, i64::MAX),
        (0, u64::MAX, 0, i64::MAX),
        (6, 0, i64::MIN, i64::MIN),
        (6, 0, i64::MAX, i64::MAX),
        // Conversion must not saturate the raw timestamp before applying its offset.
        (0, 10_000_000_000_000, -10_000_000_000_000, 0),
    ];
    for kind in [2, 6] {
        for (resolution, ticks, offset, expected) in cases {
            let mut capture = WireCapture::new(Order::Little);
            capture.interface(1, 65535, Some(resolution), Some(offset));
            capture.packet(kind, 0, ticks, &[1]);
            assert_eq!(
                parser(capture.bytes).next_batch(8).unwrap().unwrap()[0].timestamp_micros,
                expected
            );
        }
    }
}

#[test]
fn new_sections_reset_interface_metadata_and_can_change_endianness() {
    let mut first = WireCapture::new(Order::Little);
    first.interface(1, 65535, Some(0x8a), Some(100));
    first.packet(2, 0, 1024, &[1]);
    let mut second = WireCapture::new(Order::Big);
    second.interface(1, 65535, None, None);
    second.packet(6, 0, 102_000_000, &[2]);
    first.bytes.extend(second.bytes);
    let batch = parser(first.bytes).next_batch(8).unwrap().unwrap();
    assert_eq!(batch[0].timestamp_micros, 101_000_000);
    assert_eq!(batch[1].timestamp_micros, 102_000_000);
}

#[test]
fn rejects_unknown_interfaces_in_each_section_and_packet_format() {
    for kind in [2, 6] {
        let mut capture = WireCapture::new(Order::Little);
        capture.interface(1, 65535, None, None);
        let mut second = WireCapture::new(Order::Big);
        second.packet(kind, 0, 1, &[1]);
        capture.bytes.extend(second.bytes);
        assert!(
            parser(capture.bytes)
                .next_batch(8)
                .unwrap_err()
                .to_string()
                .contains("unknown interface 0")
        );
    }
}

#[test]
fn rejects_duplicate_timestamp_options_and_invalid_option_lengths() {
    for (code, values) in [
        (9, vec![vec![6], vec![9]]),
        (14, vec![vec![0; 8], vec![0; 8]]),
        (9, vec![vec![6, 6]]),
        (14, vec![vec![0; 4]]),
    ] {
        let mut capture = WireCapture::new(Order::Little);
        let mut options = Vec::new();
        for value in values {
            options.extend(capture.option(code, &value));
        }
        options.extend([0; 4]);
        capture.interface_options(1, 65535, &options);
        assert!(parser(capture.bytes).next_batch(8).is_err());
    }
}

#[test]
fn preserves_block_and_packet_length_validation() {
    for kind in [2, 6] {
        for invalid_field in [
            "trailer",
            "captured_len",
            "original_len",
            "snaplen",
            "truncated",
        ] {
            let mut capture = WireCapture::new(Order::Little);
            capture.interface(
                1,
                if invalid_field == "snaplen" { 1 } else { 65535 },
                None,
                None,
            );
            let packet_start = capture.bytes.len();
            capture.packet(kind, 0, 1, &[1, 2, 3, 4]);
            match invalid_field {
                "trailer" => {
                    let last = capture.bytes.len() - 4;
                    capture.bytes[last] = 0;
                }
                "captured_len" => capture.bytes[packet_start + 20..packet_start + 24]
                    .copy_from_slice(&100_u32.to_le_bytes()),
                "original_len" => capture.bytes[packet_start + 24..packet_start + 28]
                    .copy_from_slice(&1_u32.to_le_bytes()),
                "truncated" => {
                    capture.bytes.pop();
                }
                _ => {}
            }
            assert!(
                parser(capture.bytes).next_batch(8).is_err(),
                "{invalid_field}"
            );
        }
    }
}

#[test]
fn rejects_huge_truncated_blocks_without_reserving_the_declared_length() {
    let mut capture = WireCapture::new(Order::Little);
    capture.bytes.extend(6_u32.to_le_bytes());
    capture.bytes.extend(0xffff_fffc_u32.to_le_bytes());
    capture.bytes.extend([0; 4]);
    let mut parser = parser(capture.bytes);
    assert!(
        parser
            .next_batch(8)
            .unwrap_err()
            .to_string()
            .contains("Truncated pcapng block")
    );
    let PacketBackend::PcapNg(reader) = &parser.backend else {
        panic!("pcapng backend")
    };
    assert!(reader.block_bytes.capacity() < 1024 * 1024);
}

#[test]
fn validates_options_even_on_ignored_known_blocks() {
    let mut capture = WireCapture::new(Order::Little);
    // Interface Statistics Block, followed by an incomplete eight-byte counter option.
    let mut body = vec![0; 12];
    body.extend(capture.option(4, &[1, 2, 3, 4]));
    body.extend([0; 4]);
    capture.block(5, &body);
    assert!(parser(capture.bytes).next_batch(8).is_err());
}
