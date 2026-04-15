/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use pcap_file::DataLink;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use std::borrow::Cow;
use std::path::PathBuf;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn temp_test_path(prefix: &str, extension: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time is valid")
        .as_nanos();

    std::env::temp_dir().join(format!(
        "dpp-integration-{prefix}-{}-{unique}.{extension}",
        std::process::id()
    ))
}

pub(crate) fn classic_pcap_bytes(packets: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut bytes = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];

    for (tv_sec, tv_usec, payload) in packets {
        let length = payload.len() as u32;
        bytes.extend_from_slice(&tv_sec.to_le_bytes());
        bytes.extend_from_slice(&tv_usec.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(payload);
    }

    bytes
}

pub(crate) fn pcapng_bytes(packets: &[(u64, &[u8])]) -> Vec<u8> {
    let mut writer = PcapNgWriter::new(Vec::new()).expect("pcapng writer initializes");
    writer
        .write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::ETHERNET, 0xFFFF))
        .expect("pcapng interface block writes");

    for (timestamp_micros, payload) in packets {
        let mut packet = EnhancedPacketBlock::default();
        packet.interface_id = 0;
        packet.timestamp = Duration::from_micros(*timestamp_micros);
        packet.original_len = payload.len() as u32;
        packet.data = Cow::Borrowed(*payload);
        writer
            .write_pcapng_block(packet)
            .expect("pcapng packet block writes");
    }

    writer.into_inner()
}

pub(crate) fn encode_dns_header(id: u16, flags: u16, query_count: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(12);
    header.extend_from_slice(&id.to_be_bytes());
    header.extend_from_slice(&flags.to_be_bytes());
    header.extend_from_slice(&query_count.to_be_bytes());
    header.extend_from_slice(&0_u16.to_be_bytes());
    header.extend_from_slice(&0_u16.to_be_bytes());
    header.extend_from_slice(&0_u16.to_be_bytes());
    header
}

pub(crate) fn make_udp_dns_packet_with_payload(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    dns_payload: &[u8],
) -> Vec<u8> {
    let udp_length = 8 + dns_payload.len();
    let total_length = 20 + udp_length;

    let mut packet = Vec::with_capacity(14 + total_length);
    packet.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
    packet.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
    packet.extend_from_slice(&0x0800_u16.to_be_bytes());

    packet.push(0x45);
    packet.push(0);
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.push(64);
    packet.push(17);
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&dst_ip);

    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&(udp_length as u16).to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(dns_payload);

    packet
}
