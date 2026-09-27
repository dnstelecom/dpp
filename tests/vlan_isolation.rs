/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

#[allow(dead_code)]
mod support;

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use support::{
    classic_pcap_bytes, encode_dns_header, make_udp_dns_packet_with_payload, temp_test_path,
};

fn dns_packet(response: bool, ipv6: bool, tags: &[(u16, u16)]) -> Vec<u8> {
    let mut dns = encode_dns_header(123, if response { 0x8180 } else { 0x0100 }, 1);
    dns.extend_from_slice(b"\x01a\0\0\x01\0\x01");
    let (source, destination, source_port, destination_port) = if response {
        ([8, 8, 8, 8], [10, 0, 0, 1], 53, 53000)
    } else {
        ([10, 0, 0, 1], [8, 8, 8, 8], 53000, 53)
    };
    let mut packet =
        make_udp_dns_packet_with_payload(source, destination, source_port, destination_port, &dns);
    if ipv6 {
        let udp = packet[34..].to_vec();
        packet.truncate(14);
        packet[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        packet.extend_from_slice(&[0x60, 0, 0, 0]);
        packet.extend_from_slice(&(udp.len() as u16).to_be_bytes());
        packet.extend_from_slice(&[17, 64]);
        for address in [source, destination] {
            packet.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0]);
            packet.extend_from_slice(&address);
        }
        packet.extend_from_slice(&udp);
    }
    let mut tagged = packet[..12].to_vec();
    for &(tpid, tci) in tags {
        tagged.extend_from_slice(&tpid.to_be_bytes());
        tagged.extend_from_slice(&tci.to_be_bytes());
    }
    tagged.extend_from_slice(&packet[12..]);
    tagged
}

fn output_timestamps(
    packets: &[Vec<u8>],
    threads: &str,
    fast_path: bool,
    full_fragments: bool,
) -> Vec<(i64, Option<i64>)> {
    static NEXT_CAPTURE: AtomicU64 = AtomicU64::new(0);
    let prefix = format!(
        "vlan-isolation-{}",
        NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed)
    );
    let input = temp_test_path(&prefix, "pcap");
    let output = temp_test_path(&prefix, "csv");
    let capture_packets: Vec<_> = packets
        .iter()
        .enumerate()
        .map(|(index, packet)| (1, index as u32 * 100, packet.as_slice()))
        .collect();
    fs::write(&input, classic_pcap_bytes(&capture_packets)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_dpp"));
    command.args(["--silent", "--threads", threads]);
    if fast_path {
        command.arg("--dns-wire-fast-path");
    }
    if full_fragments {
        command.arg("--full-fragments");
    }
    let result = command.arg(&input).arg(&output).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut rows: Vec<_> = csv::Reader::from_path(&output)
        .unwrap()
        .records()
        .map(|record| {
            let record = record.unwrap();
            (record[0].parse().unwrap(), record[1].parse().ok())
        })
        .collect();
    rows.sort_unstable();
    fs::remove_file(input).unwrap();
    fs::remove_file(output).unwrap();
    rows
}

#[test]
fn overlapping_dns_tuples_remain_isolated_by_full_vlan_stack() {
    for (left, right) in [
        (vec![(0x8100, 100)], vec![(0x8100, 200)]),
        (vec![], vec![(0x8100, 100)]),
        (vec![(0x8100, 100)], vec![(0x9100, 100)]),
        (
            vec![(0x88a8, 10), (0x8100, 100)],
            vec![(0x88a8, 20), (0x8100, 100)],
        ),
        (
            vec![(0x88a8, 10), (0x8100, 100)],
            vec![(0x88a8, 10), (0x8100, 200)],
        ),
    ] {
        for ipv6 in [false, true] {
            let packets = [
                dns_packet(false, ipv6, &left),
                dns_packet(false, ipv6, &right),
                dns_packet(true, ipv6, &right),
            ];
            for threads in ["1", "6"] {
                for fast_path in [false, true] {
                    assert_eq!(
                        output_timestamps(&packets, threads, fast_path, false),
                        [(1_000_000, None), (1_000_100, Some(1_000_200))],
                        "left={left:?}, right={right:?}, ipv6={ipv6}, threads={threads}, fast_path={fast_path}"
                    );
                }
            }
        }
    }
}

#[test]
fn vlan_priority_and_drop_eligibility_changes_preserve_matching() {
    for ipv6 in [false, true] {
        let packets = [
            dns_packet(false, ipv6, &[(0x88a8, 10), (0x8100, 100)]),
            dns_packet(true, ipv6, &[(0x88a8, 0xb00a), (0x8100, 0xf064)]),
        ];
        for threads in ["1", "6"] {
            for fast_path in [false, true] {
                assert_eq!(
                    output_timestamps(&packets, threads, fast_path, false),
                    [(1_000_000, Some(1_000_100))]
                );
            }
        }
    }
}

#[test]
fn reassembled_responses_keep_vlan_identity_despite_fragment_qos_changes() {
    const IP_OFFSET: usize = 14 + 8;
    const IP_HEADER_LEN: usize = 20;
    const FIRST_PAYLOAD_LEN: usize = 24;
    let query_one = dns_packet(false, false, &[(0x88a8, 10), (0x8100, 100)]);
    let query_two = dns_packet(false, false, &[(0x88a8, 20), (0x8100, 100)]);
    let response = dns_packet(true, false, &[(0x88a8, 20), (0x8100, 100)]);
    let split = IP_OFFSET + IP_HEADER_LEN + FIRST_PAYLOAD_LEN;
    let mut first = response[..split].to_vec();
    first[IP_OFFSET + 2..IP_OFFSET + 4]
        .copy_from_slice(&((IP_HEADER_LEN + FIRST_PAYLOAD_LEN) as u16).to_be_bytes());
    first[IP_OFFSET + 6..IP_OFFSET + 8].copy_from_slice(&0x2000_u16.to_be_bytes());
    let mut last = response[..IP_OFFSET + IP_HEADER_LEN].to_vec();
    last.extend_from_slice(&response[split..]);
    let last_ip_length = (last.len() - IP_OFFSET) as u16;
    last[IP_OFFSET + 2..IP_OFFSET + 4].copy_from_slice(&last_ip_length.to_be_bytes());
    last[IP_OFFSET + 6..IP_OFFSET + 8]
        .copy_from_slice(&((FIRST_PAYLOAD_LEN / 8) as u16).to_be_bytes());
    last[14..16].copy_from_slice(&0xb014_u16.to_be_bytes());
    last[18..20].copy_from_slice(&0xf064_u16.to_be_bytes());
    let packets = [query_one, query_two, first, last];
    for threads in ["1", "6"] {
        for fast_path in [false, true] {
            assert_eq!(
                output_timestamps(&packets, threads, fast_path, true),
                [(1_000_000, None), (1_000_100, Some(1_000_300))]
            );
        }
    }
}
