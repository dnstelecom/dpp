/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

mod support;

use self::support::{
    classic_pcap_bytes, encode_dns_header, make_udp_dns_packet_with_payload, temp_test_path,
};
use std::fs;
use std::io::{BufRead, BufReader};
use std::process::Command;
use std::process::Stdio;

fn dpp_binary() -> &'static str {
    env!("CARGO_BIN_EXE_dpp")
}

#[test]
fn matched_query_response_pair_round_trips_to_exact_csv_record() {
    let input_path = temp_test_path("matched-query-response", "pcap");
    let output_path = temp_test_path("matched-query-response", "csv");

    let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
    query_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    query_payload.extend_from_slice(&1_u16.to_be_bytes());
    query_payload.extend_from_slice(&1_u16.to_be_bytes());

    let mut response_payload = encode_dns_header(0x1234, 0x8180, 1);
    response_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    response_payload.extend_from_slice(&1_u16.to_be_bytes());
    response_payload.extend_from_slice(&1_u16.to_be_bytes());

    let query_packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &query_payload);
    let response_packet = make_udp_dns_packet_with_payload(
        [8, 8, 8, 8],
        [10, 0, 0, 1],
        53,
        53_000,
        &response_payload,
    );

    fs::write(
        &input_path,
        classic_pcap_bytes(&[(1, 0, &query_packet), (1, 200_000, &response_packet)]),
    )
    .expect("test pcap written");

    let output = Command::new(dpp_binary())
        .arg("-s")
        .arg(&input_path)
        .arg(&output_path)
        .output()
        .expect("dpp executed");

    assert!(
        output.status.success(),
        "dpp failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let csv_output = fs::read_to_string(&output_path).expect("csv output readable");
    assert_eq!(
        csv_output,
        concat!(
            "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n",
            "1000000,1200000,10.0.0.1,53000,4660,example.com,A,No Error\n"
        )
    );

    fs::remove_file(&input_path).expect("remove input pcap");
    fs::remove_file(&output_path).expect("remove output csv");
}

#[test]
fn unmatched_query_finalizes_to_timeout_record_in_completed_run() {
    let input_path = temp_test_path("timeout-query", "pcap");
    let output_path = temp_test_path("timeout-query", "csv");

    let mut query_payload = encode_dns_header(0xBEEF, 0x0100, 1);
    query_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'o', b'r', b'g', 0,
    ]);
    query_payload.extend_from_slice(&1_u16.to_be_bytes());
    query_payload.extend_from_slice(&1_u16.to_be_bytes());

    let query_packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 2], [1, 1, 1, 1], 53_001, 53, &query_payload);

    fs::write(
        &input_path,
        classic_pcap_bytes(&[(2, 500_000, &query_packet)]),
    )
    .expect("test pcap written");

    let output = Command::new(dpp_binary())
        .arg("-s")
        .arg(&input_path)
        .arg(&output_path)
        .output()
        .expect("dpp executed");

    assert!(
        output.status.success(),
        "dpp failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let csv_output = fs::read_to_string(&output_path).expect("csv output readable");
    assert_eq!(
        csv_output,
        concat!(
            "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n",
            "2500000,,10.0.0.2,53001,48879,example.org,A,\n"
        )
    );

    fs::remove_file(&input_path).expect("remove input pcap");
    fs::remove_file(&output_path).expect("remove output csv");
}

#[test]
fn stdout_broken_pipe_exits_quietly() {
    let input_path = temp_test_path("stdout-broken-pipe", "pcap");

    let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
    query_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    query_payload.extend_from_slice(&1_u16.to_be_bytes());
    query_payload.extend_from_slice(&1_u16.to_be_bytes());

    let mut response_payload = encode_dns_header(0x1234, 0x8180, 1);
    response_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    response_payload.extend_from_slice(&1_u16.to_be_bytes());
    response_payload.extend_from_slice(&1_u16.to_be_bytes());

    let query_packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &query_payload);
    let response_packet = make_udp_dns_packet_with_payload(
        [8, 8, 8, 8],
        [10, 0, 0, 1],
        53,
        53_000,
        &response_payload,
    );

    fs::write(
        &input_path,
        classic_pcap_bytes(&[(1, 0, &query_packet), (1, 200_000, &response_packet)]),
    )
    .expect("test pcap written");

    let mut child = Command::new(dpp_binary())
        .arg("-s")
        .arg(&input_path)
        .arg("-")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("dpp executed");

    let stdout = child.stdout.take().expect("stdout is piped");
    let mut reader = BufReader::new(stdout);
    let mut header = String::new();
    reader.read_line(&mut header).expect("header is readable");
    assert!(header.starts_with("request_timestamp,response_timestamp"));
    drop(reader);

    let output = child.wait_with_output().expect("dpp exits");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "dpp failed: {stderr}");
    assert!(
        !stderr.contains("Broken pipe"),
        "unexpected stderr: {stderr}"
    );

    fs::remove_file(&input_path).expect("remove input pcap");
}

#[test]
fn closed_stderr_does_not_abort_file_output() {
    let input_path = temp_test_path("stderr-broken-pipe", "pcap");
    let output_path = temp_test_path("stderr-broken-pipe", "csv");

    let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
    query_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    query_payload.extend_from_slice(&1_u16.to_be_bytes());
    query_payload.extend_from_slice(&1_u16.to_be_bytes());

    let mut response_payload = encode_dns_header(0x1234, 0x8180, 1);
    response_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    response_payload.extend_from_slice(&1_u16.to_be_bytes());
    response_payload.extend_from_slice(&1_u16.to_be_bytes());

    let query_packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &query_payload);
    let response_packet = make_udp_dns_packet_with_payload(
        [8, 8, 8, 8],
        [10, 0, 0, 1],
        53,
        53_000,
        &response_payload,
    );

    fs::write(
        &input_path,
        classic_pcap_bytes(&[(1, 0, &query_packet), (1, 200_000, &response_packet)]),
    )
    .expect("test pcap written");

    let mut child = Command::new(dpp_binary())
        .arg(&input_path)
        .arg(&output_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("dpp executed");

    drop(child.stderr.take().expect("stderr is piped"));

    let status = child.wait().expect("dpp exits");
    assert!(status.success(), "dpp failed with closed stderr");

    let csv_output = fs::read_to_string(&output_path).expect("csv output readable");
    assert!(csv_output.contains("1000000,1200000,10.0.0.1,53000,4660,example.com,A,No Error"));

    fs::remove_file(&input_path).expect("remove input pcap");
    fs::remove_file(&output_path).expect("remove output csv");
}
