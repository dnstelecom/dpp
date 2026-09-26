/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

mod support;

use self::support::{
    classic_pcap_bytes, encode_dns_header, make_udp_dns_packet_with_payload, pcapng_bytes,
    temp_test_path,
};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::Command;
use std::process::Stdio;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use nix::poll::{PollFd, PollFlags, poll};
#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::Pid;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::process::Child;

fn dpp_binary() -> &'static str {
    env!("CARGO_BIN_EXE_dpp")
}

fn append_example_a_query(dns_payload: &mut Vec<u8>) {
    dns_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
}

fn append_repeated_byte_question(
    dns_payload: &mut Vec<u8>,
    labels: &[(usize, u8)],
    query_type: u16,
) {
    for &(label_len, byte) in labels {
        dns_payload.push(u8::try_from(label_len).expect("test label length fits into u8"));
        dns_payload.extend(std::iter::repeat_n(byte, label_len));
    }
    dns_payload.push(0);
    dns_payload.extend_from_slice(&query_type.to_be_bytes());
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
}

fn append_opt_record(dns_payload: &mut Vec<u8>, extended_high: u8, edns_version: u8) {
    dns_payload.push(0);
    dns_payload.extend_from_slice(&41_u16.to_be_bytes());
    dns_payload.extend_from_slice(&1232_u16.to_be_bytes());
    dns_payload.extend_from_slice(&[extended_high, edns_version, 0, 0]);
    dns_payload.extend_from_slice(&0_u16.to_be_bytes());
}

fn fragment_ipv4_udp_packet(packet: &[u8], first_payload_len: usize) -> (Vec<u8>, Vec<u8>) {
    const IPV4_START: usize = 14;
    const IPV4_HEADER_LEN: usize = 20;
    assert_eq!(
        first_payload_len % 8,
        0,
        "nonfinal fragment must be 8-byte aligned"
    );
    let first_end = IPV4_START + IPV4_HEADER_LEN + first_payload_len;
    assert!(first_end < packet.len(), "fixture needs a later fragment");

    let mut first_fragment = packet[..first_end].to_vec();
    first_fragment[IPV4_START + 2..IPV4_START + 4]
        .copy_from_slice(&((IPV4_HEADER_LEN + first_payload_len) as u16).to_be_bytes());
    first_fragment[IPV4_START + 4..IPV4_START + 6].copy_from_slice(&0x4321_u16.to_be_bytes());
    first_fragment[IPV4_START + 6..IPV4_START + 8].copy_from_slice(&0x2000_u16.to_be_bytes());

    let remaining_payload = &packet[first_end..];
    let mut later_fragment = packet[..IPV4_START + IPV4_HEADER_LEN].to_vec();
    later_fragment[IPV4_START + 2..IPV4_START + 4]
        .copy_from_slice(&((IPV4_HEADER_LEN + remaining_payload.len()) as u16).to_be_bytes());
    later_fragment[IPV4_START + 4..IPV4_START + 6].copy_from_slice(&0x4321_u16.to_be_bytes());
    later_fragment[IPV4_START + 6..IPV4_START + 8]
        .copy_from_slice(&((first_payload_len / 8) as u16).to_be_bytes());
    later_fragment.extend_from_slice(remaining_payload);

    (first_fragment, later_fragment)
}

#[cfg(unix)]
fn wait_for_child_exit(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child
            .try_wait()
            .expect("child status is available")
            .is_some()
        {
            return;
        }
        if Instant::now() >= deadline {
            child.kill().expect("stalled child is killed");
            child.wait().expect("killed child is reaped");
            panic!("DPP did not exit promptly after the termination signal");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn wait_for_output_creation(child: &mut Child, path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            child
                .try_wait()
                .expect("child status is available")
                .is_none(),
            "DPP exited before its output writer was created"
        );
        if Instant::now() >= deadline {
            child.kill().expect("stalled child is killed");
            child.wait().expect("killed child is reaped");
            panic!("DPP did not create its output writer");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn wait_for_stdin_start_log(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut logs = Vec::new();
    while !logs
        .windows(b"Starting to process PCAP stream from stdin".len())
        .any(|window| window == b"Starting to process PCAP stream from stdin")
    {
        if Instant::now() >= deadline {
            child.kill().expect("stalled child is killed");
            child.wait().expect("killed child is reaped");
            panic!("DPP did not reach stdin initialization");
        }
        let ready = {
            let stderr = child.stderr.as_ref().expect("stderr is piped");
            let mut fds = [PollFd::new(stderr.as_fd(), PollFlags::POLLIN)];
            poll(&mut fds, 100_u16).expect("stderr readiness is polled")
        };
        if ready != 0 {
            let mut buf = [0_u8; 2048];
            let read = child
                .stderr
                .as_mut()
                .expect("stderr is piped")
                .read(&mut buf)
                .expect("startup log is readable");
            assert_ne!(read, 0, "DPP exited before stdin initialization");
            logs.extend_from_slice(&buf[..read]);
        }
    }
}

#[cfg(unix)]
fn run_open_stdin_signal_test(
    name: &str,
    bytes: &[u8],
    signal: Signal,
    has_header: bool,
) -> Option<serde_json::Value> {
    let output_path = temp_test_path(name, "csv");
    let mut child = Command::new(dpp_binary())
        .args([
            "--report-format",
            if has_header { "json" } else { "text" },
            "-",
        ])
        .arg(&output_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("DPP starts");

    if !has_header {
        wait_for_stdin_start_log(&mut child);
    }
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(bytes).expect("capture bytes are written");
    if has_header {
        wait_for_output_creation(&mut child, &output_path);
    }
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        child
            .try_wait()
            .expect("child status is available")
            .is_none(),
        "DPP must still be waiting on the open stdin pipe"
    );

    kill(
        Pid::from_raw(i32::try_from(child.id()).expect("PID fits i32")),
        signal,
    )
    .expect("termination signal is sent");
    wait_for_child_exit(&mut child);
    let output = child.wait_with_output().expect("DPP output is collected");
    assert!(
        output.status.success(),
        "DPP did not shut down cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report = if has_header {
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON report parses");
        assert_eq!(
            report["warnings"]["graceful_signal_shutdown"],
            serde_json::json!(true)
        );
        assert_eq!(
            fs::read_to_string(&output_path).expect("CSV writer closed and flushed"),
            "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n"
        );
        fs::remove_file(&output_path).expect("remove output csv");
        Some(report)
    } else {
        assert!(
            output.stdout.is_empty(),
            "no summary exists before capture setup"
        );
        assert!(!output_path.exists(), "writer was not initialized");
        None
    };

    // Keep the parent end of the pipe open until after DPP exits. A closed pipe
    // would test EOF handling instead of signal cancellation.
    drop(stdin);
    report
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
fn ipv4_first_fragment_response_requires_opt_in_and_later_fragment_is_ignored() {
    let input_path = temp_test_path("first-fragment-response", "pcap");
    let default_output_path = temp_test_path("first-fragment-default", "csv");
    let fragment_output_path = temp_test_path("first-fragment-enabled", "csv");

    let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
    append_example_a_query(&mut query_payload);

    let mut response_payload = encode_dns_header(0x1234, 0x8180, 1);
    response_payload[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response_payload[10..12].copy_from_slice(&1_u16.to_be_bytes());
    append_example_a_query(&mut response_payload);
    // The answer starts in the first fragment and ends in the second one.
    response_payload.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
    // An OPT record beyond the first fragment can change the full RCODE.
    append_opt_record(&mut response_payload, 0, 0);

    let query_packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &query_payload);
    let response_packet = make_udp_dns_packet_with_payload(
        [8, 8, 8, 8],
        [10, 0, 0, 1],
        53,
        53_000,
        &response_payload,
    );
    let (first_fragment, later_fragment) = fragment_ipv4_udp_packet(&response_packet, 40);

    fs::write(
        &input_path,
        classic_pcap_bytes(&[
            (1, 0, &query_packet),
            (1, 200_000, &first_fragment),
            (1, 200_001, &later_fragment),
        ]),
    )
    .expect("fragmented test pcap written");

    let default_result = Command::new(dpp_binary())
        .arg("-s")
        .arg(&input_path)
        .arg(&default_output_path)
        .output()
        .expect("dpp executed without fragment mode");
    assert!(
        default_result.status.success(),
        "dpp failed: {}",
        String::from_utf8_lossy(&default_result.stderr)
    );
    assert_eq!(
        fs::read_to_string(&default_output_path).expect("default CSV readable"),
        concat!(
            "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n",
            "1000000,,10.0.0.1,53000,4660,example.com,A,\n"
        )
    );

    let fragment_result = Command::new(dpp_binary())
        .arg("-s")
        .arg("--allow-fragments")
        .arg(&input_path)
        .arg(&fragment_output_path)
        .output()
        .expect("dpp executed with fragment mode");
    assert!(
        fragment_result.status.success(),
        "dpp failed: {}",
        String::from_utf8_lossy(&fragment_result.stderr)
    );
    assert_eq!(
        fs::read_to_string(&fragment_output_path).expect("fragment CSV readable"),
        concat!(
            "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n",
            "1000000,1200000,10.0.0.1,53000,4660,example.com,A,\n"
        )
    );

    fs::remove_file(input_path).expect("remove input pcap");
    fs::remove_file(default_output_path).expect("remove default output csv");
    fs::remove_file(fragment_output_path).expect("remove fragment output csv");
}

#[test]
fn full_ipv4_fragment_reassembly_recovers_extended_response_code_once() {
    let input_path = temp_test_path("full-fragments-edns", "pcap");
    let output_path = temp_test_path("full-fragments-edns", "csv");

    let mut query_payload = encode_dns_header(0x2345, 0x0100, 1);
    query_payload[10..12].copy_from_slice(&1_u16.to_be_bytes());
    append_example_a_query(&mut query_payload);
    append_opt_record(&mut query_payload, 0, 0);

    let mut response_payload = encode_dns_header(0x2345, 0x8180, 1);
    response_payload[10..12].copy_from_slice(&1_u16.to_be_bytes());
    append_example_a_query(&mut response_payload);
    append_opt_record(&mut response_payload, 1, 0);

    let query_packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &query_payload);
    let response_packet = make_udp_dns_packet_with_payload(
        [8, 8, 8, 8],
        [10, 0, 0, 1],
        53,
        53_000,
        &response_payload,
    );
    // The first fragment contains the DNS header and question, but only the
    // beginning of the OPT record that carries the extended response code.
    let (first_fragment, later_fragment) = fragment_ipv4_udp_packet(&response_packet, 40);
    fs::write(
        &input_path,
        classic_pcap_bytes(&[
            (1, 0, &query_packet),
            (1, 200_000, &first_fragment),
            (1, 200_001, &later_fragment),
        ]),
    )
    .expect("fragmented EDNS test pcap written");

    let result = Command::new(dpp_binary())
        .arg("-s")
        .arg("--full-fragments")
        .arg(&input_path)
        .arg(&output_path)
        .output()
        .expect("dpp executed with full fragment reassembly");
    assert!(
        result.status.success(),
        "dpp failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_to_string(&output_path).expect("full fragment CSV readable"),
        concat!(
            "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n",
            "1000000,1200001,10.0.0.1,53000,9029,example.com,A,EDNS_BADVERS\n"
        )
    );

    fs::remove_file(input_path).expect("remove input pcap");
    fs::remove_file(output_path).expect("remove output csv");
}

#[test]
fn full_ipv4_reassembly_ignores_first_fragment_duplicate_after_completion() {
    let input_path = temp_test_path("full-fragments-duplicate-first", "pcap");
    let output_path = temp_test_path("full-fragments-duplicate-first", "csv");

    let mut query_payload = encode_dns_header(0x2345, 0x0100, 1);
    append_example_a_query(&mut query_payload);
    let mut response_payload = encode_dns_header(0x2345, 0x8180, 1);
    response_payload[10..12].copy_from_slice(&1_u16.to_be_bytes());
    append_example_a_query(&mut response_payload);
    append_opt_record(&mut response_payload, 1, 0);

    let query_packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &query_payload);
    let response_packet = make_udp_dns_packet_with_payload(
        [8, 8, 8, 8],
        [10, 0, 0, 1],
        53,
        53_000,
        &response_payload,
    );
    let (first_fragment, final_fragment) = fragment_ipv4_udp_packet(&response_packet, 40);
    fs::write(
        &input_path,
        classic_pcap_bytes(&[
            (1, 0, &query_packet),
            (1, 200_000, &first_fragment),
            (1, 200_001, &final_fragment),
            // The first transaction is already matched. A second query makes
            // an inferred response from the duplicate visible in the CSV.
            (1, 300_000, &query_packet),
            (1, 400_000, &first_fragment),
        ]),
    )
    .expect("fragmented duplicate test pcap written");

    let result = Command::new(dpp_binary())
        .args(["-s", "--full-fragments", "--report-format", "json"])
        .arg(&input_path)
        .arg(&output_path)
        .output()
        .expect("dpp executed with full fragment reassembly");
    assert!(
        result.status.success(),
        "dpp failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_to_string(&output_path).expect("duplicate fragment CSV readable"),
        concat!(
            "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n",
            "1000000,1200001,10.0.0.1,53000,9029,example.com,A,EDNS_BADVERS\n",
            "1300000,,10.0.0.1,53000,9029,example.com,A,\n"
        )
    );
    let report: serde_json::Value =
        serde_json::from_slice(&result.stdout).expect("JSON report parses");
    assert_eq!(report["metrics"]["total_dns_responses_processed"], 1);
    assert_eq!(report["metrics"]["fragmented_response_prefix_count"], 0);
    assert_eq!(report["metrics"]["total_matched_query_response_pairs"], 1);
    assert_eq!(report["metrics"]["timed_out_queries"], 1);

    fs::remove_file(input_path).expect("remove input pcap");
    fs::remove_file(output_path).expect("remove output csv");
}

#[test]
fn full_ipv4_fragment_mode_falls_back_to_first_fragment_at_eof() {
    let input_path = temp_test_path("full-fragments-incomplete", "pcap");
    let output_path = temp_test_path("full-fragments-incomplete", "csv");

    let mut query_payload = encode_dns_header(0x2345, 0x0100, 1);
    append_example_a_query(&mut query_payload);
    let mut response_payload = encode_dns_header(0x2345, 0x8180, 1);
    response_payload[10..12].copy_from_slice(&1_u16.to_be_bytes());
    append_example_a_query(&mut response_payload);
    append_opt_record(&mut response_payload, 1, 0);

    let query_packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &query_payload);
    let response_packet = make_udp_dns_packet_with_payload(
        [8, 8, 8, 8],
        [10, 0, 0, 1],
        53,
        53_000,
        &response_payload,
    );
    let (first_fragment, _missing_later_fragment) = fragment_ipv4_udp_packet(&response_packet, 40);
    fs::write(
        &input_path,
        classic_pcap_bytes(&[(1, 0, &query_packet), (1, 200_000, &first_fragment)]),
    )
    .expect("incomplete fragment pcap written");

    let result = Command::new(dpp_binary())
        .arg("-s")
        .arg("--full-fragments")
        .arg(&input_path)
        .arg(&output_path)
        .output()
        .expect("dpp executed with full fragment mode");
    assert!(
        result.status.success(),
        "dpp failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_to_string(&output_path).expect("incomplete fragment CSV readable"),
        concat!(
            "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n",
            "1000000,1200000,10.0.0.1,53000,9029,example.com,A,\n"
        )
    );

    fs::remove_file(input_path).expect("remove input pcap");
    fs::remove_file(output_path).expect("remove output csv");
}

#[test]
fn maximum_wire_qname_round_trips_with_full_escaped_presentation() {
    let input_path = temp_test_path("maximum-wire-qname", "pcap");
    let output_path = temp_test_path("maximum-wire-qname", "csv");
    let labels = [(63, 1), (63, 1), (63, 1), (61, 1)];

    let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
    append_repeated_byte_question(&mut query_payload, &labels, 1);
    let mut response_payload = encode_dns_header(0x1234, 0x8180, 1);
    append_repeated_byte_question(&mut response_payload, &labels, 1);

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
    let expected_name = [63_usize, 63, 63, 61]
        .map(|label_len| "\\001".repeat(label_len))
        .join(".");
    let csv_output = fs::read_to_string(&output_path).expect("csv output readable");
    let record = csv_output
        .lines()
        .nth(1)
        .expect("matched record is exported");
    assert!(record.contains(&expected_name));
    assert_eq!(expected_name.len(), 1003);
    assert_eq!(csv_output.lines().count(), 2);

    fs::remove_file(&input_path).expect("remove input pcap");
    fs::remove_file(&output_path).expect("remove output csv");
}

#[test]
fn oversized_wire_qname_is_rejected_and_reported() {
    let input_path = temp_test_path("oversized-wire-qname", "pcap");
    let output_path = temp_test_path("oversized-wire-qname", "csv");
    let mut dns_payload = encode_dns_header(0x1234, 0x0100, 1);
    append_repeated_byte_question(
        &mut dns_payload,
        &[(63, b'a'), (63, b'a'), (63, b'a'), (62, b'a')],
        1,
    );
    let packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &dns_payload);
    fs::write(&input_path, classic_pcap_bytes(&[(1, 0, &packet)])).expect("test pcap written");

    let output = Command::new(dpp_binary())
        .args(["--report-format", "json"])
        .arg(&input_path)
        .arg(&output_path)
        .output()
        .expect("dpp executed");

    assert!(
        output.status.success(),
        "dpp failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON report parses");
    assert_eq!(
        report["metrics"]["dns_messages_rejected_oversized_qname"],
        serde_json::json!(1)
    );
    assert_eq!(
        report["metrics"]["total_dns_queries_processed"],
        serde_json::json!(0)
    );
    let csv_output = fs::read_to_string(&output_path).expect("csv output readable");
    assert_eq!(csv_output.lines().count(), 1);

    fs::remove_file(&input_path).expect("remove input pcap");
    fs::remove_file(&output_path).expect("remove output csv");
}

#[test]
fn input_file_is_preserved_when_output_path_is_the_same_file() {
    let input_path = temp_test_path("same-input-output", "pcap");
    let input_bytes = classic_pcap_bytes(&[]);
    fs::write(&input_path, &input_bytes).expect("test pcap written");

    let output = Command::new(dpp_binary())
        .arg("-s")
        .arg(&input_path)
        .arg(&input_path)
        .output()
        .expect("dpp executed");

    assert!(!output.status.success(), "same input and output must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refer to the same file"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(&input_path).expect("input pcap remains readable"),
        input_bytes
    );

    fs::remove_file(input_path).expect("remove input pcap");
}

#[test]
fn midstream_capture_error_flushes_complete_partial_output() {
    let input_path = temp_test_path("midstream-error-input", "pcap");
    let output_path = temp_test_path("midstream-error-output", "csv");

    let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
    append_example_a_query(&mut query_payload);
    let mut response_payload = query_payload.clone();
    response_payload[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());

    let query_packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &query_payload);
    let response_packet = make_udp_dns_packet_with_payload(
        [8, 8, 8, 8],
        [10, 0, 0, 1],
        53,
        53_000,
        &response_payload,
    );
    let non_dns_packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 123, &[0_u8; 12]);

    // The fixture fills the current ingest batch before the following malformed record is read.
    let mut packets = Vec::with_capacity(65_536);
    packets.push((1, 0, query_packet.as_slice()));
    packets.push((1, 200_000, response_packet.as_slice()));
    packets.push((2, 0, query_packet.as_slice()));
    packets.extend(std::iter::repeat_n(
        (3, 0, non_dns_packet.as_slice()),
        65_536 - packets.len(),
    ));

    let mut capture = classic_pcap_bytes(&packets);
    capture.extend_from_slice(&4_u32.to_le_bytes());
    capture.extend_from_slice(&0_u32.to_le_bytes());
    capture.extend_from_slice(&64_u32.to_le_bytes());
    capture.extend_from_slice(&64_u32.to_le_bytes());
    capture.extend_from_slice(&[0_u8; 3]);
    fs::write(&input_path, capture).expect("truncated pcap written");

    let output = Command::new(dpp_binary())
        .arg("-s")
        .arg(&input_path)
        .arg(&output_path)
        .output()
        .expect("dpp executed");

    assert!(!output.status.success(), "truncated capture must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("DNS processing failed"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&output_path).expect("partial CSV is readable"),
        concat!(
            "request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code\n",
            "1000000,1200000,10.0.0.1,53000,4660,example.com,A,No Error\n"
        )
    );

    fs::remove_file(input_path).expect("remove input pcap");
    fs::remove_file(output_path).expect("remove output csv");
}

#[test]
fn invalid_capture_header_does_not_create_output() {
    let input_path = temp_test_path("invalid-header-input", "pcap");
    let output_path = temp_test_path("invalid-header-output", "csv");
    fs::write(&input_path, [0_u8; 3]).expect("invalid pcap written");

    let output = Command::new(dpp_binary())
        .arg("-s")
        .arg(&input_path)
        .arg(&output_path)
        .output()
        .expect("dpp executed");

    assert!(!output.status.success(), "invalid capture must fail");
    assert!(
        !output_path.exists(),
        "output must not be created before capture initialization succeeds"
    );

    fs::remove_file(input_path).expect("remove input pcap");
}

#[test]
fn edns_badvers_round_trips_without_tsig_failure_report_label() {
    let input_path = temp_test_path("edns-badvers-response", "pcap");
    let output_path = temp_test_path("edns-badvers-response", "csv");

    let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
    query_payload[10..12].copy_from_slice(&1_u16.to_be_bytes());
    append_example_a_query(&mut query_payload);
    append_opt_record(&mut query_payload, 0, 255);

    let mut response_payload = encode_dns_header(0x1234, 0x8180, 1);
    response_payload[10..12].copy_from_slice(&1_u16.to_be_bytes());
    append_example_a_query(&mut response_payload);
    append_opt_record(&mut response_payload, 1, 0);

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
    assert!(csv_output.contains(",EDNS_BADVERS\n"));
    assert!(!csv_output.contains("TSIG Failure"));

    fs::remove_file(&input_path).expect("remove input pcap");
    fs::remove_file(&output_path).expect("remove output csv");
}

#[test]
fn stdin_stream_round_trips_to_exact_csv_record() {
    let output_path = temp_test_path("stdin-query-response", "csv");

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
    let input_bytes = classic_pcap_bytes(&[(1, 0, &query_packet), (1, 200_000, &response_packet)]);

    let mut child = Command::new(dpp_binary())
        .arg("-s")
        .arg("-")
        .arg(&output_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("dpp executed");

    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(&input_bytes)
        .expect("pcap stream written");

    let output = child.wait_with_output().expect("dpp exits");
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

    fs::remove_file(&output_path).expect("remove output csv");
}

#[test]
fn stdin_pcapng_stream_round_trips_to_exact_csv_record() {
    let output_path = temp_test_path("stdin-pcapng-query-response", "csv");

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
    let input_bytes = pcapng_bytes(&[(1_000_000, &query_packet), (1_200_000, &response_packet)]);

    let mut child = Command::new(dpp_binary())
        .arg("-s")
        .arg("-")
        .arg(&output_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("dpp executed");

    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(&input_bytes)
        .expect("pcapng stream written");

    let output = child.wait_with_output().expect("dpp exits");
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

    fs::remove_file(&output_path).expect("remove output csv");
}

#[cfg(unix)]
#[test]
fn sigint_stops_classic_pcap_stdin_without_eof() {
    let mut dns_payload = encode_dns_header(0x1234, 0x0100, 1);
    append_example_a_query(&mut dns_payload);
    let packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &dns_payload);
    let bytes = classic_pcap_bytes(&[(1, 0, &packet)]);
    let _ = run_open_stdin_signal_test("sigint-classic-open-pipe", &bytes, Signal::SIGINT, true);
}

#[cfg(unix)]
#[test]
fn sigint_processes_completed_packets_in_partial_stdin_batch() {
    let mut query_payload = encode_dns_header(0x1234, 0x0100, 1);
    append_example_a_query(&mut query_payload);
    let mut response_payload = encode_dns_header(0x1234, 0x8180, 1);
    append_example_a_query(&mut response_payload);
    let query =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &query_payload);
    let response = make_udp_dns_packet_with_payload(
        [8, 8, 8, 8],
        [10, 0, 0, 1],
        53,
        53_000,
        &response_payload,
    );
    let bytes = classic_pcap_bytes(&[(1, 0, &query), (1, 200_000, &response)]);

    let report =
        run_open_stdin_signal_test("sigint-partial-stdin-batch", &bytes, Signal::SIGINT, true)
            .expect("signal report exists");
    assert_eq!(report["metrics"]["total_packets_processed"], 2);
    assert_eq!(report["metrics"]["total_dns_queries_processed"], 1);
    assert_eq!(report["metrics"]["total_dns_responses_processed"], 1);
    assert_eq!(report["metrics"]["total_matched_query_response_pairs"], 1);
}

#[cfg(unix)]
#[test]
fn sigint_stops_pcapng_stdin_mid_block_without_eof() {
    let mut dns_payload = encode_dns_header(0x1234, 0x0100, 1);
    append_example_a_query(&mut dns_payload);
    let packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &dns_payload);
    let mut bytes = pcapng_bytes(&[(1_000_000, &packet)]);
    // A complete next block prefix declares a body that never arrives. This
    // exercises read_exact/read_to_end cancellation while stdin stays open.
    bytes.extend_from_within(..12);
    let _ = run_open_stdin_signal_test("sigint-pcapng-mid-block", &bytes, Signal::SIGINT, true);
}

#[cfg(unix)]
#[test]
fn sigterm_stops_classic_pcap_stdin_mid_record_without_eof() {
    let mut dns_payload = encode_dns_header(0x1234, 0x0100, 1);
    append_example_a_query(&mut dns_payload);
    let packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &dns_payload);
    let mut bytes = classic_pcap_bytes(&[(1, 0, &packet)]);
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&64_u32.to_le_bytes());
    bytes.extend_from_slice(&64_u32.to_le_bytes());
    bytes.extend_from_slice(&[0_u8; 3]);
    let _ = run_open_stdin_signal_test("sigterm-classic-mid-record", &bytes, Signal::SIGTERM, true);
}

#[cfg(unix)]
#[test]
fn sigint_stops_stdin_probe_before_capture_header_without_eof() {
    let _ = run_open_stdin_signal_test(
        "sigint-before-capture-header",
        &[0xd4, 0xc3, 0xb2],
        Signal::SIGINT,
        false,
    );
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

#[test]
fn unknown_protocol_values_round_trip_through_csv_and_parquet() {
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use parquet::record::RowAccessor;

    let input_path = temp_test_path("unknown-protocol-values", "pcap");
    let mut frames = Vec::new();
    for (id, query_type, response_code) in [(1_u16, 65400_u16, 64_u16), (2, 65401, 65)] {
        let mut query = encode_dns_header(id, 0x0100, 1);
        append_example_a_query(&mut query);
        let type_offset = query.len() - 4;
        query[type_offset..type_offset + 2].copy_from_slice(&query_type.to_be_bytes());
        let mut response = query.clone();
        response[2..4].copy_from_slice(&(0x8180 | (response_code & 0xf)).to_be_bytes());
        response[10..12].copy_from_slice(&1_u16.to_be_bytes());
        append_opt_record(&mut response, (response_code >> 4) as u8, 0);
        frames.push(make_udp_dns_packet_with_payload(
            [10, 0, 0, 1],
            [8, 8, 8, 8],
            53000,
            53,
            &query,
        ));
        frames.push(make_udp_dns_packet_with_payload(
            [8, 8, 8, 8],
            [10, 0, 0, 1],
            53,
            53000,
            &response,
        ));
    }
    let packets: Vec<_> = frames
        .iter()
        .enumerate()
        .map(|(index, frame)| (1, index as u32 * 10_000, frame.as_slice()))
        .collect();
    fs::write(&input_path, classic_pcap_bytes(&packets)).expect("writes capture");

    for fast in [false, true] {
        for format in ["csv", "parquet"] {
            let output_path = temp_test_path("unknown-protocol-values", format);
            let mut command = Command::new(dpp_binary());
            command.args(["-s", "-f", format]);
            if fast {
                command.arg("--dns-wire-fast-path");
            }
            let output = command
                .arg(&input_path)
                .arg(&output_path)
                .output()
                .expect("runs dpp");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let values: Vec<(String, String)> = if format == "csv" {
                csv::Reader::from_path(&output_path)
                    .expect("opens csv")
                    .records()
                    .map(|row| {
                        let row = row.expect("reads row");
                        (row[6].to_owned(), row[7].to_owned())
                    })
                    .collect()
            } else {
                SerializedFileReader::new(fs::File::open(&output_path).expect("opens parquet"))
                    .expect("reads parquet")
                    .get_row_iter(None)
                    .expect("reads rows")
                    .map(|row| {
                        let row = row.expect("reads row");
                        (
                            row.get_string(6).unwrap().clone(),
                            row.get_string(7).unwrap().clone(),
                        )
                    })
                    .collect()
            };
            assert_eq!(
                values,
                vec![
                    ("TYPE65400".to_owned(), "64".to_owned()),
                    ("TYPE65401".to_owned(), "65".to_owned())
                ],
                "fast={fast}, format={format}"
            );
            fs::remove_file(output_path).expect("removes output");
        }
    }
    fs::remove_file(input_path).expect("removes input");
}
