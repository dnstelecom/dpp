/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::catalog::SERVER1_JUL_2024_POSITIVE_DOMAINS;
use crate::cli::{Cli, GeneratorConfig, ProfileKind};
use crate::error::Error;
use crate::generator::write_capture;
use crate::model::{DEFAULT_START_EPOCH_SECS, DnsQuestionType, ResponseCodeKind};
use crate::packet::{
    MAX_SYNTHETIC_CLIENTS, ROOT_NAME_SERVER_TARGETS, build_dns_query_payload,
    build_dns_response_payload,
};
use crate::profile::{
    is_disallowed_domain, profile_for, qtype_weights_for_positive_domain, validate_profile,
};
use pcap_file::pcap::PcapReader;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::Duration;

fn test_config() -> GeneratorConfig {
    GeneratorConfig {
        transactions: 24,
        qps: 100.0,
        clients: 12,
        resolvers: 3,
        duplicate_rate: 0.4,
        timeout_rate: 0.2,
        duplicate_max: 3,
        seed: 7,
        start_epoch_seconds: DEFAULT_START_EPOCH_SECS,
    }
}

#[test]
fn catalog_exposes_large_domain_set() {
    assert_eq!(SERVER1_JUL_2024_POSITIVE_DOMAINS.len(), 10_000);
}

#[test]
fn sanitized_profile_contains_no_disallowed_domains() {
    let profile = profile_for(ProfileKind::Server1Jul2024Sanitized);
    validate_profile(&profile).expect("profile must validate");

    for domain in profile.positive_domains {
        assert!(
            !is_disallowed_domain(domain.name),
            "domain '{}' must stay sanitized",
            domain.name
        );
    }
}

#[test]
fn disallowed_domain_detector_catches_only_current_sanitization_targets() {
    assert!(is_disallowed_domain("android.clients.google.com"));
    assert!(!is_disallowed_domain("www.google.com"));
}

#[test]
fn root_domain_is_allowed_and_forces_ns_queries() {
    assert!(!is_disallowed_domain("."));

    let weights = qtype_weights_for_positive_domain(".");
    assert_eq!(weights.len(), 1);
    assert_eq!(weights[0].qtype, DnsQuestionType::Ns);
    assert_eq!(weights[0].weight, 100);
}

#[test]
fn root_domain_serializes_as_valid_ns_query_and_response() {
    let query = build_dns_query_payload(0x1234, ".", DnsQuestionType::Ns).expect("query encodes");
    assert_eq!(query[12], 0);
    assert_eq!(&query[13..15], &2_u16.to_be_bytes());

    let response = build_dns_response_payload(
        0x1234,
        ".",
        DnsQuestionType::Ns,
        ResponseCodeKind::NoError,
        3,
    )
    .expect("response encodes");
    assert_eq!(&response[6..8], &1_u16.to_be_bytes());
    assert_eq!(response[12], 0);
}

#[test]
fn root_name_server_targets_match_the_current_a_to_m_root_set() {
    assert_eq!(
        ROOT_NAME_SERVER_TARGETS,
        &[
            "a.root-servers.net",
            "b.root-servers.net",
            "c.root-servers.net",
            "d.root-servers.net",
            "e.root-servers.net",
            "f.root-servers.net",
            "g.root-servers.net",
            "h.root-servers.net",
            "i.root-servers.net",
            "j.root-servers.net",
            "k.root-servers.net",
            "l.root-servers.net",
            "m.root-servers.net",
        ]
    );
}

#[test]
fn cli_rejects_client_count_above_address_pool_capacity() {
    let cli = Cli {
        output: PathBuf::from("ignored.pcap"),
        profile: ProfileKind::Server1Jul2024Sanitized,
        transactions: Some(1),
        duration_seconds: 300,
        qps: 1200.0,
        clients: MAX_SYNTHETIC_CLIENTS + 1,
        resolvers: 3,
        duplicate_rate: 0.08,
        timeout_rate: 0.03,
        duplicate_max: 3,
        seed: 7,
        start_epoch_seconds: DEFAULT_START_EPOCH_SECS,
    };

    assert!(matches!(
        GeneratorConfig::try_from(&cli),
        Err(Error::TooManyClients { value, max })
            if value == MAX_SYNTHETIC_CLIENTS + 1 && max == MAX_SYNTHETIC_CLIENTS
    ));
}

#[test]
fn disallowed_domain_detector_preserves_case_insensitive_behavior() {
    assert!(is_disallowed_domain("Android.Clients.Google.com"));
    assert!(!is_disallowed_domain("WWW.Google.com"));
}

#[test]
fn qtype_classifier_preserves_case_insensitive_behavior() {
    assert!(std::ptr::eq(
        qtype_weights_for_positive_domain("WWW.Example.com"),
        qtype_weights_for_positive_domain("www.example.com")
    ));
    assert!(std::ptr::eq(
        qtype_weights_for_positive_domain("Api.Googleapis.com"),
        qtype_weights_for_positive_domain("api.googleapis.com")
    ));
}

#[test]
fn generator_produces_reproducible_output_for_same_seed() {
    let config = test_config();
    let profile = profile_for(ProfileKind::Server1Jul2024Sanitized);

    let writer_one = Cursor::new(Vec::new());
    let writer_two = Cursor::new(Vec::new());

    let (writer_one, summary_one) =
        write_capture(writer_one, &config, &profile).expect("first capture");
    let (writer_two, summary_two) =
        write_capture(writer_two, &config, &profile).expect("second capture");

    assert_eq!(summary_one, summary_two);
    assert_eq!(writer_one.into_inner(), writer_two.into_inner());
}

#[test]
fn forced_timeouts_and_duplicates_are_reflected_in_summary() {
    let mut config = test_config();
    config.transactions = 16;
    config.duplicate_rate = 1.0;
    config.timeout_rate = 1.0;
    config.duplicate_max = 2;

    let profile = profile_for(ProfileKind::Server1Jul2024Sanitized);
    let writer = Cursor::new(Vec::new());
    let (_, summary) = write_capture(writer, &config, &profile).expect("capture writes");

    assert_eq!(summary.logical_transactions, 16);
    assert_eq!(summary.response_packets, 0);
    assert_eq!(summary.timed_out_transactions, 16);
    assert!(summary.duplicate_query_packets >= 16);
    assert_eq!(
        summary.query_packets,
        summary.logical_transactions + summary.duplicate_query_packets
    );
}

#[test]
fn generated_pcap_round_trips_packet_count_and_timestamp_order() {
    let config = test_config();
    let profile = profile_for(ProfileKind::Server1Jul2024Sanitized);
    let writer = Cursor::new(Vec::new());
    let (writer, summary) = write_capture(writer, &config, &profile).expect("capture writes");

    let bytes = writer.into_inner();
    let mut reader = PcapReader::new(Cursor::new(bytes)).expect("pcap reader opens");
    let mut packet_count = 0_u64;
    let mut last_timestamp = Duration::ZERO;

    while let Some(packet) = reader.next_packet() {
        let packet = packet.expect("packet decodes");
        assert!(packet.timestamp >= last_timestamp);
        last_timestamp = packet.timestamp;
        packet_count += 1;
    }

    assert_eq!(packet_count, summary.total_packets());
}
