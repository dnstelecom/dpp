/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::artifact::load_profile_dir as load_profile_dir_artifact;
use crate::catalog::load_catalog;
use crate::cli::{Cli, GeneratorConfig};
use crate::error::Error;
use crate::generator::write_capture;
use crate::model::{DEFAULT_START_EPOCH_SECS, DnsQuestionType, ResponseCodeKind};
use crate::packet::{
    MAX_SYNTHETIC_CLIENTS, ROOT_NAME_SERVER_TARGETS, build_dns_query_payload,
    build_dns_response_payload,
};
use crate::profile::{is_disallowed_domain, validate_profile};
use crate::load_profile_dir as load_runtime_profile_dir;
use pcap_file::pcap::PcapReader;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn temp_profile_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "dns-pcap-generator-{name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("temp profile dir created");
    path
}

fn write_profile_fixture(dir: &std::path::Path) {
    let catalog_bytes = b"10\texample.com\n8\twww.example.org\n";
    fs::write(dir.join("catalog_data.tsv"), catalog_bytes).expect("catalog fixture written");
    let catalog_sha256 = format!("{:x}", Sha256::digest(catalog_bytes));
    fs::write(
        dir.join("fitted-generator.toml"),
        format!(
            r#"
schema_version = 1
profile_name = "fixture-profile"
catalog_path = "catalog_data.tsv"
catalog_sha256 = "{catalog_sha256}"

[generation_defaults]
qps = 4321.0
clients = 128
resolvers = 4
duplicate_max = 2

[latent]
logical_timeout_rate = 0.041
duplicate_transaction_rate = 0.123

[query_types]
positive = [
  {{ qtype = "A", weight = 700 }},
  {{ qtype = "AAAA", weight = 200 }},
  {{ qtype = "HTTPS", weight = 100 }},
]
negative = [
  {{ qtype = "A", weight = 700 }},
  {{ qtype = "AAAA", weight = 200 }},
  {{ qtype = "HTTPS", weight = 100 }},
]
reverse = [
  {{ qtype = "PTR", weight = 1000 }},
]
root = [
  {{ qtype = "NS", weight = 1000 }},
]

[duplicate_model]
retry_count_weights = [
  {{ retry_count = 1, weight = 800 }},
  {{ retry_count = 2, weight = 200 }},
]

[response_codes]
formerr = 1
noerror = 976
nxdomain = 17
notimp = 1
refused = 2
servfail = 3

[response_delay]
unit = "us"

[response_delay.normal]
buckets = [
  {{ name = "fast", share_per_mille = 900, range_us = [10, 20] }},
  {{ name = "tail", share_per_mille = 100, range_us = [21, 30] }},
]

[response_delay.servfail]
buckets = [
  {{ name = "fast", share_per_mille = 1000, range_us = [50, 60] }},
]

[retry_delay]
answered_steps = [
  {{ step = 1, range_us = [100, 200] }},
  {{ step = 2, range_us = [300, 400] }},
]
unanswered_steps = [
  {{ step = 1, range_us = [50000, 60000] }},
  {{ step = 2, range_us = [70000, 80000] }},
]
"#
        ),
    )
    .expect("fitted profile fixture written");
}

fn checked_in_profile_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("profiles/server1-jul-2024")
}

#[test]
fn catalog_exposes_large_domain_set() {
    let domains =
        load_catalog(include_str!("../catalog_data.tsv")).expect("workspace catalog must decode");
    assert_eq!(domains.len(), 10_000);
}

#[test]
fn sanitized_profile_contains_no_disallowed_domains() {
    let profile =
        load_profile_dir_artifact(&checked_in_profile_dir()).expect("checked-in profile loads");
    validate_profile(&profile).expect("profile must validate");

    for domain in profile.positive_domains {
        assert!(
            !is_disallowed_domain(domain.name.as_ref()),
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
fn ptr_query_serializes_as_valid_query_and_response() {
    let qname = "4.0.41.198.in-addr.arpa";
    let query =
        build_dns_query_payload(0x4321, qname, DnsQuestionType::Ptr).expect("query encodes");
    assert_eq!(
        &query[query.len() - 4..query.len() - 2],
        &12_u16.to_be_bytes()
    );

    let response = build_dns_response_payload(
        0x4321,
        qname,
        DnsQuestionType::Ptr,
        ResponseCodeKind::NoError,
        7,
    )
    .expect("response encodes");
    assert_eq!(&response[6..8], &1_u16.to_be_bytes());
    assert_eq!(
        &response[query.len()..query.len() + 2],
        &0xc00c_u16.to_be_bytes()
    );
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
        profile_dir: PathBuf::from("fixture-profile"),
        transactions: Some(1),
        duration_seconds: Some(300),
        qps: Some(1200.0),
        clients: Some(MAX_SYNTHETIC_CLIENTS + 1),
        resolvers: Some(3),
        seed: 7,
        start_epoch_seconds: DEFAULT_START_EPOCH_SECS,
    };

    assert!(matches!(
        GeneratorConfig::from_cli(
            &cli,
            &crate::model::ProfileGenerationDefaults {
                qps: 1200.0,
                clients: 2048,
                resolvers: 3,
                duplicate_rate: 0.08,
                timeout_rate: 0.03,
                duplicate_max: 3,
            },
            "fixture-profile"
        ),
        Err(Error::TooManyClients { value, max })
            if value == MAX_SYNTHETIC_CLIENTS + 1 && max == MAX_SYNTHETIC_CLIENTS
    ));
}

#[test]
fn profile_dir_loader_applies_fitted_defaults() {
    let dir = temp_profile_dir("defaults");
    write_profile_fixture(&dir);

    let profile = load_profile_dir_artifact(&dir).expect("profile dir loads");
    let cli = Cli {
        output: PathBuf::from("ignored.pcap"),
        profile_dir: dir.clone(),
        transactions: Some(1),
        duration_seconds: None,
        qps: None,
        clients: None,
        resolvers: None,
        seed: 7,
        start_epoch_seconds: DEFAULT_START_EPOCH_SECS,
    };

    let config = GeneratorConfig::from_cli(&cli, &profile.generation_defaults, &profile.name)
        .expect("config resolves");

    assert_eq!(profile.name, "fixture-profile");
    assert_eq!(profile.positive_domains.len(), 2);
    assert_eq!(config.qps, 4321.0);
    assert_eq!(config.clients, 128);
    assert_eq!(config.resolvers, 4);
    assert_eq!(config.duplicate_rate, 0.123);
    assert_eq!(config.timeout_rate, 0.041);
    assert_eq!(config.duplicate_max, 2);

    fs::remove_dir_all(dir).expect("temp profile dir removed");
}

#[test]
fn profile_dir_loader_rejects_catalog_hash_mismatch() {
    let dir = temp_profile_dir("catalog-hash-mismatch");
    write_profile_fixture(&dir);
    let catalog_sha256 = format!("{:x}", Sha256::digest(b"10\texample.com\n8\twww.example.org\n"));

    let fitted_path = dir.join("fitted-generator.toml");
    let fitted = fs::read_to_string(&fitted_path).expect("fitted profile read");
    fs::write(
        &fitted_path,
        fitted.replace(
            &format!("catalog_sha256 = \"{catalog_sha256}\""),
            "catalog_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
        ),
    )
    .expect("fitted profile rewritten");

    let error = load_profile_dir_artifact(&dir).expect_err("catalog hash mismatch must fail");
    assert!(matches!(error, Error::CatalogHashMismatch { .. }));

    fs::remove_dir_all(dir).expect("temp profile dir removed");
}

#[test]
fn runtime_profile_dir_loader_accepts_small_extracted_catalogs() {
    let dir = temp_profile_dir("runtime-small-catalog");
    write_profile_fixture(&dir);

    let profile = load_runtime_profile_dir(&dir).expect("runtime profile dir loads");

    assert_eq!(crate::profile_name(&profile), "fixture-profile");
    assert_eq!(
        crate::profile_generation_defaults(&profile).duplicate_max,
        2
    );

    fs::remove_dir_all(dir).expect("temp profile dir removed");
}

#[test]
fn checked_in_server1_profile_dir_loads_against_workspace_catalog() {
    let profile = load_runtime_profile_dir(&checked_in_profile_dir())
        .expect("checked-in profile dir loads");

    assert_eq!(crate::profile_name(&profile), "server1-jul-2024");
    assert_eq!(
        crate::profile_generation_defaults(&profile).duplicate_max,
        16
    );
}

#[test]
fn disallowed_domain_detector_preserves_case_insensitive_behavior() {
    assert!(is_disallowed_domain("Android.Clients.Google.com"));
    assert!(!is_disallowed_domain("WWW.Google.com"));
}

#[test]
fn generator_produces_reproducible_output_for_same_seed() {
    let config = test_config();
    let dir = temp_profile_dir("reproducible-output");
    write_profile_fixture(&dir);
    let profile = load_profile_dir_artifact(&dir).expect("fixture profile loads");

    let writer_one = Cursor::new(Vec::new());
    let writer_two = Cursor::new(Vec::new());

    let (writer_one, summary_one) =
        write_capture(writer_one, &config, &profile).expect("first capture");
    let (writer_two, summary_two) =
        write_capture(writer_two, &config, &profile).expect("second capture");

    assert_eq!(summary_one, summary_two);
    assert_eq!(writer_one.into_inner(), writer_two.into_inner());

    fs::remove_dir_all(dir).expect("temp profile dir removed");
}

#[test]
fn forced_timeouts_and_duplicates_are_reflected_in_summary() {
    let mut config = test_config();
    config.transactions = 16;
    config.duplicate_rate = 1.0;
    config.timeout_rate = 1.0;
    config.duplicate_max = 2;

    let dir = temp_profile_dir("forced-timeouts");
    write_profile_fixture(&dir);
    let profile = load_profile_dir_artifact(&dir).expect("fixture profile loads");
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

    fs::remove_dir_all(dir).expect("temp profile dir removed");
}

#[test]
fn generated_pcap_round_trips_packet_count_and_timestamp_order() {
    let config = test_config();
    let dir = temp_profile_dir("roundtrip");
    write_profile_fixture(&dir);
    let profile = load_profile_dir_artifact(&dir).expect("fixture profile loads");
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

    fs::remove_dir_all(dir).expect("temp profile dir removed");
}
