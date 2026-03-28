/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use hickory_proto::op::response_code::ResponseCode as HickoryResponseCode;
use hickory_proto::rr::Name;
use hickory_proto::rr::record_type::RecordType as HickoryRecordType;
use std::net::{IpAddr, Ipv4Addr};

use super::DnsProcessor;
use super::types::{ProcessedDnsRecord, QueryMap, ResponseMap};
use crate::custom_types::DnsName255;
use crate::test_support::{
    encode_dns_header, make_udp_dns_packet, make_udp_dns_packet_with_payload,
};

fn test_processor() -> DnsProcessor {
    DnsProcessor::new(None).expect("processor initializes")
}

fn test_processor_with_dns_wire_fast_path() -> DnsProcessor {
    DnsProcessor::new_with_dns_wire_fast_path(None, true).expect("processor initializes")
}

fn test_processor_with_match_timeout_micros(match_timeout_micros: i64) -> DnsProcessor {
    DnsProcessor::new_with_runtime_options(None, false, match_timeout_micros, false)
        .expect("processor initializes")
}

fn test_processor_with_monotonic_capture(match_timeout_micros: i64) -> DnsProcessor {
    DnsProcessor::new_with_runtime_options(None, false, match_timeout_micros, true)
        .expect("processor initializes")
}

fn test_name() -> DnsName255 {
    DnsName255::new("example.com").expect("test name fits")
}

fn named_test_name(name: &str) -> DnsName255 {
    DnsName255::new(name).expect("test name fits")
}

fn expected_formatted_name(name: &Name) -> DnsName255 {
    let ascii = name.to_ascii();
    let formatted = ascii
        .strip_suffix('.')
        .filter(|stripped| !stripped.is_empty())
        .unwrap_or(ascii.as_str());

    DnsName255::new(formatted).unwrap_or_default()
}

fn pending_query_count(query_map: &QueryMap) -> usize {
    query_map
        .values()
        .map(|timeline| {
            timeline
                .values()
                .map(std::collections::BTreeMap::len)
                .sum::<usize>()
        })
        .sum()
}

fn pending_response_count(response_map: &ResponseMap) -> usize {
    response_map
        .values()
        .map(|timeline| {
            timeline
                .values()
                .map(std::collections::BTreeMap::len)
                .sum::<usize>()
        })
        .sum()
}

fn make_query(packet_ordinal: u64, record_ordinal: u32) -> super::types::DnsQuery {
    make_query_with_timestamp(1_000, packet_ordinal, record_ordinal)
}

fn make_query_with_timestamp(
    timestamp_micros: i64,
    packet_ordinal: u64,
    record_ordinal: u32,
) -> super::types::DnsQuery {
    super::types::DnsQuery {
        id: 42,
        name: test_name(),
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 53000,
        timestamp_micros,
        packet_ordinal,
        record_ordinal,
        query_type: HickoryRecordType::A,
    }
}

fn make_response(packet_ordinal: u64, record_ordinal: u32) -> super::types::DnsResponse {
    make_response_with_timestamp(1_100, packet_ordinal, record_ordinal)
}

fn make_response_with_timestamp(
    timestamp_micros: i64,
    packet_ordinal: u64,
    record_ordinal: u32,
) -> super::types::DnsResponse {
    super::types::DnsResponse {
        id: 42,
        name: test_name(),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_port: 53000,
        timestamp_micros,
        packet_ordinal,
        record_ordinal,
        response_code: HickoryResponseCode::NoError,
        query_type: HickoryRecordType::A,
    }
}

fn make_query_record(packet_ordinal: u64, record_ordinal: u32) -> ProcessedDnsRecord {
    make_query_record_with_timestamp(1_000, packet_ordinal, record_ordinal)
}

fn make_query_record_with_timestamp(
    timestamp_micros: i64,
    packet_ordinal: u64,
    record_ordinal: u32,
) -> ProcessedDnsRecord {
    ProcessedDnsRecord {
        id: 42,
        timestamp_micros,
        packet_ordinal,
        record_ordinal,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 53000,
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        dst_port: 53,
        is_query: true,
        name: test_name(),
        query_type: HickoryRecordType::A,
        response_code: HickoryResponseCode::ServFail,
    }
}

fn make_response_record_with_timestamp(
    timestamp_micros: i64,
    packet_ordinal: u64,
    record_ordinal: u32,
) -> ProcessedDnsRecord {
    ProcessedDnsRecord {
        id: 42,
        timestamp_micros,
        packet_ordinal,
        record_ordinal,
        src_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 53,
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_port: 53000,
        is_query: false,
        name: test_name(),
        query_type: HickoryRecordType::A,
        response_code: HickoryResponseCode::NoError,
    }
}

#[test]
fn packet_flow_key_is_direction_insensitive_for_query_and_response() {
    let query_packet = make_udp_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53);
    let response_packet = make_udp_dns_packet([8, 8, 8, 8], [10, 0, 0, 1], 53, 53_000);

    let query_key = DnsProcessor::packet_flow_key(&query_packet).expect("query flow key");
    let response_key = DnsProcessor::packet_flow_key(&response_packet).expect("response flow key");

    assert_eq!(query_key, response_key);
    assert_eq!(query_key.client_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(query_key.client_port, 53_000);
    assert_eq!(query_key.resolver_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
}

#[test]
fn packet_flow_key_ignores_non_dns_udp_packets() {
    let packet = make_udp_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 123);

    assert!(DnsProcessor::packet_flow_key(&packet).is_none());
}

#[test]
fn packet_routing_meta_preserves_standard_packet_processing_output() {
    let processor = test_processor();
    let mut dns_payload = encode_dns_header(0x1234, 0x0100, 1);
    dns_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
    let packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &dns_payload);

    let standard_records = processor
        .process_packet_batch(&packet, 1_234_567)
        .expect("standard parser succeeds");
    let routing_meta = DnsProcessor::packet_routing_meta(&packet).expect("routing metadata exists");
    let meta_records = processor
        .process_packet_batch_with_meta(&packet, 1_234_567, routing_meta)
        .expect("metadata-assisted parser succeeds");

    assert_eq!(
        routing_meta.flow_key.client_ip,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert_eq!(routing_meta.flow_key.client_port, 53_000);
    assert_eq!(
        routing_meta.flow_key.resolver_ip,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    );
    assert_eq!(standard_records.len(), meta_records.len());

    for (standard, assisted) in standard_records.into_iter().zip(meta_records) {
        assert_eq!(standard.id, assisted.id);
        assert_eq!(standard.timestamp_micros, assisted.timestamp_micros);
        assert_eq!(standard.src_ip, assisted.src_ip);
        assert_eq!(standard.src_port, assisted.src_port);
        assert_eq!(standard.dst_ip, assisted.dst_ip);
        assert_eq!(standard.dst_port, assisted.dst_port);
        assert_eq!(standard.is_query, assisted.is_query);
        assert_eq!(standard.name, assisted.name);
        assert_eq!(standard.query_type, assisted.query_type);
        assert_eq!(standard.response_code, assisted.response_code);
    }
}

#[test]
fn deduplicates_later_pending_queries_inside_timeout_window() {
    let processor = test_processor();
    let mut query_map: QueryMap = std::collections::BTreeMap::new();
    let mut response_map: ResponseMap = std::collections::BTreeMap::new();

    let batch_result = processor.process_shard_records_with_batch_watermark(
        vec![
            make_query_record_with_timestamp(1_000, 1, 0),
            make_query_record_with_timestamp(1_300, 2, 0),
            make_response_record_with_timestamp(1_500, 3, 0),
        ],
        &mut query_map,
        &mut response_map,
        None,
    );

    assert_eq!(batch_result.dns_query_count, 2);
    assert_eq!(batch_result.duplicated_query_count, 1);
    assert_eq!(batch_result.matched_query_response_count, 1);
    assert_eq!(batch_result.output_records.len(), 1);
    assert_eq!(batch_result.output_records[0].request_timestamp, 1_000);
    assert_eq!(pending_query_count(&query_map), 0);
    assert_eq!(pending_response_count(&response_map), 0);
}

#[test]
fn duplicate_query_identity_requires_same_source_port() {
    let processor = test_processor();
    let mut query_map: QueryMap = std::collections::BTreeMap::new();
    let mut response_map: ResponseMap = std::collections::BTreeMap::new();

    let mut second_query = make_query_record_with_timestamp(1_300, 2, 0);
    second_query.src_port = second_query.src_port.saturating_add(1);

    let batch_result = processor.process_shard_records_with_batch_watermark(
        vec![make_query_record_with_timestamp(1_000, 1, 0), second_query],
        &mut query_map,
        &mut response_map,
        None,
    );

    assert_eq!(batch_result.dns_query_count, 2);
    assert_eq!(batch_result.duplicated_query_count, 0);
    assert_eq!(pending_query_count(&query_map), 2);
}

#[test]
fn duplicate_responses_stay_distinct_and_tie_break_by_discriminator() {
    let processor = test_processor();
    let mut response_map: ResponseMap = std::collections::BTreeMap::new();
    let query = make_query(9, 0);

    let first = make_response(11, 0);
    let second = make_response(11, 1);

    let first_key = processor.create_response_key(
        &first,
        first.timestamp_micros,
        first.packet_ordinal,
        first.record_ordinal,
    );
    processor.insert_response_entry(&mut response_map, first.clone());
    processor.insert_response_entry(&mut response_map, second.clone());

    assert_eq!(pending_response_count(&response_map), 2);

    let lower_bound_key = processor.create_response_key_from_query(
        &query,
        query.timestamp_micros,
        u64::MIN,
        u32::MIN,
    );
    let upper_bound_key = processor.create_response_key_from_query(
        &query,
        query.timestamp_micros
            + i64::try_from(crate::config::DEFAULT_MATCH_TIMEOUT_MS)
                .expect("default timeout fits into i64")
                * 1_000,
        u64::MAX,
        u32::MAX,
    );

    let matched = processor
        .find_closest_response(
            &response_map,
            &lower_bound_key,
            &upper_bound_key,
            query.timestamp_micros,
        )
        .expect("a match is expected");

    assert_eq!(matched.2, first_key);
}

#[test]
fn response_at_exact_match_timeout_boundary_still_matches() {
    let processor = test_processor_with_match_timeout_micros(1_200_000);
    let mut query_map: QueryMap = std::collections::BTreeMap::new();
    let mut response_map: ResponseMap = std::collections::BTreeMap::new();

    let batch_result = processor.process_shard_records_with_batch_watermark(
        vec![
            make_query_record_with_timestamp(1_000_000, 1, 0),
            make_response_record_with_timestamp(2_200_000, 2, 0),
        ],
        &mut query_map,
        &mut response_map,
        None,
    );

    assert_eq!(batch_result.matched_query_response_count, 1);
    assert_eq!(batch_result.timeout_query_count, 0);
    assert_eq!(batch_result.output_records.len(), 1);
    assert_eq!(batch_result.output_records[0].request_timestamp, 1_000_000);
    assert_eq!(batch_result.output_records[0].response_timestamp, 2_200_000);
    assert_eq!(pending_query_count(&query_map), 0);
    assert_eq!(pending_response_count(&response_map), 0);
}

#[test]
fn shorter_match_timeout_changes_pairing_window() {
    let processor = test_processor_with_match_timeout_micros(200_000);
    let mut query_map: QueryMap = std::collections::BTreeMap::new();
    let mut response_map: ResponseMap = std::collections::BTreeMap::new();

    let batch_result = processor.process_shard_records_with_batch_watermark(
        vec![
            make_query_record_with_timestamp(1_000_000, 1, 0),
            make_query_record_with_timestamp(1_300_000, 2, 0),
            make_response_record_with_timestamp(1_500_000, 3, 0),
        ],
        &mut query_map,
        &mut response_map,
        None,
    );

    assert_eq!(batch_result.dns_query_count, 2);
    assert_eq!(batch_result.duplicated_query_count, 0);
    assert_eq!(batch_result.matched_query_response_count, 1);
    assert_eq!(batch_result.output_records.len(), 1);
    assert_eq!(batch_result.output_records[0].request_timestamp, 1_300_000);
    assert_eq!(pending_query_count(&query_map), 1);
    assert_eq!(pending_response_count(&response_map), 0);
}

#[test]
fn shard_processing_defers_timeout_until_finalization() {
    let processor = test_processor();
    let mut query_map: QueryMap = std::collections::BTreeMap::new();
    let mut response_map: ResponseMap = std::collections::BTreeMap::new();

    let batch_result = processor.process_shard_records_with_batch_watermark(
        vec![make_query_record(1, 0)],
        &mut query_map,
        &mut response_map,
        None,
    );

    assert_eq!(batch_result.dns_query_count, 1);
    assert!(batch_result.output_records.is_empty());
    assert_eq!(pending_query_count(&query_map), 1);

    let finalization_result = processor.finalize_shard(&mut query_map, &mut response_map);

    assert_eq!(finalization_result.output_records.len(), 1);
    assert_eq!(pending_query_count(&query_map), 0);
}

#[test]
fn monotonic_capture_enables_batched_timeout_eviction() {
    let processor = test_processor_with_monotonic_capture(1_200_000);
    let mut query_map: QueryMap = std::collections::BTreeMap::new();
    let mut response_map: ResponseMap = std::collections::BTreeMap::new();

    let batch_result = processor.process_shard_records_with_batch_watermark(
        vec![
            make_query_record_with_timestamp(1_000_000, 1, 0),
            make_query_record_with_timestamp(2_500_000, 2, 0),
        ],
        &mut query_map,
        &mut response_map,
        None,
    );

    assert_eq!(batch_result.dns_query_count, 2);
    assert_eq!(batch_result.timeout_query_count, 1);
    assert_eq!(batch_result.output_records.len(), 1);
    assert_eq!(batch_result.output_records[0].request_timestamp, 1_000_000);
    assert_eq!(pending_query_count(&query_map), 1);
}

#[test]
fn monotonic_capture_preserves_query_at_exact_timeout_boundary() {
    let processor = test_processor_with_monotonic_capture(1_200_000);
    let mut query_map: QueryMap = std::collections::BTreeMap::new();
    let mut response_map: ResponseMap = std::collections::BTreeMap::new();

    let batch_result = processor.process_shard_records_with_batch_watermark(
        vec![make_query_record_with_timestamp(1_000_000, 1, 0)],
        &mut query_map,
        &mut response_map,
        Some(2_200_000),
    );

    assert_eq!(batch_result.timeout_query_count, 0);
    assert!(batch_result.output_records.is_empty());
    assert_eq!(pending_query_count(&query_map), 1);
}

#[test]
fn monotonic_capture_evicts_unmatched_responses() {
    let processor = test_processor_with_monotonic_capture(1_200_000);
    let mut query_map: QueryMap = std::collections::BTreeMap::new();
    let mut response_map: ResponseMap = std::collections::BTreeMap::new();

    let batch_result = processor.process_shard_records_with_batch_watermark(
        vec![
            make_response_record_with_timestamp(1_000_000, 1, 0),
            make_query_record_with_timestamp(2_500_000, 2, 0),
        ],
        &mut query_map,
        &mut response_map,
        Some(2_500_000),
    );

    assert_eq!(batch_result.timeout_query_count, 0);
    assert!(batch_result.output_records.is_empty());
    assert_eq!(pending_query_count(&query_map), 1);
    assert_eq!(pending_response_count(&response_map), 0);
}

#[test]
fn monotonic_capture_uses_batch_watermark_for_sparse_shards() {
    let processor = test_processor_with_monotonic_capture(1_200_000);
    let mut query_map: QueryMap = std::collections::BTreeMap::new();
    let mut response_map: ResponseMap = std::collections::BTreeMap::new();

    let batch_result = processor.process_shard_records_with_batch_watermark(
        vec![make_query_record_with_timestamp(1_000_000, 1, 0)],
        &mut query_map,
        &mut response_map,
        Some(2_500_000),
    );

    assert_eq!(batch_result.timeout_query_count, 1);
    assert_eq!(batch_result.output_records.len(), 1);
    assert_eq!(batch_result.output_records[0].request_timestamp, 1_000_000);
    assert_eq!(pending_query_count(&query_map), 0);
}

#[test]
fn finalization_preserves_full_key_order_across_identity_and_timestamp() {
    let processor = test_processor();
    let mut query_map: QueryMap = std::collections::BTreeMap::new();
    let mut response_map: ResponseMap = std::collections::BTreeMap::new();

    processor.insert_query_entry(
        &mut query_map,
        super::types::DnsQuery {
            id: 42,
            name: named_test_name("b.example"),
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 53_000,
            timestamp_micros: 1_500,
            packet_ordinal: 3,
            record_ordinal: 0,
            query_type: HickoryRecordType::A,
        },
    );
    processor.insert_query_entry(
        &mut query_map,
        super::types::DnsQuery {
            id: 42,
            name: named_test_name("a.example"),
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 53_000,
            timestamp_micros: 2_000,
            packet_ordinal: 2,
            record_ordinal: 0,
            query_type: HickoryRecordType::A,
        },
    );
    processor.insert_query_entry(
        &mut query_map,
        super::types::DnsQuery {
            id: 42,
            name: named_test_name("a.example"),
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 53_000,
            timestamp_micros: 1_000,
            packet_ordinal: 1,
            record_ordinal: 0,
            query_type: HickoryRecordType::A,
        },
    );

    let finalization_result = processor.finalize_shard(&mut query_map, &mut response_map);

    let observed = finalization_result
        .output_records
        .into_iter()
        .map(|record| (record.name.as_str().to_string(), record.request_timestamp))
        .collect::<Vec<_>>();

    assert_eq!(
        observed,
        vec![
            ("a.example".to_string(), 1_000),
            ("a.example".to_string(), 2_000),
            ("b.example".to_string(), 1_500),
        ]
    );
}

#[test]
fn parser_domain_formatter_matches_hickory_ascii_path() {
    let cases = vec![
        Name::new(),
        Name::from_ascii("WWW.example.COM.").expect("valid ascii name"),
        Name::root(),
        Name::from_ascii("*.example.com.").expect("valid wildcard name"),
        Name::from_ascii("_sip._tcp.example.com.").expect("valid service name"),
        Name::from_ascii("a-b.example.com.").expect("valid plain ascii name"),
        Name::from_labels(vec![b"bad.char" as &[u8], b"example", b"com"])
            .expect("valid escaped label"),
        Name::from_labels(vec![b"exa*mple" as &[u8], b"example", b"com"])
            .expect("valid escaped asterisk label"),
        Name::from_labels(vec![&[1u8] as &[u8], b"example", b"com"]).expect("valid raw-byte label"),
        Name::from_utf8("täst.example.").expect("valid utf8 name"),
    ];

    for name in cases {
        assert_eq!(
            DnsProcessor::format_domain_name(&name),
            expected_formatted_name(&name)
        );
    }
}

#[test]
fn parser_domain_formatter_preserves_overflow_fallback() {
    let labels = [vec![1u8; 63], vec![1u8; 63], vec![1u8; 63], vec![1u8; 58]];
    let name = Name::from_labels(labels.iter().map(Vec::as_slice)).expect("valid long raw name");

    assert_eq!(expected_formatted_name(&name), DnsName255::default());
    assert_eq!(
        DnsProcessor::format_domain_name(&name),
        DnsName255::default()
    );
}

#[test]
fn parser_decodes_multiple_wire_questions_including_compression() {
    let processor = test_processor_with_dns_wire_fast_path();
    let mut dns_payload = encode_dns_header(0x1234, 0x0100, 2);
    dns_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
    dns_payload.extend_from_slice(&[3, b'w', b'w', b'w', 0xC0, 0x0C]);
    dns_payload.extend_from_slice(&28_u16.to_be_bytes());
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());

    let packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &dns_payload);

    let records = processor
        .process_packet_batch(&packet, 1_234_567)
        .expect("packet parses");

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].id, 0x1234);
    assert!(records[0].is_query);
    assert_eq!(records[0].name.as_str(), "example.com");
    assert_eq!(records[0].query_type, HickoryRecordType::A);
    assert_eq!(records[0].response_code, HickoryResponseCode::ServFail);
    assert_eq!(records[1].name.as_str(), "www.example.com");
    assert_eq!(records[1].query_type, HickoryRecordType::AAAA);
}

#[test]
fn parser_decodes_response_code_from_wire_header() {
    let processor = test_processor_with_dns_wire_fast_path();
    let mut dns_payload = encode_dns_header(0xBEEF, 0x8183, 1);
    dns_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());

    let packet =
        make_udp_dns_packet_with_payload([8, 8, 8, 8], [10, 0, 0, 1], 53, 53_000, &dns_payload);

    let records = processor
        .process_packet_batch(&packet, 1_234_567)
        .expect("packet parses");

    assert_eq!(records.len(), 1);
    assert!(!records[0].is_query);
    assert_eq!(records[0].id, 0xBEEF);
    assert_eq!(records[0].name.as_str(), "example.com");
    assert_eq!(records[0].response_code, HickoryResponseCode::NXDomain);
}

#[test]
fn parser_rejects_wire_name_compression_loops() {
    let processor = test_processor_with_dns_wire_fast_path();
    let mut dns_payload = encode_dns_header(0xCAFE, 0x0100, 1);
    dns_payload.extend_from_slice(&[0xC0, 0x0C]);
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());

    let packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &dns_payload);

    assert!(processor.process_packet_batch(&packet, 1_234_567).is_none());
}

#[test]
fn parser_fast_path_flag_preserves_legacy_packet_output() {
    let legacy_processor = test_processor();
    let fast_path_processor = test_processor_with_dns_wire_fast_path();
    let mut dns_payload = encode_dns_header(0x1234, 0x0100, 2);
    dns_payload.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
    dns_payload.extend_from_slice(&[3, b'w', b'w', b'w', 0xC0, 0x0C]);
    dns_payload.extend_from_slice(&28_u16.to_be_bytes());
    dns_payload.extend_from_slice(&1_u16.to_be_bytes());
    let packet =
        make_udp_dns_packet_with_payload([10, 0, 0, 1], [8, 8, 8, 8], 53_000, 53, &dns_payload);

    let legacy_records = legacy_processor
        .process_packet_batch(&packet, 1_234_567)
        .expect("legacy parser succeeds");
    let fast_path_records = fast_path_processor
        .process_packet_batch(&packet, 1_234_567)
        .expect("fast parser succeeds");

    assert_eq!(legacy_records.len(), fast_path_records.len());
    for (legacy, fast) in legacy_records.into_iter().zip(fast_path_records) {
        assert_eq!(legacy.id, fast.id);
        assert_eq!(legacy.timestamp_micros, fast.timestamp_micros);
        assert_eq!(legacy.src_ip, fast.src_ip);
        assert_eq!(legacy.src_port, fast.src_port);
        assert_eq!(legacy.dst_ip, fast.dst_ip);
        assert_eq!(legacy.dst_port, fast.dst_port);
        assert_eq!(legacy.is_query, fast.is_query);
        assert_eq!(legacy.name, fast.name);
        assert_eq!(legacy.query_type, fast.query_type);
        assert_eq!(legacy.response_code, fast.response_code);
    }
}
