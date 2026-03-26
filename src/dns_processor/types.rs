/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use arrayvec::ArrayString;
use hickory_proto::op::response_code::ResponseCode as HickoryResponseCode;
use hickory_proto::rr::record_type::RecordType as HickoryRecordType;
use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::record::DnsRecord;

pub(super) type QueryKey = (
    u16,
    ArrayString<255>,
    IpAddr,
    u16,
    HickoryRecordType,
    i64,
    u64,
    u32,
);
pub(super) type QueryIdentityKey = (u16, ArrayString<255>, IpAddr, u16, HickoryRecordType);
pub(super) type ResponseKey = (
    u16,
    ArrayString<255>,
    IpAddr,
    u16,
    HickoryRecordType,
    i64,
    u64,
    u32,
);
pub(super) type ResponseIdentityKey = (u16, ArrayString<255>, IpAddr, u16, HickoryRecordType);
pub(super) type RecordDiscriminator = (u64, u32);
pub(super) type QueryTimeline = BTreeMap<i64, BTreeMap<RecordDiscriminator, DnsQuery>>;
pub(super) type ResponseTimeline = BTreeMap<i64, BTreeMap<RecordDiscriminator, DnsResponse>>;

pub(super) const MIN_RECORD_DISCRIMINATOR: (u64, u32) = (u64::MIN, u32::MIN);
pub(super) const MAX_RECORD_DISCRIMINATOR: (u64, u32) = (u64::MAX, u32::MAX);

pub(super) type QueryMap = BTreeMap<QueryIdentityKey, QueryTimeline>;
pub(super) type ResponseMap = BTreeMap<ResponseIdentityKey, ResponseTimeline>;

#[derive(Default)]
pub(super) struct ShardProcessingResult {
    pub(super) output_records: Vec<DnsRecord>,
    pub(super) dns_query_count: usize,
    pub(super) duplicated_query_count: usize,
    pub(super) dns_response_count: usize,
    pub(super) matched_query_response_count: usize,
    pub(super) timeout_query_count: usize,
    pub(super) matched_rtt_sum_micros: u64,
    pub(super) out_of_order_combined_count: usize,
}

#[derive(Debug, Clone)]
pub(super) struct ProcessedDnsRecord {
    pub(super) id: u16,
    pub(super) timestamp_micros: i64,
    pub(super) packet_ordinal: u64,
    pub(super) record_ordinal: u32,
    pub(super) src_ip: IpAddr,
    pub(super) src_port: u16,
    pub(super) dst_ip: IpAddr,
    pub(super) dst_port: u16,
    pub(super) is_query: bool,
    pub(super) name: ArrayString<255>,
    pub(super) query_type: HickoryRecordType,
    pub(super) response_code: HickoryResponseCode,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct DnsQuery {
    pub(super) id: u16,
    pub(super) name: ArrayString<255>,
    pub(super) src_ip: IpAddr,
    pub(super) src_port: u16,
    pub(super) timestamp_micros: i64,
    pub(super) packet_ordinal: u64,
    pub(super) record_ordinal: u32,
    pub(super) query_type: HickoryRecordType,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct DnsResponse {
    pub(super) id: u16,
    pub(super) name: ArrayString<255>,
    pub(super) dst_ip: IpAddr,
    pub(super) dst_port: u16,
    pub(super) timestamp_micros: i64,
    pub(super) packet_ordinal: u64,
    pub(super) record_ordinal: u32,
    pub(super) response_code: HickoryResponseCode,
    pub(super) query_type: HickoryRecordType,
}
