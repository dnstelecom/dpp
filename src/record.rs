/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::custom_types::{FixedSizeString, ProtoRecordType, ProtoResponseCode};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Canonical exported DNS record contract shared by CSV and Parquet writers.
///
/// Timeout records use `response_timestamp = 0` and `response_code = ServFail` as the current
/// community-edition sentinel encoding for "no matching response was observed inside the configured
/// timeout window".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DnsRecord {
    pub(crate) request_timestamp: i64,
    pub(crate) response_timestamp: i64,
    pub(crate) source_ip: IpAddr,
    pub(crate) source_port: u16,
    pub(crate) id: u16,
    pub(crate) name: FixedSizeString<255>,
    pub(crate) query_type: ProtoRecordType,
    pub(crate) response_code: ProtoResponseCode,
}
