/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::custom_types::{DnsNameBuf, ProtoRecordType, ProtoResponseCode};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Canonical exported DNS record contract shared by CSV and Parquet writers.
///
/// Timeout records leave both response fields absent. A response timestamp with no response code
/// means a query was paired with an observed first IPv4 response fragment, but the DNS response
/// code could not be determined from the available prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DnsRecord {
    pub(crate) request_timestamp: i64,
    pub(crate) response_timestamp: Option<i64>,
    pub(crate) source_ip: IpAddr,
    pub(crate) source_port: u16,
    pub(crate) id: u16,
    pub(crate) name: DnsNameBuf,
    pub(crate) query_type: ProtoRecordType,
    pub(crate) response_code: Option<ProtoResponseCode>,
}
