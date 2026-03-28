/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use hickory_proto::op::Header;
use hickory_proto::op::Message;
use hickory_proto::op::Query;
use hickory_proto::op::response_code::ResponseCode as HickoryResponseCode;
use hickory_proto::rr::Name;
use hickory_proto::rr::record_type::RecordType as HickoryRecordType;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::DnsProcessor;
use super::types::ProcessedDnsRecord;
use crate::custom_types::DnsNameBuf;

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const DNS_HEADER_LEN: usize = 12;
const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86dd;
const IP_PROTOCOL_UDP: u8 = 17;
const DNS_PORT: u16 = 53;
const DNS_POINTER_MASK: u8 = 0b1100_0000;
const DNS_POINTER_TAG: u8 = 0b1100_0000;
const DNS_LABEL_LEN_MASK: u8 = 0b0011_1111;
const DNS_COMPRESSION_JUMP_LIMIT: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CanonicalFlowKey {
    pub(super) client_ip: IpAddr,
    pub(super) client_port: u16,
    pub(super) resolver_ip: IpAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ParsedUdpDnsMeta {
    pub(super) flow_key: CanonicalFlowKey,
    pub(super) dns_offset: u16,
    pub(super) is_response: bool,
}

impl ParsedUdpDnsMeta {
    fn src_ip(self) -> IpAddr {
        if self.is_response {
            self.flow_key.resolver_ip
        } else {
            self.flow_key.client_ip
        }
    }

    fn dst_ip(self) -> IpAddr {
        if self.is_response {
            self.flow_key.client_ip
        } else {
            self.flow_key.resolver_ip
        }
    }

    fn src_port(self) -> u16 {
        if self.is_response {
            DNS_PORT
        } else {
            self.flow_key.client_port
        }
    }

    fn dst_port(self) -> u16 {
        if self.is_response {
            self.flow_key.client_port
        } else {
            DNS_PORT
        }
    }

    fn dns_data(self, data: &[u8]) -> Result<&[u8], &'static str> {
        data.get(usize::from(self.dns_offset)..)
            .ok_or("Failed to parse UDP packet")
    }
}

struct DecodedDnsHeader {
    id: u16,
    response_code: HickoryResponseCode,
}

struct DecodedDnsQuestion {
    name: DnsNameBuf,
    query_type: HickoryRecordType,
}

impl DnsProcessor {
    #[inline]
    pub(super) fn packet_routing_meta(data: &[u8]) -> Option<ParsedUdpDnsMeta> {
        Self::extract_udp_dns_meta(data).ok().flatten()
    }

    #[inline]
    #[cfg(test)]
    pub(super) fn packet_flow_key(data: &[u8]) -> Option<CanonicalFlowKey> {
        Self::packet_routing_meta(data).map(|meta| meta.flow_key)
    }

    #[cfg(test)]
    pub(super) fn process_packet_batch(
        &self,
        data: &[u8],
        timestamp_micros: i64,
    ) -> Option<Vec<ProcessedDnsRecord>> {
        match Self::extract_udp_dns_meta(data) {
            Ok(Some(meta)) => self.process_packet_batch_with_meta(data, timestamp_micros, meta),
            Ok(None) => Some(Vec::new()),
            Err(_) => None,
        }
    }

    pub(super) fn process_packet_batch_with_meta(
        &self,
        data: &[u8],
        timestamp_micros: i64,
        meta: ParsedUdpDnsMeta,
    ) -> Option<Vec<ProcessedDnsRecord>> {
        self.process_packet_with_meta(data, timestamp_micros, meta)
            .ok()
    }

    #[inline]
    fn remove_trailing_dot(name: &str) -> &str {
        let stripped = name.strip_suffix('.').unwrap_or(name);

        if stripped.is_empty() { name } else { stripped }
    }

    #[inline]
    pub(super) fn format_domain_name(name: &Name) -> DnsNameBuf {
        let mut formatted = DnsNameBuf::default();

        if Self::write_domain_name(name, &mut formatted) {
            return formatted;
        }

        DnsNameBuf::new(Self::remove_trailing_dot(&name.to_ascii())).unwrap_or_default()
    }

    fn write_domain_name(name: &Name, output: &mut DnsNameBuf) -> bool {
        let mut labels = name.iter();
        let Some(first_label) = labels.next() else {
            return !name.is_fqdn() || output.try_push('.').is_ok();
        };

        if !Self::write_label_ascii(first_label, output) {
            return false;
        }

        for label in labels {
            if output.try_push('.').is_err() || !Self::write_label_ascii(label, output) {
                return false;
            }
        }

        true
    }

    fn write_label_ascii(label: &[u8], output: &mut DnsNameBuf) -> bool {
        if Self::is_plain_ascii_label(label) {
            // SAFETY: `is_plain_ascii_label` only accepts ASCII bytes that can be copied
            // directly into the presentation form without further escaping.
            return output
                .try_push_str(unsafe { std::str::from_utf8_unchecked(label) })
                .is_ok();
        }

        for (index, byte) in label.iter().copied().enumerate() {
            if !Self::write_ascii_byte(byte, index == 0, output) {
                return false;
            }
        }

        true
    }

    #[inline]
    fn is_plain_ascii_label(label: &[u8]) -> bool {
        let Some((&first, rest)) = label.split_first() else {
            return true;
        };

        Self::is_plain_ascii_first_byte(first)
            && rest
                .iter()
                .copied()
                .all(Self::is_plain_ascii_non_first_byte)
    }

    #[inline]
    fn is_plain_ascii_first_byte(byte: u8) -> bool {
        matches!(byte, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'*')
    }

    #[inline]
    fn is_plain_ascii_non_first_byte(byte: u8) -> bool {
        matches!(byte, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'-')
    }

    fn write_ascii_byte(byte: u8, is_first: bool, output: &mut DnsNameBuf) -> bool {
        match byte {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'_' => output.try_push(byte as char).is_ok(),
            b'-' if !is_first => output.try_push('-').is_ok(),
            b'*' if is_first => output.try_push('*').is_ok(),
            b if b > b'\x20' && b < b'\x7f' => {
                output.try_push('\\').is_ok() && output.try_push(byte as char).is_ok()
            }
            _ => Self::write_octal_escape(byte, output),
        }
    }

    fn write_octal_escape(byte: u8, output: &mut DnsNameBuf) -> bool {
        output.try_push('\\').is_ok()
            && output
                .try_push(char::from(b'0' + ((byte >> 6) & 0b111)))
                .is_ok()
            && output
                .try_push(char::from(b'0' + ((byte >> 3) & 0b111)))
                .is_ok()
            && output.try_push(char::from(b'0' + (byte & 0b111))).is_ok()
    }

    fn process_packet_with_meta(
        &self,
        data: &[u8],
        timestamp_micros: i64,
        meta: ParsedUdpDnsMeta,
    ) -> Result<Vec<ProcessedDnsRecord>, Box<dyn Error>> {
        let (header, queries) = self.decode_dns_questions(meta.dns_data(data)?)?;

        self.build_dns_records(
            &header,
            queries.as_slice(),
            meta.src_ip(),
            meta.dst_ip(),
            meta.src_port(),
            meta.dst_port(),
            timestamp_micros,
            meta.is_response,
        )
    }

    fn build_dns_records(
        &self,
        header: &DecodedDnsHeader,
        queries: &[DecodedDnsQuestion],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        timestamp_micros: i64,
        is_answer: bool,
    ) -> Result<Vec<ProcessedDnsRecord>, Box<dyn Error>> {
        let records = queries
            .iter()
            .take(if is_answer { 1 } else { usize::MAX })
            .map(|query| {
                let domain_name = query.name;
                let query_type = query.query_type;
                let response_code = if is_answer {
                    header.response_code
                } else {
                    HickoryResponseCode::ServFail
                };

                ProcessedDnsRecord {
                    id: header.id,
                    timestamp_micros,
                    packet_ordinal: 0,
                    record_ordinal: 0,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    is_query: !is_answer,
                    name: domain_name,
                    query_type,
                    response_code,
                }
            })
            .collect::<Vec<ProcessedDnsRecord>>();

        Ok(records)
    }

    fn decode_dns_questions(
        &self,
        dns_data: &[u8],
    ) -> Result<(DecodedDnsHeader, Vec<DecodedDnsQuestion>), &'static str> {
        if self.dns_wire_fast_path {
            Self::decode_dns_questions_fast(dns_data)
                .or_else(|_| Self::decode_dns_questions_hickory(dns_data))
        } else {
            Self::decode_dns_questions_hickory(dns_data)
        }
    }

    fn decode_dns_questions_fast(
        dns_data: &[u8],
    ) -> Result<(DecodedDnsHeader, Vec<DecodedDnsQuestion>), &'static str> {
        if dns_data.len() < DNS_HEADER_LEN {
            return Err("DNS data too short");
        }

        let id = Self::parse_u16_at(dns_data, 0, "Failed to parse DNS header")?;
        let flags = Self::parse_u16_at(dns_data, 2, "Failed to parse DNS header")?;
        let query_count = usize::from(Self::parse_u16_at(
            dns_data,
            4,
            "Failed to parse DNS question count",
        )?);
        let header = DecodedDnsHeader {
            id,
            response_code: HickoryResponseCode::from(0, (flags & 0x000f) as u8),
        };

        let mut cursor = DNS_HEADER_LEN;
        let mut queries = Vec::with_capacity(query_count);
        for _ in 0..query_count {
            let name = Self::read_wire_domain_name(dns_data, &mut cursor)?;
            let query_type = HickoryRecordType::from(Self::parse_u16_at(
                dns_data,
                cursor,
                "DNS question truncated",
            )?);
            cursor += 2;
            let _query_class = Self::parse_u16_at(dns_data, cursor, "DNS question truncated")?;
            cursor += 2;

            queries.push(DecodedDnsQuestion { name, query_type });
        }

        Ok((header, queries))
    }

    fn decode_dns_questions_hickory(
        dns_data: &[u8],
    ) -> Result<(DecodedDnsHeader, Vec<DecodedDnsQuestion>), &'static str> {
        let mut decoder = BinDecoder::new(dns_data);
        let header = Header::read(&mut decoder).map_err(|_| "Failed to parse DNS header")?;
        let queries = Message::read_queries(&mut decoder, header.query_count() as usize)
            .map_err(|_| "Failed to parse DNS questions")?;

        Ok((
            DecodedDnsHeader {
                id: header.id(),
                response_code: header.response_code(),
            },
            queries
                .into_iter()
                .map(|query: Query| DecodedDnsQuestion {
                    name: Self::format_domain_name(query.name()),
                    query_type: query.query_type(),
                })
                .collect(),
        ))
    }

    fn read_wire_domain_name(
        dns_data: &[u8],
        cursor: &mut usize,
    ) -> Result<DnsNameBuf, &'static str> {
        let mut output = DnsNameBuf::default();
        let mut position = *cursor;
        let mut resume_position = None;
        let mut wrote_label = false;
        let mut jump_count = 0;

        loop {
            let length = *dns_data.get(position).ok_or("DNS name truncated")?;

            match length {
                0 => {
                    position += 1;
                    if !wrote_label && output.try_push('.').is_err() {
                        return Err("DNS name too long");
                    }

                    *cursor = resume_position.unwrap_or(position);
                    return Ok(output);
                }
                _ if (length & DNS_POINTER_MASK) == DNS_POINTER_TAG => {
                    let next = *dns_data
                        .get(position + 1)
                        .ok_or("DNS compression pointer truncated")?;
                    let offset =
                        (((length & DNS_LABEL_LEN_MASK) as usize) << 8) | usize::from(next);

                    if offset >= dns_data.len() {
                        return Err("DNS compression pointer out of bounds");
                    }

                    if resume_position.is_none() {
                        resume_position = Some(position + 2);
                    }

                    jump_count += 1;
                    if jump_count > DNS_COMPRESSION_JUMP_LIMIT {
                        return Err("DNS compression pointer loop");
                    }

                    position = offset;
                }
                _ if (length & DNS_POINTER_MASK) != 0 => {
                    return Err("Unsupported DNS label encoding");
                }
                _ => {
                    let label_len = usize::from(length);
                    let label = dns_data
                        .get(position + 1..position + 1 + label_len)
                        .ok_or("DNS label truncated")?;

                    if wrote_label && output.try_push('.').is_err() {
                        return Err("DNS name too long");
                    }
                    if !Self::write_label_ascii(label, &mut output) {
                        return Err("DNS name too long");
                    }

                    wrote_label = true;
                    position += 1 + label_len;
                }
            }
        }
    }

    #[inline]
    fn parse_u16(data: &[u8], offset: usize) -> Result<u16, &'static str> {
        Self::parse_u16_at(data, offset, "Failed to parse transport header")
    }

    #[inline]
    fn parse_u16_at(data: &[u8], offset: usize, error: &'static str) -> Result<u16, &'static str> {
        let bytes = data.get(offset..offset + 2).ok_or(error)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn extract_udp_dns_meta(data: &[u8]) -> Result<Option<ParsedUdpDnsMeta>, &'static str> {
        let ethernet = data
            .get(..ETHERNET_HEADER_LEN)
            .ok_or("Failed to parse Ethernet packet")?;
        let ethertype = u16::from_be_bytes([ethernet[12], ethernet[13]]);
        let payload = &data[ETHERNET_HEADER_LEN..];

        match ethertype {
            ETHER_TYPE_IPV4 => Self::extract_udp_dns_from_ipv4(payload, ETHERNET_HEADER_LEN),
            ETHER_TYPE_IPV6 => Self::extract_udp_dns_from_ipv6(payload, ETHERNET_HEADER_LEN),
            _ => Ok(None),
        }
    }

    fn extract_udp_dns_from_ipv4(
        data: &[u8],
        l3_offset: usize,
    ) -> Result<Option<ParsedUdpDnsMeta>, &'static str> {
        let header = data
            .get(..IPV4_MIN_HEADER_LEN)
            .ok_or("Failed to parse IPv4 packet")?;
        let version = header[0] >> 4;
        if version != 4 {
            return Err("Failed to parse IPv4 packet");
        }

        let header_len = usize::from(header[0] & 0x0f) * 4;
        if header_len < IPV4_MIN_HEADER_LEN || data.len() < header_len {
            return Err("Failed to parse IPv4 packet");
        }

        if header[9] != IP_PROTOCOL_UDP {
            return Ok(None);
        }

        let src_ip = IpAddr::V4(Ipv4Addr::new(
            header[12], header[13], header[14], header[15],
        ));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(
            header[16], header[17], header[18], header[19],
        ));

        Self::extract_udp_dns_from_transport(
            &data[header_len..],
            src_ip,
            dst_ip,
            l3_offset + header_len,
        )
    }

    fn extract_udp_dns_from_ipv6(
        data: &[u8],
        l3_offset: usize,
    ) -> Result<Option<ParsedUdpDnsMeta>, &'static str> {
        let header = data
            .get(..IPV6_HEADER_LEN)
            .ok_or("Failed to parse IPv6 packet")?;
        let version = header[0] >> 4;
        if version != 6 {
            return Err("Failed to parse IPv6 packet");
        }

        if header[6] != IP_PROTOCOL_UDP {
            return Ok(None);
        }

        let src_ip = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&header[8..24]).unwrap(),
        ));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&header[24..40]).unwrap(),
        ));

        Self::extract_udp_dns_from_transport(
            &data[IPV6_HEADER_LEN..],
            src_ip,
            dst_ip,
            l3_offset + IPV6_HEADER_LEN,
        )
    }

    fn extract_udp_dns_from_transport(
        data: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        l4_offset: usize,
    ) -> Result<Option<ParsedUdpDnsMeta>, &'static str> {
        if data.len() < UDP_HEADER_LEN {
            return Err("Failed to parse UDP packet");
        }

        let src_port = Self::parse_u16(data, 0)?;
        let dst_port = Self::parse_u16(data, 2)?;
        if !(src_port == DNS_PORT || dst_port == DNS_PORT) {
            return Ok(None);
        }

        let dns_data = data
            .get(UDP_HEADER_LEN..)
            .ok_or("Failed to parse UDP packet")?;
        if dns_data.len() < DNS_HEADER_LEN {
            return Err("DNS data too short");
        }

        let dns_offset = l4_offset
            .checked_add(UDP_HEADER_LEN)
            .ok_or("Failed to parse UDP packet")?;

        Ok(Some(ParsedUdpDnsMeta {
            flow_key: Self::canonical_flow_key(src_ip, dst_ip, src_port, dst_port),
            dns_offset: u16::try_from(dns_offset)
                .map_err(|_| "UDP DNS offset exceeds supported range")?,
            is_response: src_port == DNS_PORT,
        }))
    }

    fn canonical_flow_key(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> CanonicalFlowKey {
        if src_port == DNS_PORT {
            CanonicalFlowKey {
                client_ip: dst_ip,
                client_port: dst_port,
                resolver_ip: src_ip,
            }
        } else {
            CanonicalFlowKey {
                client_ip: src_ip,
                client_port: src_port,
                resolver_ip: dst_ip,
            }
        }
    }
}
