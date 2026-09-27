/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use hickory_proto::ProtoError;
use hickory_proto::op::Header;
#[cfg(test)]
use hickory_proto::op::Message;
use hickory_proto::op::Query;
use hickory_proto::op::ResponseCode as HickoryResponseCode;
use hickory_proto::rr::Name;
use hickory_proto::rr::RecordType as HickoryRecordType;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, DecodeError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::DnsProcessor;
use super::name_decoder::DnsNameDecoder;
use super::types::{ProcessedDnsRecord, VlanContext};
use crate::custom_types::{DnsNameBuf, DnsNameTooLong, ProtoResponseCode};

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const DNS_HEADER_LEN: usize = 12;
const MIN_DNS_OFFSET: usize = ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN;
const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86dd;
const ETHER_TYPE_VLAN: u16 = 0x8100;
const ETHER_TYPE_PROVIDER_BRIDGING: u16 = 0x88a8;
const ETHER_TYPE_LEGACY_QINQ: u16 = 0x9100;
const IP_PROTOCOL_UDP: u8 = 17;
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IP_AUTHENTICATION: u8 = 51;
const IPV6_DESTINATION_OPTIONS: u8 = 60;
const IPV6_FRAGMENT_OFFSET_AND_MORE: u16 = 0xfff9;
const IPV4_MORE_FRAGMENTS: u16 = 0x2000;
const IPV4_DONT_FRAGMENT: u16 = 0x4000;
const IPV4_RESERVED_FLAG: u16 = 0x8000;
const IPV4_FRAGMENT_OFFSET_MASK: u16 = 0x1fff;
const DNS_PORT: u16 = 53;
const DNS_RESOURCE_RECORD_FIXED_LEN: usize = 10;
const DNS_OPT_RECORD_TYPE: u16 = 41;
const DNS_TSIG_RECORD_TYPE: u16 = 250;

/// Decode the encapsulated EtherType, payload start and canonical VLAN context once.
/// Reassembly and DNS matching share this traversal and its VLAN identity semantics.
pub(super) fn ethernet_ethertype_and_payload_offset(
    data: &[u8],
) -> Result<(u16, usize, VlanContext), &'static str> {
    let ethernet = data
        .get(..ETHERNET_HEADER_LEN)
        .ok_or("Failed to parse Ethernet packet")?;
    let mut ethertype = u16::from_be_bytes([ethernet[12], ethernet[13]]);
    let mut payload_offset = ETHERNET_HEADER_LEN;
    let mut tags = Vec::new();

    while matches!(
        ethertype,
        ETHER_TYPE_VLAN | ETHER_TYPE_PROVIDER_BRIDGING | ETHER_TYPE_LEGACY_QINQ
    ) {
        let tag = data
            .get(payload_offset..payload_offset + 4)
            .ok_or("Failed to parse Ethernet VLAN tag")?;
        let vlan_id = u16::from_be_bytes([tag[0], tag[1]]) & 0x0fff;
        tags.push((u32::from(ethertype) << 16) | u32::from(vlan_id));
        ethertype = u16::from_be_bytes([tag[2], tag[3]]);
        payload_offset += 4;
    }

    Ok((ethertype, payload_offset, VlanContext::from_tags(tags)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CanonicalFlowKey {
    pub(super) client_ip: IpAddr,
    pub(super) client_port: u16,
    pub(super) resolver_ip: IpAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ParsedUdpDnsMeta {
    pub(super) flow_key: CanonicalFlowKey,
    vlan_context: VlanContext,
    // DNS starts at least at byte 42. A maximum IPv6 frame ends at byte 65589;
    // reserving the validated 12-byte DNS header bounds this delta to 65535.
    dns_offset_delta: u16,
    pub(super) dns_len: u16,
    pub(super) is_response: bool,
    /// The first IPv4 fragment contains a complete question but not the complete UDP datagram.
    pub(super) partial_first_ipv4_fragment: bool,
}

impl ParsedUdpDnsMeta {
    fn dns_offset(&self) -> usize {
        MIN_DNS_OFFSET + usize::from(self.dns_offset_delta)
    }

    fn src_ip(&self) -> IpAddr {
        if self.is_response {
            self.flow_key.resolver_ip
        } else {
            self.flow_key.client_ip
        }
    }

    fn dst_ip(&self) -> IpAddr {
        if self.is_response {
            self.flow_key.client_ip
        } else {
            self.flow_key.resolver_ip
        }
    }

    fn src_port(&self) -> u16 {
        if self.is_response {
            DNS_PORT
        } else {
            self.flow_key.client_port
        }
    }

    fn dst_port(&self) -> u16 {
        if self.is_response {
            self.flow_key.client_port
        } else {
            DNS_PORT
        }
    }

    fn dns_data<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], &'static str> {
        let start = self.dns_offset();
        let end = start
            .checked_add(usize::from(self.dns_len))
            .ok_or("Failed to parse UDP packet")?;
        data.get(start..end).ok_or("Failed to parse UDP packet")
    }
}

struct DecodedDnsHeader {
    id: u16,
    opcode: u8,
    response_code: ProtoResponseCode,
    partial_response_code: Option<ProtoResponseCode>,
}

struct DecodedDnsQuestion {
    name: DnsNameBuf,
    query_type: HickoryRecordType,
    query_class: u16,
}

#[derive(Debug)]
pub(super) enum PacketProcessingOutcome<T = ()> {
    Records(T),
    RejectedOversizedQname,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DnsQuestionDecodeError {
    OversizedQname,
    Invalid,
}

impl From<&'static str> for DnsQuestionDecodeError {
    fn from(_: &'static str) -> Self {
        Self::Invalid
    }
}

#[derive(Clone, Copy)]
struct DnsSectionCounts {
    answers: usize,
    authorities: usize,
    additionals: usize,
}

struct DnsResourceRecordMeta {
    owner_is_root: bool,
    record_type: u16,
    ttl: u32,
    rdata_start: usize,
    rdata_end: usize,
}

#[derive(Default)]
struct AdditionalResponseCodeFields {
    edns_response_code_high: Option<u8>,
    tsig_error: Option<u16>,
}

impl DnsProcessor {
    #[inline]
    #[cfg(test)]
    pub(super) fn packet_routing_meta(data: &[u8]) -> Option<ParsedUdpDnsMeta> {
        Self::packet_routing_meta_with_fragments(data, false)
    }

    #[inline]
    pub(super) fn packet_routing_meta_with_fragments(
        data: &[u8],
        allow_first_ipv4_response_fragment: bool,
    ) -> Option<ParsedUdpDnsMeta> {
        Self::extract_udp_dns_meta_with_fragments(data, allow_first_ipv4_response_fragment)
            .ok()
            .flatten()
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
            Ok(Some(meta)) => {
                match self.process_packet_batch_with_meta(data, timestamp_micros, meta) {
                    PacketProcessingOutcome::Records(records) => Some(records),
                    PacketProcessingOutcome::RejectedOversizedQname
                    | PacketProcessingOutcome::Invalid => None,
                }
            }
            Ok(None) => Some(Vec::new()),
            Err(_) => None,
        }
    }

    #[cfg(test)]
    pub(super) fn process_packet_batch_with_meta(
        &self,
        data: &[u8],
        timestamp_micros: i64,
        meta: ParsedUdpDnsMeta,
    ) -> PacketProcessingOutcome<Vec<ProcessedDnsRecord>> {
        let mut records = Vec::new();
        match self.process_packet_batch_with_meta_into(
            data,
            timestamp_micros,
            0,
            meta,
            &mut records,
        ) {
            PacketProcessingOutcome::Records(()) => PacketProcessingOutcome::Records(records),
            PacketProcessingOutcome::RejectedOversizedQname => {
                PacketProcessingOutcome::RejectedOversizedQname
            }
            PacketProcessingOutcome::Invalid => PacketProcessingOutcome::Invalid,
        }
    }

    pub(super) fn process_packet_batch_with_meta_into(
        &self,
        data: &[u8],
        timestamp_micros: i64,
        packet_ordinal: u64,
        meta: ParsedUdpDnsMeta,
        records: &mut Vec<ProcessedDnsRecord>,
    ) -> PacketProcessingOutcome {
        match self.process_packet_with_meta_into(
            data,
            timestamp_micros,
            packet_ordinal,
            meta,
            records,
        ) {
            Ok(()) => PacketProcessingOutcome::Records(()),
            Err(DnsQuestionDecodeError::OversizedQname) => {
                PacketProcessingOutcome::RejectedOversizedQname
            }
            Err(DnsQuestionDecodeError::Invalid) => PacketProcessingOutcome::Invalid,
        }
    }

    #[inline]
    pub(super) fn format_domain_name(name: &Name) -> Result<DnsNameBuf, DnsNameTooLong> {
        let mut formatted = DnsNameBuf::default();

        if Self::write_domain_name(name, &mut formatted) {
            Ok(formatted)
        } else {
            Err(DnsNameTooLong)
        }
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

    fn process_packet_with_meta_into(
        &self,
        data: &[u8],
        timestamp_micros: i64,
        packet_ordinal: u64,
        meta: ParsedUdpDnsMeta,
        records: &mut Vec<ProcessedDnsRecord>,
    ) -> Result<(), DnsQuestionDecodeError> {
        let (header, queries) = self.decode_dns_questions(
            meta.dns_data(data)?,
            meta.is_response,
            meta.partial_first_ipv4_fragment,
        )?;

        self.build_dns_records_into(
            &header,
            queries,
            timestamp_micros,
            packet_ordinal,
            meta,
            records,
        );

        Ok(())
    }

    fn build_dns_records_into(
        &self,
        header: &DecodedDnsHeader,
        queries: Vec<DecodedDnsQuestion>,
        timestamp_micros: i64,
        packet_ordinal: u64,
        meta: ParsedUdpDnsMeta,
        records: &mut Vec<ProcessedDnsRecord>,
    ) {
        for (record_ordinal, query) in queries
            .into_iter()
            .take(if meta.is_response { 1 } else { usize::MAX })
            .enumerate()
        {
            let response_code = if meta.is_response {
                header.response_code
            } else {
                HickoryResponseCode::ServFail.into()
            };

            records.push(ProcessedDnsRecord {
                id: header.id,
                timestamp_micros,
                packet_ordinal,
                record_ordinal: record_ordinal as u32,
                src_ip: meta.src_ip(),
                src_port: meta.src_port(),
                dst_ip: meta.dst_ip(),
                dst_port: meta.dst_port(),
                is_query: !meta.is_response,
                name: query.name,
                query_type: query.query_type,
                query_class: query.query_class,
                opcode: header.opcode,
                response_code,
                vlan_context: meta.vlan_context.clone(),
                partial_first_ipv4_fragment: meta.partial_first_ipv4_fragment,
                partial_response_code: header.partial_response_code,
            });
        }
    }

    fn decode_dns_questions(
        &self,
        dns_data: &[u8],
        decode_extended_rcode: bool,
        partial_first_ipv4_fragment: bool,
    ) -> Result<(DecodedDnsHeader, Vec<DecodedDnsQuestion>), DnsQuestionDecodeError> {
        let mut names = DnsNameDecoder::new(dns_data, self.max_dns_compression_jumps);
        if self.dns_wire_fast_path {
            Self::decode_dns_questions_fast(
                dns_data,
                &mut names,
                decode_extended_rcode,
                partial_first_ipv4_fragment,
            )
            .or_else(|_| {
                Self::decode_dns_questions_hickory(
                    dns_data,
                    &mut names,
                    decode_extended_rcode,
                    partial_first_ipv4_fragment,
                )
            })
        } else {
            Self::decode_dns_questions_hickory(
                dns_data,
                &mut names,
                decode_extended_rcode,
                partial_first_ipv4_fragment,
            )
        }
    }

    fn classify_hickory_question_error(error: ProtoError) -> DnsQuestionDecodeError {
        match error {
            ProtoError::Decode(DecodeError::DomainNameTooLong(_)) => {
                DnsQuestionDecodeError::OversizedQname
            }
            _ => DnsQuestionDecodeError::Invalid,
        }
    }

    #[inline]
    fn invalid_question_count(opcode: u8, query_count: usize) -> bool {
        // RFC 9619 limits standard QUERY messages to one question.
        opcode == 0 && query_count > 1
    }

    fn question_capacity(dns_len: usize, count: usize) -> usize {
        // Even a root question occupies five bytes. An untrusted count alone
        // must not reserve tens of MiB for presentation-form names.
        count.min(dns_len.saturating_sub(DNS_HEADER_LEN) / 5)
    }

    fn decode_dns_questions_fast(
        dns_data: &[u8],
        names: &mut DnsNameDecoder<'_>,
        decode_extended_rcode: bool,
        partial_first_ipv4_fragment: bool,
    ) -> Result<(DecodedDnsHeader, Vec<DecodedDnsQuestion>), DnsQuestionDecodeError> {
        if dns_data.len() < DNS_HEADER_LEN {
            return Err(DnsQuestionDecodeError::Invalid);
        }

        let id = Self::parse_u16_at(dns_data, 0, "Failed to parse DNS header")?;
        let flags = Self::parse_u16_at(dns_data, 2, "Failed to parse DNS header")?;
        let opcode = ((flags >> 11) & 0x0f) as u8;
        let low_response_code = (flags & 0x000f) as u8;
        let query_count = usize::from(Self::parse_u16_at(
            dns_data,
            4,
            "Failed to parse DNS question count",
        )?);
        if Self::invalid_question_count(opcode, query_count) {
            return Err(DnsQuestionDecodeError::Invalid);
        }

        let mut cursor = DNS_HEADER_LEN;
        let mut queries = Vec::with_capacity(Self::question_capacity(dns_data.len(), query_count));
        for _ in 0..query_count {
            let name = Self::read_wire_domain_name(names, &mut cursor)?;
            let query_type = HickoryRecordType::from(Self::parse_u16_at(
                dns_data,
                cursor,
                "DNS question truncated",
            )?);
            cursor += 2;
            let query_class = Self::parse_u16_at(dns_data, cursor, "DNS question truncated")?;
            cursor += 2;

            queries.push(DecodedDnsQuestion {
                name,
                query_type,
                query_class,
            });
        }
        let mut response_code =
            ProtoResponseCode::from(HickoryResponseCode::from(0, low_response_code));
        let mut partial_response_code = None;
        if decode_extended_rcode {
            let section_counts = DnsSectionCounts {
                answers: usize::from(Self::parse_u16_at(
                    dns_data,
                    6,
                    "Failed to parse DNS answer count",
                )?),
                authorities: usize::from(Self::parse_u16_at(
                    dns_data,
                    8,
                    "Failed to parse DNS authority count",
                )?),
                additionals: usize::from(Self::parse_u16_at(
                    dns_data,
                    10,
                    "Failed to parse DNS additional count",
                )?),
            };
            if partial_first_ipv4_fragment {
                partial_response_code = Self::decode_partial_response_code_with_sections(
                    dns_data,
                    names,
                    cursor,
                    section_counts,
                    low_response_code,
                )?;
            } else if section_counts.answers > 0
                || section_counts.authorities > 0
                || section_counts.additionals > 0
            {
                response_code = Self::decode_response_code_with_sections(
                    dns_data,
                    names,
                    cursor,
                    section_counts,
                    low_response_code,
                )?;
            }
        }
        let header = DecodedDnsHeader {
            id,
            opcode,
            response_code,
            partial_response_code,
        };

        Ok((header, queries))
    }

    fn decode_dns_questions_hickory(
        dns_data: &[u8],
        names: &mut DnsNameDecoder<'_>,
        decode_extended_rcode: bool,
        partial_first_ipv4_fragment: bool,
    ) -> Result<(DecodedDnsHeader, Vec<DecodedDnsQuestion>), DnsQuestionDecodeError> {
        let mut decoder = BinDecoder::new(dns_data);
        let header = Header::read(&mut decoder).map_err(|_| DnsQuestionDecodeError::Invalid)?;
        let opcode: u8 = header.op_code.into();
        if Self::invalid_question_count(opcode, header.counts.queries as usize) {
            return Err(DnsQuestionDecodeError::Invalid);
        }
        let mut cursor = decoder.index();
        let mut queries = Vec::with_capacity(Self::question_capacity(
            dns_data.len(),
            header.counts.queries as usize,
        ));
        for _ in 0..header.counts.queries {
            let query = Self::read_hickory_question(dns_data, names, &mut cursor)?;
            queries.push(DecodedDnsQuestion {
                name: Self::format_domain_name(query.name())
                    .map_err(|_| DnsQuestionDecodeError::Invalid)?,
                query_type: query.query_type(),
                query_class: query.query_class().into(),
            });
        }
        let mut response_code = ProtoResponseCode::from(header.response_code);
        let mut partial_response_code = None;
        if decode_extended_rcode {
            let section_counts = DnsSectionCounts {
                answers: header.counts.answers as usize,
                authorities: header.counts.authorities as usize,
                additionals: header.counts.additionals as usize,
            };
            if partial_first_ipv4_fragment {
                partial_response_code = Self::decode_partial_response_code_with_sections(
                    dns_data,
                    names,
                    cursor,
                    section_counts,
                    header.response_code.low(),
                )?;
            } else if section_counts.answers > 0
                || section_counts.authorities > 0
                || section_counts.additionals > 0
            {
                response_code = Self::decode_response_code_with_sections(
                    dns_data,
                    names,
                    cursor,
                    section_counts,
                    header.response_code.low(),
                )?;
            }
        }

        Ok((
            DecodedDnsHeader {
                id: header.id,
                opcode,
                response_code,
                partial_response_code,
            },
            queries,
        ))
    }

    fn decode_response_code_with_sections(
        dns_data: &[u8],
        names: &mut DnsNameDecoder<'_>,
        mut cursor: usize,
        section_counts: DnsSectionCounts,
        low_response_code: u8,
    ) -> Result<ProtoResponseCode, &'static str> {
        let response_code =
            ProtoResponseCode::from(HickoryResponseCode::from(0, low_response_code));

        Self::skip_dns_resource_records(
            dns_data,
            names,
            &mut cursor,
            section_counts.answers,
            true,
        )?;
        Self::skip_dns_resource_records(
            dns_data,
            names,
            &mut cursor,
            section_counts.authorities,
            true,
        )?;
        let additional_fields = Self::read_additional_response_code_fields(
            dns_data,
            names,
            &mut cursor,
            section_counts.additionals,
        )?;

        if let Some(tsig_error) = additional_fields.tsig_error
            && tsig_error != 0
        {
            return Ok(ProtoResponseCode::from_tsig_error(tsig_error));
        }

        if let Some(high_response_code) = additional_fields.edns_response_code_high {
            Ok(ProtoResponseCode::from_edns(HickoryResponseCode::from(
                high_response_code,
                low_response_code,
            )))
        } else {
            Ok(response_code)
        }
    }

    fn decode_partial_response_code_with_sections(
        dns_data: &[u8],
        names: &mut DnsNameDecoder<'_>,
        cursor: usize,
        section_counts: DnsSectionCounts,
        low_response_code: u8,
    ) -> Result<Option<ProtoResponseCode>, DnsQuestionDecodeError> {
        let low_code = ProtoResponseCode::from(HickoryResponseCode::from(0, low_response_code));
        let mut boundary_cursor = cursor;
        let record_count =
            section_counts.answers + section_counts.authorities + section_counts.additionals;
        let mut additional_fields = AdditionalResponseCodeFields::default();
        for index in 0..record_count {
            match Self::read_dns_resource_record_meta(dns_data, names, &mut boundary_cursor) {
                Ok(meta) => {
                    if index < section_counts.answers + section_counts.authorities {
                        if meta.record_type == DNS_OPT_RECORD_TYPE {
                            return Err(DnsQuestionDecodeError::Invalid);
                        }
                    } else {
                        let additional_index =
                            index - section_counts.answers - section_counts.authorities;
                        Self::include_additional_response_code_fields(
                            dns_data,
                            names,
                            &mut additional_fields,
                            &meta,
                            additional_index,
                            section_counts.additionals,
                        )
                        .map_err(|_| DnsQuestionDecodeError::Invalid)?;
                    }
                }
                Err(error) if Self::is_incomplete_fragment_section(error) => {
                    // OPT and TSIG are additional records. With no additionals, the header's
                    // low RCODE is final even when an answer spans later IP fragments.
                    return Ok((section_counts.additionals == 0).then_some(low_code));
                }
                Err(_) => return Err(DnsQuestionDecodeError::Invalid),
            }
        }

        // All declared records fit in the first fragment. Decode their complete response-code
        // context, including OPT and TSIG, using the same validation as full datagrams.
        Self::decode_response_code_with_sections(
            dns_data,
            names,
            cursor,
            section_counts,
            low_response_code,
        )
        .map(Some)
        .map_err(|_| DnsQuestionDecodeError::Invalid)
    }

    fn is_incomplete_fragment_section(error: &str) -> bool {
        matches!(
            error,
            "DNS name truncated"
                | "DNS compression pointer truncated"
                | "DNS label truncated"
                | "DNS resource record truncated"
        )
    }

    fn skip_dns_resource_records(
        dns_data: &[u8],
        names: &mut DnsNameDecoder<'_>,
        cursor: &mut usize,
        count: usize,
        reject_opt: bool,
    ) -> Result<(), &'static str> {
        for _ in 0..count {
            let meta = Self::read_dns_resource_record_meta(dns_data, names, cursor)?;
            if reject_opt && meta.record_type == DNS_OPT_RECORD_TYPE {
                return Err("OPT record outside additional section");
            }
        }

        Ok(())
    }

    fn read_additional_response_code_fields(
        dns_data: &[u8],
        names: &mut DnsNameDecoder<'_>,
        cursor: &mut usize,
        additional_count: usize,
    ) -> Result<AdditionalResponseCodeFields, &'static str> {
        let mut fields = AdditionalResponseCodeFields::default();
        for index in 0..additional_count {
            let meta = Self::read_dns_resource_record_meta(dns_data, names, cursor)?;
            Self::include_additional_response_code_fields(
                dns_data,
                names,
                &mut fields,
                &meta,
                index,
                additional_count,
            )?;
        }

        Ok(fields)
    }

    fn include_additional_response_code_fields(
        dns_data: &[u8],
        names: &mut DnsNameDecoder<'_>,
        fields: &mut AdditionalResponseCodeFields,
        meta: &DnsResourceRecordMeta,
        index: usize,
        additional_count: usize,
    ) -> Result<(), &'static str> {
        match meta.record_type {
            DNS_OPT_RECORD_TYPE => {
                if fields.edns_response_code_high.is_some() {
                    return Err("Multiple OPT records");
                }
                if !meta.owner_is_root {
                    return Err("OPT record owner must be root");
                }
                fields.edns_response_code_high = Some((meta.ttl >> 24) as u8);
            }
            DNS_TSIG_RECORD_TYPE => {
                if fields.tsig_error.is_some() {
                    return Err("Multiple TSIG records");
                }
                if index + 1 != additional_count {
                    return Err("TSIG record must be last additional");
                }
                fields.tsig_error = Some(Self::read_tsig_error(dns_data, names, meta)?);
            }
            _ => {}
        }
        Ok(())
    }

    fn read_tsig_error(
        dns_data: &[u8],
        names: &mut DnsNameDecoder<'_>,
        meta: &DnsResourceRecordMeta,
    ) -> Result<u16, &'static str> {
        let mut cursor = meta.rdata_start;
        let rdata_end = meta.rdata_end;

        Self::skip_wire_domain_name_in_range(names, &mut cursor, rdata_end)?;
        Self::skip_bytes_in_range(&mut cursor, rdata_end, 6 + 2)?;
        let mac_size = usize::from(Self::parse_u16_at(
            dns_data,
            cursor,
            "TSIG record truncated",
        )?);
        cursor += 2;
        Self::skip_bytes_in_range(&mut cursor, rdata_end, mac_size + 2)?;

        let error = Self::parse_u16_at(dns_data, cursor, "TSIG record truncated")?;
        cursor += 2;
        let other_len = usize::from(Self::parse_u16_at(
            dns_data,
            cursor,
            "TSIG record truncated",
        )?);
        Self::skip_bytes_in_range(&mut cursor, rdata_end, 2 + other_len)?;
        if cursor != rdata_end {
            return Err("TSIG record has trailing data");
        }

        Ok(error)
    }

    fn read_dns_resource_record_meta(
        dns_data: &[u8],
        names: &mut DnsNameDecoder<'_>,
        cursor: &mut usize,
    ) -> Result<DnsResourceRecordMeta, &'static str> {
        let owner_is_root = names.skip(cursor)?;
        let fixed_start = *cursor;
        let fixed_end = fixed_start
            .checked_add(DNS_RESOURCE_RECORD_FIXED_LEN)
            .ok_or("DNS resource record truncated")?;
        let fixed = dns_data
            .get(fixed_start..fixed_end)
            .ok_or("DNS resource record truncated")?;
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let rdata_len = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let rdata_end = fixed_end
            .checked_add(rdata_len)
            .ok_or("DNS resource record truncated")?;
        dns_data
            .get(fixed_end..rdata_end)
            .ok_or("DNS resource record truncated")?;
        *cursor = rdata_end;

        Ok(DnsResourceRecordMeta {
            owner_is_root,
            record_type,
            ttl,
            rdata_start: fixed_end,
            rdata_end,
        })
    }

    fn skip_wire_domain_name_in_range(
        names: &mut DnsNameDecoder<'_>,
        cursor: &mut usize,
        limit: usize,
    ) -> Result<(), &'static str> {
        if *cursor >= limit {
            return Err("DNS name truncated");
        }

        names.skip(cursor)?;
        if *cursor > limit {
            return Err("DNS name truncated");
        }

        Ok(())
    }

    fn skip_bytes_in_range(
        cursor: &mut usize,
        limit: usize,
        byte_count: usize,
    ) -> Result<(), &'static str> {
        *cursor = cursor
            .checked_add(byte_count)
            .filter(|next| *next <= limit)
            .ok_or("TSIG record truncated")?;

        Ok(())
    }

    fn read_wire_domain_name(
        names: &mut DnsNameDecoder<'_>,
        cursor: &mut usize,
    ) -> Result<DnsNameBuf, DnsQuestionDecodeError> {
        // Most questions contain no compression at all. Keep their original
        // single-pass formatter free of cache metadata and callback overhead.
        // A pointer restarts through the shared decoder from the original cursor.
        let dns_data = names.data();
        let mut position = *cursor;
        let mut output = DnsNameBuf::default();
        let mut expanded_wire_len = 1_usize;
        let mut oversized = false;
        loop {
            let length = *dns_data.get(position).ok_or("DNS name truncated")?;
            match length {
                0 => {
                    if oversized {
                        return Err(DnsQuestionDecodeError::OversizedQname);
                    }
                    if output.as_str().is_empty() {
                        output
                            .try_push('.')
                            .map_err(|_| DnsQuestionDecodeError::Invalid)?;
                    }
                    *cursor = position + 1;
                    return Ok(output);
                }
                _ if length & 0xc0 == 0xc0 => {
                    return Self::read_compressed_wire_domain_name(names, cursor);
                }
                _ if length & 0xc0 != 0 => return Err(DnsQuestionDecodeError::Invalid),
                _ => {
                    let end = position + 1 + usize::from(length);
                    let label = dns_data
                        .get(position + 1..end)
                        .ok_or("DNS label truncated")?;
                    expanded_wire_len = expanded_wire_len.saturating_add(1 + label.len());
                    oversized |= expanded_wire_len > Name::MAX_LENGTH;
                    if !oversized {
                        if !output.as_str().is_empty() {
                            output
                                .try_push('.')
                                .map_err(|_| DnsQuestionDecodeError::Invalid)?;
                        }
                        if !Self::write_label_ascii(label, &mut output) {
                            return Err(DnsQuestionDecodeError::Invalid);
                        }
                    }
                    position = end;
                }
            }
        }
    }

    fn read_compressed_wire_domain_name(
        names: &mut DnsNameDecoder<'_>,
        cursor: &mut usize,
    ) -> Result<DnsNameBuf, DnsQuestionDecodeError> {
        let mut output = DnsNameBuf::default();
        let mut presentation_valid = true;
        let name = names.read_with_labels(cursor, |label| {
            if presentation_valid {
                if !output.as_str().is_empty() {
                    presentation_valid = output.try_push('.').is_ok();
                }
                presentation_valid &= Self::write_label_ascii(label, &mut output);
            }
        })?;
        if name.expanded_wire_len > Name::MAX_LENGTH {
            return Err(DnsQuestionDecodeError::OversizedQname);
        }
        if !presentation_valid {
            return Err(DnsQuestionDecodeError::Invalid);
        }
        if output.as_str().is_empty() {
            output
                .try_push('.')
                .map_err(|_| DnsQuestionDecodeError::Invalid)?;
        }
        Ok(output)
    }

    fn read_hickory_question(
        dns_data: &[u8],
        names: &mut DnsNameDecoder<'_>,
        cursor: &mut usize,
    ) -> Result<Query, DnsQuestionDecodeError> {
        let start = *cursor;
        let name = names.read(cursor)?;
        if name.expanded_wire_len > Name::MAX_LENGTH {
            return Err(DnsQuestionDecodeError::OversizedQname);
        }
        let fields = dns_data
            .get(*cursor..*cursor + 4)
            .ok_or("DNS question truncated")?;
        *cursor += 4;
        if name.jumps == 0 {
            return Query::read(&mut BinDecoder::new(&dns_data[start..*cursor]))
                .map_err(|error| Self::classify_hickory_question_error(error.into()));
        }

        // Hickory keeps semantic ownership of questions, but never recursively
        // follows the original chain again. The validated name fits on the stack.
        let mut expanded = [0_u8; Name::MAX_LENGTH + 4];
        let mut end = 0;
        for label in names.labels(name) {
            expanded[end] = label.len() as u8;
            end += 1;
            expanded[end..end + label.len()].copy_from_slice(label);
            end += label.len();
        }
        end += 1; // terminating root, already zeroed
        expanded[end..end + 4].copy_from_slice(fields);
        Query::read(&mut BinDecoder::new(&expanded[..end + 4]))
            .map_err(|error| Self::classify_hickory_question_error(error.into()))
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

    #[cfg(test)]
    fn extract_udp_dns_meta(data: &[u8]) -> Result<Option<ParsedUdpDnsMeta>, &'static str> {
        Self::extract_udp_dns_meta_with_fragments(data, false)
    }

    fn extract_udp_dns_meta_with_fragments(
        data: &[u8],
        allow_first_ipv4_response_fragment: bool,
    ) -> Result<Option<ParsedUdpDnsMeta>, &'static str> {
        let (ethertype, l3_offset, vlan_context) = ethernet_ethertype_and_payload_offset(data)?;
        let payload = &data[l3_offset..];

        let mut meta = match ethertype {
            ETHER_TYPE_IPV4 => Self::extract_udp_dns_from_ipv4(
                payload,
                l3_offset,
                allow_first_ipv4_response_fragment,
            ),
            ETHER_TYPE_IPV6 => Self::extract_udp_dns_from_ipv6(payload, l3_offset),
            _ => Ok(None),
        }?;
        if let Some(meta) = meta.as_mut() {
            meta.vlan_context = vlan_context;
        }
        Ok(meta)
    }

    fn extract_udp_dns_from_ipv4(
        data: &[u8],
        l3_offset: usize,
        allow_first_ipv4_response_fragment: bool,
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

        let total_length = usize::from(Self::parse_u16_at(
            header,
            2,
            "Failed to parse IPv4 packet",
        )?);
        if total_length < header_len {
            return Err("Failed to parse IPv4 packet");
        }
        let datagram = data
            .get(..total_length)
            .ok_or("Failed to parse IPv4 packet")?;

        let flags_and_fragment_offset =
            Self::parse_u16_at(header, 6, "Failed to parse IPv4 packet")?;
        let fragmented =
            flags_and_fragment_offset & (IPV4_MORE_FRAGMENTS | IPV4_FRAGMENT_OFFSET_MASK) != 0;
        let first_fragment = flags_and_fragment_offset & IPV4_MORE_FRAGMENTS != 0
            && flags_and_fragment_offset & IPV4_FRAGMENT_OFFSET_MASK == 0;
        if fragmented && !(allow_first_ipv4_response_fragment && first_fragment) {
            return Ok(None);
        }
        if first_fragment
            && flags_and_fragment_offset & (IPV4_RESERVED_FLAG | IPV4_DONT_FRAGMENT) != 0
        {
            return Err("Contradictory IPv4 fragmentation flags");
        }
        if first_fragment && (total_length - header_len) % 8 != 0 {
            return Err("Non-final IPv4 fragment payload length is not divisible by eight");
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
            &datagram[header_len..],
            src_ip,
            dst_ip,
            l3_offset + header_len,
            first_fragment,
            usize::from(u16::MAX) - header_len,
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

        let payload_length = usize::from(Self::parse_u16_at(
            header,
            4,
            "Failed to parse IPv6 packet",
        )?);
        let packet_length = IPV6_HEADER_LEN
            .checked_add(payload_length)
            .ok_or("Failed to parse IPv6 packet")?;
        let payload = data
            .get(IPV6_HEADER_LEN..packet_length)
            .ok_or("Failed to parse IPv6 packet")?;

        let src_ip = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&header[8..24]).unwrap(),
        ));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&header[24..40]).unwrap(),
        ));

        let mut next_header = header[6];
        let mut cursor = 0;
        loop {
            if next_header == IP_PROTOCOL_UDP {
                return Self::extract_udp_dns_from_transport(
                    &payload[cursor..],
                    src_ip,
                    dst_ip,
                    l3_offset + IPV6_HEADER_LEN + cursor,
                    false,
                    usize::from(u16::MAX),
                );
            }

            let minimum_length = match next_header {
                IPV6_HOP_BY_HOP if cursor != 0 => {
                    return Err("IPv6 Hop-by-Hop header must follow IPv6 header");
                }
                IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DESTINATION_OPTIONS | IPV6_FRAGMENT => 8,
                IP_AUTHENTICATION => 12,
                // Other transport protocols, ESP and No Next Header contain no
                // directly decodable UDP payload at this extraction boundary.
                _ => return Ok(None),
            };
            let extension = payload
                .get(cursor..)
                .filter(|remaining| remaining.len() >= minimum_length)
                .ok_or("IPv6 extension header truncated")?;
            let extension_length = match next_header {
                IPV6_FRAGMENT => {
                    let offset_and_flags = u16::from_be_bytes([extension[2], extension[3]]);
                    if offset_and_flags & IPV6_FRAGMENT_OFFSET_AND_MORE != 0 {
                        // An atomic fragment needs no reassembly; other fragments do.
                        return Ok(None);
                    }
                    8
                }
                IP_AUTHENTICATION => {
                    // AH counts 32-bit words excluding the first two words,
                    // while other extension lengths count 8-octet units.
                    let length = (usize::from(extension[1]) + 2) * 4;
                    if length < minimum_length || length % 8 != 0 {
                        return Err("Invalid IPv6 Authentication header length");
                    }
                    length
                }
                _ => (usize::from(extension[1]) + 1) * 8,
            };
            extension
                .get(..extension_length)
                .ok_or("IPv6 extension header truncated")?;
            next_header = extension[0];
            // Every accepted extension consumes at least eight bytes, so even
            // repeated headers are bounded by the declared IPv6 Payload Length.
            cursor += extension_length;
        }
    }

    fn extract_udp_dns_from_transport(
        data: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        l4_offset: usize,
        partial_first_ipv4_fragment: bool,
        maximum_udp_length: usize,
    ) -> Result<Option<ParsedUdpDnsMeta>, &'static str> {
        if data.len() < UDP_HEADER_LEN {
            return Err("Failed to parse UDP packet");
        }

        let src_port = Self::parse_u16(data, 0)?;
        let dst_port = Self::parse_u16(data, 2)?;
        if !(src_port == DNS_PORT || dst_port == DNS_PORT) {
            return Ok(None);
        }

        let udp_length = usize::from(Self::parse_u16(data, 4)?);
        if udp_length < UDP_HEADER_LEN {
            return Err("Failed to parse UDP packet");
        }
        if udp_length > maximum_udp_length {
            return Err("UDP length exceeds the IP datagram limit");
        }
        let datagram = if partial_first_ipv4_fragment {
            if udp_length <= data.len() {
                return Err("First IPv4 fragment does not contain a partial UDP datagram");
            }
            data
        } else {
            data.get(..udp_length).ok_or("Failed to parse UDP packet")?
        };
        let dns_data = datagram
            .get(UDP_HEADER_LEN..)
            .ok_or("Failed to parse UDP packet")?;
        if dns_data.len() < DNS_HEADER_LEN {
            return Err("DNS data too short");
        }
        let is_response = dns_data[2] & 0x80 != 0;
        if (is_response && src_port != DNS_PORT) || (!is_response && dst_port != DNS_PORT) {
            return Ok(None);
        }
        if partial_first_ipv4_fragment && !is_response {
            // A first-fragment query is not useful for the response-only opt-in mode.
            return Ok(None);
        }

        let dns_offset = l4_offset
            .checked_add(UDP_HEADER_LEN)
            .ok_or("Failed to parse UDP packet")?;

        Ok(Some(ParsedUdpDnsMeta {
            flow_key: Self::canonical_flow_key(src_ip, dst_ip, src_port, dst_port, is_response),
            vlan_context: VlanContext::default(),
            dns_offset_delta: u16::try_from(
                dns_offset
                    .checked_sub(MIN_DNS_OFFSET)
                    .ok_or("UDP DNS offset precedes minimum header length")?,
            )
            .map_err(|_| "UDP DNS offset exceeds supported range")?,
            dns_len: u16::try_from(dns_data.len())
                .map_err(|_| "UDP DNS payload exceeds supported range")?,
            is_response,
            partial_first_ipv4_fragment,
        }))
    }

    fn canonical_flow_key(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        is_response: bool,
    ) -> CanonicalFlowKey {
        if is_response {
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

#[cfg(test)]
mod protocol_regression_tests {
    use super::*;
    use crate::test_support::{encode_dns_header, make_udp_dns_packet_with_payload};

    fn processors() -> [DnsProcessor; 2] {
        [
            DnsProcessor::new(None).unwrap(),
            DnsProcessor::new_with_dns_wire_fast_path(None, true).unwrap(),
        ]
    }

    fn question(flags: u16, query_class: u16) -> Vec<u8> {
        let mut dns = encode_dns_header(0xbeef, flags, 1);
        dns.extend_from_slice(b"\x07example\x03com\0\0\x01");
        dns.extend_from_slice(&query_class.to_be_bytes());
        dns
    }

    fn ipv4(dns: &[u8], response: bool, client_port: u16) -> Vec<u8> {
        let (src, dst, src_port, dst_port) = if response {
            ([8, 8, 8, 8], [10, 0, 0, 1], 53, client_port)
        } else {
            ([10, 0, 0, 1], [8, 8, 8, 8], client_port, 53)
        };
        make_udp_dns_packet_with_payload(src, dst, src_port, dst_port, dns)
    }

    fn with_vlan_tags(packet: &[u8], tags: &[(u16, u16)]) -> Vec<u8> {
        let mut tagged = Vec::with_capacity(packet.len() + tags.len() * 4);
        tagged.extend_from_slice(&packet[..12]);
        for &(ethertype, tci) in tags {
            tagged.extend_from_slice(&ethertype.to_be_bytes());
            tagged.extend_from_slice(&tci.to_be_bytes());
        }
        tagged.extend_from_slice(&packet[12..]);
        tagged
    }

    fn first_ipv4_fragment(mut packet: Vec<u8>, fragment_payload_len: usize) -> Vec<u8> {
        assert_eq!(fragment_payload_len % 8, 0);
        let fragment_len = IPV4_MIN_HEADER_LEN + fragment_payload_len;
        assert!(packet.len() > ETHERNET_HEADER_LEN + fragment_len);
        packet.truncate(ETHERNET_HEADER_LEN + fragment_len);
        packet[ETHERNET_HEADER_LEN + 2..ETHERNET_HEADER_LEN + 4]
            .copy_from_slice(&(fragment_len as u16).to_be_bytes());
        packet[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8]
            .copy_from_slice(&IPV4_MORE_FRAGMENTS.to_be_bytes());
        packet
    }

    fn ipv6(dns: &[u8], extensions: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut payload = Vec::new();
        for (index, (_, extension)) in extensions.iter().enumerate() {
            let mut extension = extension.clone();
            extension[0] = extensions.get(index + 1).map_or(17, |next| next.0);
            payload.extend_from_slice(&extension);
        }
        payload.extend_from_slice(&53000_u16.to_be_bytes());
        payload.extend_from_slice(&53_u16.to_be_bytes());
        payload.extend_from_slice(&u16::try_from(8 + dns.len()).unwrap().to_be_bytes());
        payload.extend_from_slice(&[0, 0]);
        payload.extend_from_slice(dns);

        let mut packet = vec![0; ETHERNET_HEADER_LEN + IPV6_HEADER_LEN];
        packet[12..14].copy_from_slice(&ETHER_TYPE_IPV6.to_be_bytes());
        packet[14] = 0x60;
        packet[18..20].copy_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        packet[20] = extensions.first().map_or(17, |first| first.0);
        packet[21] = 64;
        packet[22..38].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[38..54].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        packet.extend_from_slice(&payload);
        packet
    }

    #[test]
    fn qr_routes_port_53_query_and_response_to_same_flow() {
        let query = ipv4(&question(0x0100, 1), false, 53);
        let response = ipv4(&question(0x8180, 1), true, 53);
        let query_meta = DnsProcessor::packet_routing_meta(&query).unwrap();
        let response_meta = DnsProcessor::packet_routing_meta(&response).unwrap();
        assert!(!query_meta.is_response);
        assert!(response_meta.is_response);
        assert_eq!(query_meta.flow_key, response_meta.flow_key);
        assert_eq!(query_meta.flow_key.client_ip, IpAddr::from([10, 0, 0, 1]));
        assert_eq!(query_meta.flow_key.client_port, 53);

        for processor in processors() {
            let queries = processor.process_packet_batch(&query, 0).unwrap();
            let responses = processor.process_packet_batch(&response, 100).unwrap();
            assert_eq!(queries.len(), 1);
            assert_eq!(responses.len(), 1);
            assert!(queries[0].is_query);
            assert!(!responses[0].is_query);
            assert_eq!(queries[0].src_ip, responses[0].dst_ip);
        }
    }

    #[test]
    fn vlan_and_qinq_frames_route_and_decode_dns() {
        let query_dns = question(0x0100, 1);
        let response_dns = question(0x8180, 1);
        let tags = [
            vec![(ETHER_TYPE_VLAN, 100)],
            vec![(ETHER_TYPE_PROVIDER_BRIDGING, 200), (ETHER_TYPE_VLAN, 100)],
            vec![(ETHER_TYPE_LEGACY_QINQ, 200), (ETHER_TYPE_VLAN, 100)],
        ];

        for tag_stack in &tags {
            let query = with_vlan_tags(&ipv4(&query_dns, false, 53000), tag_stack);
            let response = with_vlan_tags(&ipv4(&response_dns, true, 53000), tag_stack);
            let query_meta = DnsProcessor::packet_routing_meta(&query).expect("tagged query");
            let response_meta =
                DnsProcessor::packet_routing_meta(&response).expect("tagged response");
            assert_eq!(query_meta.flow_key, response_meta.flow_key);
            assert_eq!(query_meta.dns_data(&query), Ok(query_dns.as_slice()));
            assert_eq!(
                response_meta.dns_data(&response),
                Ok(response_dns.as_slice())
            );

            for processor in processors() {
                assert_eq!(processor.process_packet_batch(&query, 0).unwrap().len(), 1);
                assert_eq!(
                    processor
                        .process_packet_batch(&response, 100)
                        .unwrap()
                        .len(),
                    1
                );
            }
        }

        let ipv6_query = with_vlan_tags(
            &ipv6(&query_dns, &[]),
            &[(ETHER_TYPE_PROVIDER_BRIDGING, 200), (ETHER_TYPE_VLAN, 100)],
        );
        let ipv6_meta = DnsProcessor::packet_routing_meta(&ipv6_query).expect("tagged IPv6");
        assert_eq!(ipv6_meta.dns_data(&ipv6_query), Ok(query_dns.as_slice()));
    }

    #[test]
    fn truncated_vlan_tag_is_rejected() {
        let mut frame = vec![0; ETHERNET_HEADER_LEN + 4];
        frame[12..14].copy_from_slice(&ETHER_TYPE_VLAN.to_be_bytes());
        for len in ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + 4 {
            assert_eq!(
                ethernet_ethertype_and_payload_offset(&frame[..len]),
                Err("Failed to parse Ethernet VLAN tag")
            );
        }

        frame[16..18].copy_from_slice(&ETHER_TYPE_VLAN.to_be_bytes());
        assert_eq!(
            ethernet_ethertype_and_payload_offset(&frame),
            Err("Failed to parse Ethernet VLAN tag")
        );
    }

    #[test]
    fn qr_does_not_create_candidates_on_wrong_server_port() {
        for packet in [
            ipv4(&question(0x8180, 1), false, 53000),
            ipv4(&question(0x0100, 1), true, 53000),
        ] {
            assert!(DnsProcessor::packet_routing_meta(&packet).is_none());
        }
    }

    #[test]
    fn opt_in_first_ipv4_response_fragment_requires_complete_question() {
        let mut dns = question(0x8180, 1);
        dns[6..8].copy_from_slice(&1_u16.to_be_bytes());
        dns[10..12].copy_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, 0, 16]);
        dns.extend_from_slice(&[b'x'; 16]);
        dns.extend_from_slice(&[0; 16]);
        let complete = ipv4(&dns, true, 53000);
        let first = first_ipv4_fragment(complete, 40);

        assert!(DnsProcessor::packet_routing_meta(&first).is_none());
        let meta = DnsProcessor::packet_routing_meta_with_fragments(&first, true)
            .expect("first response fragment routes when enabled");
        assert!(meta.partial_first_ipv4_fragment);
        assert_eq!(meta.dns_data(&first).unwrap().len(), 32);

        for processor in processors() {
            let records = match processor.process_packet_batch_with_meta(&first, 100, meta.clone())
            {
                PacketProcessingOutcome::Records(records) => records,
                other => panic!("partial response rejected: {other:?}"),
            };
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].id, 0xbeef);
            assert_eq!(records[0].name.as_str(), "example.com");
            assert!(!records[0].is_query);
            assert!(records[0].partial_first_ipv4_fragment);
            assert!(records[0].partial_response_code.is_none());
        }

        let incomplete_question = first_ipv4_fragment(ipv4(&dns, true, 53000), 24);
        let meta = DnsProcessor::packet_routing_meta_with_fragments(&incomplete_question, true)
            .expect("header-only first fragment routes for decode validation");
        for processor in processors() {
            assert!(matches!(
                processor.process_packet_batch_with_meta(&incomplete_question, 100, meta.clone()),
                PacketProcessingOutcome::Invalid
            ));
        }
    }

    #[test]
    fn opt_in_does_not_accept_other_fragments_or_truncated_unfragmented_responses() {
        let mut dns = question(0x8180, 1);
        dns[6..8].copy_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, 0, 16]);
        dns.extend_from_slice(&[b'x'; 16]);

        let mut query_dns = dns.clone();
        query_dns[2..4].copy_from_slice(&0x0100_u16.to_be_bytes());
        let query_first = first_ipv4_fragment(ipv4(&query_dns, false, 53000), 40);
        assert!(DnsProcessor::packet_routing_meta_with_fragments(&query_first, true).is_none());

        let mut noninitial = first_ipv4_fragment(ipv4(&dns, true, 53000), 40);
        noninitial[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8]
            .copy_from_slice(&(IPV4_MORE_FRAGMENTS | 1).to_be_bytes());
        assert!(DnsProcessor::packet_routing_meta_with_fragments(&noninitial, true).is_none());

        for flags in [
            IPV4_MORE_FRAGMENTS | IPV4_DONT_FRAGMENT,
            IPV4_MORE_FRAGMENTS | IPV4_RESERVED_FLAG,
        ] {
            let mut invalid_flags = first_ipv4_fragment(ipv4(&dns, true, 53000), 40);
            invalid_flags[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8]
                .copy_from_slice(&flags.to_be_bytes());
            assert!(
                DnsProcessor::packet_routing_meta_with_fragments(&invalid_flags, true).is_none()
            );
        }

        let mut truncated_full = first_ipv4_fragment(ipv4(&dns, true, 53000), 40);
        truncated_full[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8]
            .copy_from_slice(&0_u16.to_be_bytes());
        assert!(DnsProcessor::packet_routing_meta_with_fragments(&truncated_full, true).is_none());

        let mut missing_answer = question(0x8180, 1);
        missing_answer[6..8].copy_from_slice(&1_u16.to_be_bytes());
        let full_packet = ipv4(&missing_answer, true, 53000);
        let meta = DnsProcessor::packet_routing_meta_with_fragments(&full_packet, true)
            .expect("complete response routes for strict validation");
        assert!(!meta.partial_first_ipv4_fragment);
        for processor in processors() {
            assert!(matches!(
                processor.process_packet_batch_with_meta(&full_packet, 100, meta.clone()),
                PacketProcessingOutcome::Invalid
            ));
        }
    }

    #[test]
    fn partial_response_code_is_reported_only_when_complete_in_first_fragment() {
        let mut no_additionals = question(0x8183, 1);
        no_additionals[6..8].copy_from_slice(&1_u16.to_be_bytes());
        no_additionals.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, 0, 16]);
        no_additionals.extend_from_slice(&[b'x'; 16]);
        let first = first_ipv4_fragment(ipv4(&no_additionals, true, 53000), 40);
        let meta = DnsProcessor::packet_routing_meta_with_fragments(&first, true).unwrap();
        for processor in processors() {
            let records = match processor.process_packet_batch_with_meta(&first, 100, meta.clone())
            {
                PacketProcessingOutcome::Records(records) => records,
                other => panic!("partial response rejected: {other:?}"),
            };
            assert_eq!(records[0].partial_response_code.unwrap().as_u16(), 3);
        }

        let mut with_opt = question(0x8180, 1);
        with_opt[10..12].copy_from_slice(&1_u16.to_be_bytes());
        with_opt.extend_from_slice(&[0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0]);
        with_opt.extend_from_slice(&[0; 16]);
        let first = first_ipv4_fragment(ipv4(&with_opt, true, 53000), 48);
        let meta = DnsProcessor::packet_routing_meta_with_fragments(&first, true).unwrap();
        for processor in processors() {
            let records = match processor.process_packet_batch_with_meta(&first, 100, meta.clone())
            {
                PacketProcessingOutcome::Records(records) => records,
                other => panic!("partial response rejected: {other:?}"),
            };
            assert_eq!(records[0].partial_response_code.unwrap().as_u16(), 16);
        }

        let mut with_tsig = tsig_response(16, 0, &[]);
        let fragment_payload_len = (UDP_HEADER_LEN + with_tsig.len()).next_multiple_of(8);
        with_tsig.extend_from_slice(&[0; 16]);
        let first = first_ipv4_fragment(ipv4(&with_tsig, true, 53000), fragment_payload_len);
        let meta = DnsProcessor::packet_routing_meta_with_fragments(&first, true).unwrap();
        for processor in processors() {
            let records = match processor.process_packet_batch_with_meta(&first, 100, meta.clone())
            {
                PacketProcessingOutcome::Records(records) => records,
                other => panic!("partial response rejected: {other:?}"),
            };
            assert_eq!(records[0].partial_response_code.unwrap().as_u16(), 16);
            assert_eq!(
                records[0].partial_response_code.unwrap().as_str(),
                "TSIG Failure"
            );
        }
    }

    #[test]
    fn partial_response_rejects_visible_opt_in_answer_even_if_later_record_is_incomplete() {
        let mut dns = question(0x8180, 1);
        dns[6..8].copy_from_slice(&2_u16.to_be_bytes());
        // A complete OPT in the answer section is already invalid, although the
        // following answer extends beyond the first IPv4 fragment.
        dns.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        dns.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, 0, 16]);
        dns.extend_from_slice(&[b'x'; 16]);
        let first = first_ipv4_fragment(ipv4(&dns, true, 53000), 56);
        let meta = DnsProcessor::packet_routing_meta_with_fragments(&first, true).unwrap();
        for processor in processors() {
            assert!(matches!(
                processor.process_packet_batch_with_meta(&first, 100, meta.clone()),
                PacketProcessingOutcome::Invalid
            ));
        }
    }

    #[test]
    fn both_decoders_preserve_query_class_and_every_opcode() {
        for opcode in 0..16 {
            for query_class in [1, 3, 4, 65535] {
                let packet = ipv4(
                    &question(0x0100 | (opcode << 11), query_class),
                    false,
                    53000,
                );
                for processor in processors() {
                    let records = processor.process_packet_batch(&packet, 0).unwrap();
                    assert_eq!(records.len(), 1);
                    assert_eq!(records[0].query_class, query_class);
                    assert_eq!(records[0].opcode, opcode as u8);
                }
            }
        }
    }

    fn tsig_response(error: u16, other_len: u16, other_data: &[u8]) -> Vec<u8> {
        let mut dns = question(if error == 0 { 0x8180 } else { 0x8189 }, 1);
        dns[10..12].copy_from_slice(&1_u16.to_be_bytes());
        let mut rdata = b"\x0bhmac-sha256\0".to_vec();
        rdata.extend_from_slice(&[0; 6]);
        rdata.extend_from_slice(&300_u16.to_be_bytes());
        rdata.extend_from_slice(&32_u16.to_be_bytes());
        rdata.extend_from_slice(&[0; 32]);
        rdata.extend_from_slice(&0xbeef_u16.to_be_bytes());
        rdata.extend_from_slice(&error.to_be_bytes());
        rdata.extend_from_slice(&other_len.to_be_bytes());
        rdata.extend_from_slice(other_data);
        dns.extend_from_slice(b"\x03key\x07example\0");
        dns.extend_from_slice(&DNS_TSIG_RECORD_TYPE.to_be_bytes());
        dns.extend_from_slice(&255_u16.to_be_bytes());
        dns.extend_from_slice(&[0; 4]);
        dns.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        dns.extend_from_slice(&rdata);
        dns
    }

    #[test]
    fn tsig_badtime_accepts_required_server_time_other_data() {
        for (error, other_data) in [(0, &[][..]), (18, &[0, 0, 1, 2, 3, 4][..])] {
            let dns = tsig_response(error, other_data.len() as u16, other_data);
            let packet = ipv4(&dns, true, 53000);
            for processor in processors() {
                let records = processor.process_packet_batch(&packet, 100).unwrap();
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].response_code.as_u16(), error);
            }
        }
    }

    #[test]
    fn tsig_other_data_must_match_declared_length() {
        for (other_len, other_data) in [(6, &[0; 5][..]), (0, &[0; 6][..]), (65535, &[][..])] {
            let packet = ipv4(&tsig_response(18, other_len, other_data), true, 53000);
            for processor in processors() {
                assert!(processor.process_packet_batch(&packet, 100).is_none());
            }
        }
    }

    #[test]
    fn forward_qname_pointer_is_rejected_by_both_decoders() {
        let mut dns = encode_dns_header(0xbeef, 0x8180, 1);
        dns[6..8].copy_from_slice(&1_u16.to_be_bytes());
        // QNAME at offset 12 illegally refers forward to the answer owner at 18.
        dns.extend_from_slice(b"\xc0\x12\0\x01\0\x01\x07example\x03com\0");
        dns.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let packet = ipv4(&dns, true, 53000);
        for processor in processors() {
            assert!(processor.process_packet_batch(&packet, 0).is_none());
        }
    }

    #[test]
    fn compression_rejects_overlapping_names_but_accepts_prior_questions() {
        let overlap = [4, b'a', b'b', 0xc0, 0, 0];
        assert!(
            DnsProcessor::read_wire_domain_name(&mut DnsNameDecoder::new(&overlap, 0), &mut 3)
                .is_err()
        );
        assert!(DnsNameDecoder::new(&overlap, 0).skip(&mut 3).is_err());
        assert!(Name::read(&mut BinDecoder::new(&overlap).clone(3)).is_err());

        let mut dns = question(0x0900, 1);
        dns[4..6].copy_from_slice(&2_u16.to_be_bytes());
        dns.extend_from_slice(b"\xc0\x0c\0\x1c\0\x01");
        for processor in processors() {
            let packet = ipv4(&dns, false, 53000);
            let records = processor.process_packet_batch(&packet, 0).unwrap();
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].name, records[1].name);
            assert_eq!(records[1].query_type, HickoryRecordType::AAAA);
        }
    }

    fn response_with_compression_chain(count: u16) -> (Vec<u8>, usize) {
        let mut dns = question(0x8180, 1);
        dns[6..8].copy_from_slice(&count.to_be_bytes());
        let mut previous_owner = DNS_HEADER_LEN;
        let mut last_owner = 0;
        for index in 0..count {
            last_owner = dns.len();
            dns.extend_from_slice(&(0xc000 | previous_owner as u16).to_be_bytes());
            dns.extend_from_slice(&[0, 16, 0, 1, 0, 0, 0, 60, 0, 2, 1, index as u8]);
            previous_owner = last_owner;
        }
        (dns, last_owner)
    }

    #[test]
    fn compression_limit_counts_cached_suffixes_in_both_decoders() {
        for count in [1, 2, 32, 33, 256] {
            let (dns, _) = response_with_compression_chain(count);
            if count == 33 {
                assert_eq!(Message::from_vec(&dns).unwrap().answers.len(), 33);
            }
            for limit in [1, 32, 33, 0] {
                for processor in processors() {
                    let fast = processor.dns_wire_fast_path;
                    let result = processor
                        .with_max_dns_compression_jumps(limit)
                        .process_packet_batch(&ipv4(&dns, true, 53000), 100);
                    assert_eq!(
                        result.is_some(),
                        limit == 0 || usize::from(count) <= limit,
                        "depth={count}, limit={limit}, fast={fast}"
                    );
                }
            }
        }
        let (dns, _) = response_with_compression_chain(33);
        for processor in processors() {
            assert!(
                processor
                    .process_packet_batch(&ipv4(&dns, true, 53000), 100)
                    .is_none(),
                "default limit must be 32, including after fast-path fallback"
            );
        }
    }

    #[test]
    fn compression_limit_applies_to_questions_and_unlimited_avoids_recursive_decoding() {
        for count in [32, 33, 2700] {
            let mut dns = question(0x0900, 1); // IQUERY permits multiple questions.
            dns[4..6].copy_from_slice(&(count + 1_u16).to_be_bytes());
            let mut previous = DNS_HEADER_LEN;
            for _ in 0..count {
                let current = dns.len();
                dns.extend_from_slice(&(0xc000 | previous as u16).to_be_bytes());
                dns.extend_from_slice(&[0, 1, 0, 1]);
                previous = current;
            }
            for limit in [32, 0] {
                for processor in processors() {
                    let result = processor
                        .with_max_dns_compression_jumps(limit)
                        .process_packet_batch(&ipv4(&dns, false, 53000), 0);
                    assert_eq!(result.is_some(), limit == 0 || count <= 32);
                    if let Some(records) = result {
                        assert_eq!(records.len(), usize::from(count) + 1);
                        assert!(
                            records
                                .iter()
                                .all(|record| record.name.as_str() == "example.com")
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn compression_limit_applies_to_tsig_algorithm_and_partial_responses() {
        let (mut dns, last_owner) = response_with_compression_chain(32);
        dns[10..12].copy_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 18]);
        dns.extend_from_slice(&(0xc000 | last_owner as u16).to_be_bytes());
        dns.extend_from_slice(&[0; 12]); // time, fudge, MAC length and original ID
        dns.extend_from_slice(&[0, 16, 0, 0]); // TSIG error and Other Data length
        for limit in [32, 33, 0] {
            for processor in processors() {
                let result = processor
                    .with_max_dns_compression_jumps(limit)
                    .decode_dns_questions(&dns, true, false);
                assert_eq!(result.is_ok(), limit != 32);
                if let Ok((header, _)) = result {
                    assert_eq!(header.response_code.as_u16(), 16);
                }
            }
        }
        let (mut partial, last_owner) = response_with_compression_chain(33);
        partial.truncate(last_owner + 2); // complete owner, absent RR fields/data
        for processor in processors() {
            assert!(matches!(
                processor.decode_dns_questions(&partial, true, true),
                Err(DnsQuestionDecodeError::Invalid)
            ));
            let (header, _) = processor
                .with_max_dns_compression_jumps(0)
                .decode_dns_questions(&partial, true, true)
                .unwrap();
            assert_eq!(header.partial_response_code.unwrap().as_u16(), 0);
        }
    }

    #[test]
    fn cached_expanded_root_does_not_allow_compressed_opt_owner() {
        let mut dns = encode_dns_header(0xbeef, 0x8180, 1);
        dns[6..8].copy_from_slice(&1_u16.to_be_bytes());
        dns[10..12].copy_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&[0, 0, 1, 0, 1]); // root question
        dns.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 0]);
        dns.extend_from_slice(&[0xc0, 12, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        for processor in processors() {
            assert!(
                processor
                    .process_packet_batch(&ipv4(&dns, true, 53000), 0)
                    .is_none()
            );
        }
    }

    #[test]
    fn overlapping_compression_is_not_treated_as_an_incomplete_fragment() {
        let mut dns = question(0x8180, 1);
        dns[6..8].copy_from_slice(&2_u16.to_be_bytes());
        dns.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 0, 0, 3]);
        let target = dns.len();
        dns.extend_from_slice(&[4, b'a', b'b']);
        // The preceding bytes pretend to be a label crossing this owner's
        // pointer. Those bytes are present; this is overlap, not missing data.
        dns.extend_from_slice(&(0xc000 | target as u16).to_be_bytes());
        for processor in processors() {
            assert!(matches!(
                processor.decode_dns_questions(&dns, true, true),
                Err(DnsQuestionDecodeError::Invalid)
            ));
        }
    }

    #[test]
    fn compression_walkers_reject_cycles_and_truncation() {
        for (case, bytes, offset) in [
            ("self pointer", &[0xc0, 0][..], 0),
            ("pointer cycle", &[0xc0, 2, 0xc0, 0][..], 2),
            ("truncated pointer", &[0xc0][..], 0),
            ("truncated label", &[2, b'a'][..], 0),
        ] {
            let mut read_cursor = offset;
            assert!(
                DnsProcessor::read_wire_domain_name(
                    &mut DnsNameDecoder::new(bytes, 0),
                    &mut read_cursor
                )
                .is_err(),
                "{case}"
            );
            let mut skip_cursor = offset;
            assert!(
                DnsNameDecoder::new(bytes, 0)
                    .skip(&mut skip_cursor)
                    .is_err(),
                "{case}"
            );
        }
    }

    #[test]
    fn ipv6_walks_extension_chains_and_atomic_fragments() {
        let hbh = (IPV6_HOP_BY_HOP, vec![0; 8]);
        let dest = (IPV6_DESTINATION_OPTIONS, vec![0; 8]);
        // An unrecognized Routing Type with Segments Left zero is skipped by IPv6.
        let routing = (IPV6_ROUTING, vec![0, 0, 253, 0, 0, 0, 0, 0]);
        let atomic = (IPV6_FRAGMENT, vec![0; 8]);
        let mut ah = vec![0; 16];
        ah[1] = 2;
        let ah = (IP_AUTHENTICATION, ah);
        let chains = [
            vec![],
            vec![hbh.clone()],
            vec![dest.clone()],
            vec![routing.clone()],
            vec![atomic.clone()],
            vec![ah.clone()],
            vec![hbh, dest.clone(), routing, atomic, ah, dest],
        ];
        let dns = question(0x0100, 1);
        for chain in chains {
            let packet = ipv6(&dns, &chain);
            let meta = DnsProcessor::packet_routing_meta(&packet).unwrap();
            assert_eq!(meta.dns_data(&packet).unwrap(), dns);
            for processor in processors() {
                let records = processor.process_packet_batch(&packet, 0).unwrap();
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].name.as_str(), "example.com");
            }
        }
    }

    #[test]
    fn ipv6_skips_fragments_requiring_reassembly() {
        for flags in [1_u16, 8, 9] {
            let mut fragment = vec![0; 8];
            fragment[2..4].copy_from_slice(&flags.to_be_bytes());
            let packet = ipv6(&question(0x0100, 1), &[(IPV6_FRAGMENT, fragment)]);
            assert!(DnsProcessor::packet_routing_meta(&packet).is_none());
        }
    }

    #[test]
    fn ipv6_extension_lengths_cannot_consume_capture_padding() {
        let dns = question(0x0100, 1);
        for extension_type in [
            IPV6_HOP_BY_HOP,
            IPV6_ROUTING,
            IPV6_FRAGMENT,
            IP_AUTHENTICATION,
            IPV6_DESTINATION_OPTIONS,
        ] {
            let packet = ipv6(&dns, &[(extension_type, vec![0; 8])]);
            for captured_extension_bytes in 0..8_u16 {
                let mut truncated = packet.clone();
                // Keep captured bytes intact while limiting the declared IP payload.
                truncated[18..20].copy_from_slice(&captured_extension_bytes.to_be_bytes());
                assert!(DnsProcessor::extract_udp_dns_meta(&truncated).is_err());
            }
        }
        let mut oversized_extension = ipv6(&dns, &[(IPV6_DESTINATION_OPTIONS, vec![0; 8])]);
        oversized_extension[55] = 255;
        assert!(DnsProcessor::extract_udp_dns_meta(&oversized_extension).is_err());
        for ah_length in [0, 1, 255] {
            let mut ah = vec![0; 16];
            ah[1] = ah_length;
            let packet = ipv6(&dns, &[(IP_AUTHENTICATION, ah)]);
            assert!(DnsProcessor::extract_udp_dns_meta(&packet).is_err());
        }
    }

    #[test]
    fn ipv6_dns_offset_can_exceed_u16_after_long_extension_chain() {
        let dns = question(0x0100, 1);
        let chain = vec![(IPV6_DESTINATION_OPTIONS, vec![0; 8]); 8186];
        let packet = ipv6(&dns, &chain);
        let meta = DnsProcessor::packet_routing_meta(&packet).unwrap();
        assert!(meta.dns_offset() > usize::from(u16::MAX));
        assert_eq!(meta.dns_data(&packet).unwrap(), dns);
        for processor in processors() {
            assert_eq!(processor.process_packet_batch(&packet, 0).unwrap().len(), 1);
        }
    }

    #[test]
    fn dns_offsets_cover_minimum_headers_and_maximum_ip_payloads() {
        for is_ipv6 in [false, true] {
            let ip_header_len = if is_ipv6 {
                IPV6_HEADER_LEN
            } else {
                IPV4_MIN_HEADER_LEN
            };
            let dns_len =
                usize::from(u16::MAX) - UDP_HEADER_LEN - if is_ipv6 { 0 } else { ip_header_len };
            let mut dns = question(0x0100, 1);
            dns[10..12].copy_from_slice(&1_u16.to_be_bytes());
            // Fill the maximum UDP payload with a valid EDNS Padding option.
            let padding_len = dns_len - dns.len() - 11 - 4;
            dns.push(0);
            dns.extend_from_slice(&DNS_OPT_RECORD_TYPE.to_be_bytes());
            dns.extend_from_slice(&u16::MAX.to_be_bytes());
            dns.extend_from_slice(&[0; 4]);
            dns.extend_from_slice(&u16::try_from(4 + padding_len).unwrap().to_be_bytes());
            dns.extend_from_slice(&12_u16.to_be_bytes());
            dns.extend_from_slice(&u16::try_from(padding_len).unwrap().to_be_bytes());
            dns.resize(dns_len, 0);
            let packet = if is_ipv6 {
                ipv6(&dns, &[])
            } else {
                ipv4(&dns, false, 53000)
            };
            let meta = DnsProcessor::packet_routing_meta(&packet).unwrap();
            assert_eq!(
                meta.dns_offset(),
                ETHERNET_HEADER_LEN + ip_header_len + UDP_HEADER_LEN
            );
            assert_eq!(usize::from(meta.dns_len), dns_len);
            assert_eq!(meta.dns_data(&packet).unwrap(), dns);
            if !is_ipv6 {
                assert_eq!(meta.dns_offset_delta, 0);
            }
            for processor in processors() {
                assert_eq!(processor.process_packet_batch(&packet, 0).unwrap().len(), 1);
            }
        }
    }

    #[test]
    fn relative_dns_offset_covers_largest_ipv6_frame_and_extension_prefix() {
        let dns = encode_dns_header(0xbeef, 0x0100, 0);
        // Extension lengths are multiples of eight; this is the largest prefix
        // leaving room for UDP and the minimum 12-byte DNS message.
        let chain = vec![(IPV6_DESTINATION_OPTIONS, vec![0; 8]); 8189];
        let mut packet = ipv6(&dns, &chain);
        packet.extend_from_slice(&[0; 3]);
        packet[18..20].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            packet.len(),
            ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + usize::from(u16::MAX)
        );
        let meta = DnsProcessor::packet_routing_meta(&packet).unwrap();
        assert_eq!(meta.dns_offset(), 65574);
        assert_eq!(meta.dns_data(&packet).unwrap(), dns);
    }
}
