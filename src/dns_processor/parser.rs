/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use hickory_proto::ProtoError;
use hickory_proto::op::Header;
use hickory_proto::op::Message;
use hickory_proto::op::Query;
use hickory_proto::op::ResponseCode as HickoryResponseCode;
use hickory_proto::rr::Name;
use hickory_proto::rr::RecordType as HickoryRecordType;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, DecodeError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::DnsProcessor;
use super::types::ProcessedDnsRecord;
use crate::custom_types::{DnsNameBuf, DnsNameTooLong, ProtoResponseCode};

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const DNS_HEADER_LEN: usize = 12;
const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86dd;
const IP_PROTOCOL_UDP: u8 = 17;
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IP_AUTHENTICATION: u8 = 51;
const IPV6_DESTINATION_OPTIONS: u8 = 60;
const IPV6_FRAGMENT_OFFSET_AND_MORE: u16 = 0xfff9;
const IPV4_MORE_FRAGMENTS: u16 = 0x2000;
const IPV4_FRAGMENT_OFFSET_MASK: u16 = 0x1fff;
const DNS_PORT: u16 = 53;
const DNS_POINTER_MASK: u8 = 0b1100_0000;
const DNS_POINTER_TAG: u8 = 0b1100_0000;
const DNS_LABEL_LEN_MASK: u8 = 0b0011_1111;
const DNS_COMPRESSION_JUMP_LIMIT: usize = 32;
const DNS_RESOURCE_RECORD_FIXED_LEN: usize = 10;
const DNS_OPT_RECORD_TYPE: u16 = 41;
const DNS_TSIG_RECORD_TYPE: u16 = 250;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CanonicalFlowKey {
    pub(super) client_ip: IpAddr,
    pub(super) client_port: u16,
    pub(super) resolver_ip: IpAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ParsedUdpDnsMeta {
    pub(super) flow_key: CanonicalFlowKey,
    pub(super) dns_offset: u32,
    pub(super) dns_len: u16,
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
        let start = self.dns_offset as usize;
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
        let (header, queries) =
            self.decode_dns_questions(meta.dns_data(data)?, meta.is_response)?;

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
            });
        }
    }

    fn decode_dns_questions(
        &self,
        dns_data: &[u8],
        decode_extended_rcode: bool,
    ) -> Result<(DecodedDnsHeader, Vec<DecodedDnsQuestion>), DnsQuestionDecodeError> {
        if self.dns_wire_fast_path {
            Self::decode_dns_questions_fast(dns_data, decode_extended_rcode)
                .or_else(|_| Self::decode_dns_questions_hickory(dns_data, decode_extended_rcode))
        } else {
            Self::decode_dns_questions_hickory(dns_data, decode_extended_rcode)
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

    fn decode_dns_questions_fast(
        dns_data: &[u8],
        decode_extended_rcode: bool,
    ) -> Result<(DecodedDnsHeader, Vec<DecodedDnsQuestion>), DnsQuestionDecodeError> {
        if dns_data.len() < DNS_HEADER_LEN {
            return Err(DnsQuestionDecodeError::Invalid);
        }

        let id = Self::parse_u16_at(dns_data, 0, "Failed to parse DNS header")?;
        let flags = Self::parse_u16_at(dns_data, 2, "Failed to parse DNS header")?;
        let low_response_code = (flags & 0x000f) as u8;
        let query_count = usize::from(Self::parse_u16_at(
            dns_data,
            4,
            "Failed to parse DNS question count",
        )?);

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
        if decode_extended_rcode {
            let additional_count = usize::from(Self::parse_u16_at(
                dns_data,
                10,
                "Failed to parse DNS additional count",
            )?);
            if additional_count > 0 {
                response_code = Self::decode_response_code_with_additionals(
                    dns_data,
                    cursor,
                    DnsSectionCounts {
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
                        additionals: additional_count,
                    },
                    low_response_code,
                )?;
            }
        }
        let header = DecodedDnsHeader {
            id,
            opcode: ((flags >> 11) & 0x0f) as u8,
            response_code,
        };

        Ok((header, queries))
    }

    fn decode_dns_questions_hickory(
        dns_data: &[u8],
        decode_extended_rcode: bool,
    ) -> Result<(DecodedDnsHeader, Vec<DecodedDnsQuestion>), DnsQuestionDecodeError> {
        let mut decoder = BinDecoder::new(dns_data);
        let header = Header::read(&mut decoder).map_err(|_| DnsQuestionDecodeError::Invalid)?;
        let queries = Message::read_queries(&mut decoder, header.counts.queries as usize)
            .map_err(Self::classify_hickory_question_error)?;
        let mut response_code = ProtoResponseCode::from(header.response_code);
        if decode_extended_rcode && header.counts.additionals > 0 {
            response_code = Self::decode_response_code_with_additionals(
                dns_data,
                decoder.index(),
                DnsSectionCounts {
                    answers: header.counts.answers as usize,
                    authorities: header.counts.authorities as usize,
                    additionals: header.counts.additionals as usize,
                },
                header.response_code.low(),
            )?;
        }

        Ok((
            DecodedDnsHeader {
                id: header.id,
                opcode: header.op_code.into(),
                response_code,
            },
            queries
                .into_iter()
                .map(|query: Query| {
                    Ok(DecodedDnsQuestion {
                        name: Self::format_domain_name(query.name())
                            .map_err(|_| DnsQuestionDecodeError::Invalid)?,
                        query_type: query.query_type(),
                        query_class: query.query_class().into(),
                    })
                })
                .collect::<Result<Vec<_>, DnsQuestionDecodeError>>()?,
        ))
    }

    fn decode_response_code_with_additionals(
        dns_data: &[u8],
        mut cursor: usize,
        section_counts: DnsSectionCounts,
        low_response_code: u8,
    ) -> Result<ProtoResponseCode, &'static str> {
        let response_code =
            ProtoResponseCode::from(HickoryResponseCode::from(0, low_response_code));

        Self::skip_dns_resource_records(dns_data, &mut cursor, section_counts.answers, true)?;
        Self::skip_dns_resource_records(dns_data, &mut cursor, section_counts.authorities, true)?;
        let additional_fields = Self::read_additional_response_code_fields(
            dns_data,
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

    fn skip_dns_resource_records(
        dns_data: &[u8],
        cursor: &mut usize,
        count: usize,
        reject_opt: bool,
    ) -> Result<(), &'static str> {
        for _ in 0..count {
            let meta = Self::read_dns_resource_record_meta(dns_data, cursor)?;
            if reject_opt && meta.record_type == DNS_OPT_RECORD_TYPE {
                return Err("OPT record outside additional section");
            }
        }

        Ok(())
    }

    fn read_additional_response_code_fields(
        dns_data: &[u8],
        cursor: &mut usize,
        additional_count: usize,
    ) -> Result<AdditionalResponseCodeFields, &'static str> {
        let mut fields = AdditionalResponseCodeFields::default();
        for index in 0..additional_count {
            let meta = Self::read_dns_resource_record_meta(dns_data, cursor)?;

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

                    fields.tsig_error = Some(Self::read_tsig_error(dns_data, &meta)?);
                }
                _ => {}
            }
        }

        Ok(fields)
    }

    fn read_tsig_error(dns_data: &[u8], meta: &DnsResourceRecordMeta) -> Result<u16, &'static str> {
        let mut cursor = meta.rdata_start;
        let rdata_end = meta.rdata_end;

        Self::skip_wire_domain_name_in_range(dns_data, &mut cursor, rdata_end)?;
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
        cursor: &mut usize,
    ) -> Result<DnsResourceRecordMeta, &'static str> {
        let owner_is_root = Self::skip_wire_domain_name(dns_data, cursor)?;
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
        dns_data: &[u8],
        cursor: &mut usize,
        limit: usize,
    ) -> Result<(), &'static str> {
        if *cursor >= limit {
            return Err("DNS name truncated");
        }

        Self::skip_wire_domain_name(dns_data, cursor)?;
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

    fn skip_wire_domain_name(dns_data: &[u8], cursor: &mut usize) -> Result<bool, &'static str> {
        let start = *cursor;
        let mut position = *cursor;
        let mut resume_position = None;
        let mut jump_count = 0;
        let mut segment_start = position;
        let mut segment_end = dns_data.len();

        loop {
            let length = *dns_data
                .get(..segment_end)
                .and_then(|segment| segment.get(position))
                .ok_or("DNS name truncated")?;

            match length {
                0 => {
                    position += 1;
                    *cursor = resume_position.unwrap_or(position);
                    return Ok(resume_position.is_none() && position == start + 1);
                }
                _ if (length & DNS_POINTER_MASK) == DNS_POINTER_TAG => {
                    let next = *dns_data
                        .get(..segment_end)
                        .and_then(|segment| segment.get(position + 1))
                        .ok_or("DNS compression pointer truncated")?;
                    let offset =
                        (((length & DNS_LABEL_LEN_MASK) as usize) << 8) | usize::from(next);

                    if offset >= segment_start {
                        return Err("DNS compression pointer is not prior to name");
                    }

                    if resume_position.is_none() {
                        resume_position = Some(position + 2);
                    }

                    jump_count += 1;
                    if jump_count > DNS_COMPRESSION_JUMP_LIMIT {
                        return Err("DNS compression pointer loop");
                    }

                    segment_end = segment_start;
                    segment_start = offset;
                    position = offset;
                }
                _ if (length & DNS_POINTER_MASK) != 0 => {
                    return Err("Unsupported DNS label encoding");
                }
                _ => {
                    let label_len = usize::from(length);
                    dns_data
                        .get(..segment_end)
                        .and_then(|segment| segment.get(position + 1..position + 1 + label_len))
                        .ok_or("DNS label truncated")?;
                    position += 1 + label_len;
                }
            }
        }
    }

    fn read_wire_domain_name(
        dns_data: &[u8],
        cursor: &mut usize,
    ) -> Result<DnsNameBuf, DnsQuestionDecodeError> {
        let mut output = DnsNameBuf::default();
        let mut position = *cursor;
        let mut resume_position = None;
        let mut wrote_label = false;
        let mut jump_count = 0;
        let mut expanded_wire_len = 1_usize;
        let mut oversized = false;
        let mut segment_start = position;
        let mut segment_end = dns_data.len();

        loop {
            let length = *dns_data
                .get(..segment_end)
                .and_then(|segment| segment.get(position))
                .ok_or("DNS name truncated")?;

            match length {
                0 => {
                    position += 1;
                    if oversized {
                        return Err(DnsQuestionDecodeError::OversizedQname);
                    }
                    if !wrote_label {
                        output
                            .try_push('.')
                            .map_err(|_| DnsQuestionDecodeError::Invalid)?;
                    }

                    *cursor = resume_position.unwrap_or(position);
                    return Ok(output);
                }
                _ if (length & DNS_POINTER_MASK) == DNS_POINTER_TAG => {
                    let next = *dns_data
                        .get(..segment_end)
                        .and_then(|segment| segment.get(position + 1))
                        .ok_or("DNS compression pointer truncated")?;
                    let offset =
                        (((length & DNS_LABEL_LEN_MASK) as usize) << 8) | usize::from(next);

                    // Each pointer must refer to an earlier, nonoverlapping name,
                    // matching Hickory's question decoder (RFC 1035 section 4.1.4).
                    if offset >= segment_start {
                        return Err(DnsQuestionDecodeError::Invalid);
                    }

                    if resume_position.is_none() {
                        resume_position = Some(position + 2);
                    }

                    jump_count += 1;
                    if jump_count > DNS_COMPRESSION_JUMP_LIMIT {
                        return Err(DnsQuestionDecodeError::Invalid);
                    }

                    segment_end = segment_start;
                    segment_start = offset;
                    position = offset;
                }
                _ if (length & DNS_POINTER_MASK) != 0 => {
                    return Err(DnsQuestionDecodeError::Invalid);
                }
                _ => {
                    let label_len = usize::from(length);
                    let label = dns_data
                        .get(..segment_end)
                        .and_then(|segment| segment.get(position + 1..position + 1 + label_len))
                        .ok_or("DNS label truncated")?;

                    expanded_wire_len = expanded_wire_len.saturating_add(1 + label_len);
                    oversized |= expanded_wire_len > Name::MAX_LENGTH;

                    if !oversized {
                        if wrote_label {
                            output
                                .try_push('.')
                                .map_err(|_| DnsQuestionDecodeError::Invalid)?;
                        }
                        if !Self::write_label_ascii(label, &mut output) {
                            return Err(DnsQuestionDecodeError::Invalid);
                        }
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
        if flags_and_fragment_offset & (IPV4_MORE_FRAGMENTS | IPV4_FRAGMENT_OFFSET_MASK) != 0 {
            // DNS extraction has no IPv4 fragment reassembly stage.
            return Ok(None);
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
        let datagram = data.get(..udp_length).ok_or("Failed to parse UDP packet")?;
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

        let dns_offset = l4_offset
            .checked_add(UDP_HEADER_LEN)
            .ok_or("Failed to parse UDP packet")?;

        Ok(Some(ParsedUdpDnsMeta {
            flow_key: Self::canonical_flow_key(src_ip, dst_ip, src_port, dst_port, is_response),
            dns_offset: u32::try_from(dns_offset)
                .map_err(|_| "UDP DNS offset exceeds supported range")?,
            dns_len: u16::try_from(dns_data.len())
                .map_err(|_| "UDP DNS payload exceeds supported range")?,
            is_response,
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
    fn qr_does_not_create_candidates_on_wrong_server_port() {
        for packet in [
            ipv4(&question(0x8180, 1), false, 53000),
            ipv4(&question(0x0100, 1), true, 53000),
        ] {
            assert!(DnsProcessor::packet_routing_meta(&packet).is_none());
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
        assert!(DnsProcessor::read_wire_domain_name(&overlap, &mut 3).is_err());
        assert!(Name::read(&mut BinDecoder::new(&overlap).clone(3)).is_err());

        let mut dns = question(0x0100, 1);
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
        assert!(meta.dns_offset > u32::from(u16::MAX));
        assert_eq!(meta.dns_data(&packet).unwrap(), dns);
        for processor in processors() {
            assert_eq!(processor.process_packet_batch(&packet, 0).unwrap().len(), 1);
        }
    }
}
