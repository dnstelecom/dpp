/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::model::{DnsQuestionType, ResponseCodeKind};
use crate::{Error, Result};
use seahash::hash;
use std::net::Ipv4Addr;

pub(crate) const DNS_PORT: u16 = 53;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
pub(crate) const ROOT_NAME_SERVER_TARGETS: &[&str] = &[
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
];

#[derive(Clone, Copy)]
pub(crate) struct MacPair {
    source: [u8; 6],
    destination: [u8; 6],
}

impl MacPair {
    pub(crate) fn for_query(client: Ipv4Addr, resolver: Ipv4Addr) -> Self {
        Self {
            source: mac_for_ip(client, 0x10),
            destination: mac_for_ip(resolver, 0x53),
        }
    }

    pub(crate) fn for_response(resolver: Ipv4Addr, client: Ipv4Addr) -> Self {
        Self {
            source: mac_for_ip(resolver, 0x53),
            destination: mac_for_ip(client, 0x10),
        }
    }
}

pub(crate) fn build_client_pool(count: usize) -> Vec<Ipv4Addr> {
    (0..count)
        .map(|index| {
            let slot = index as u32;
            let second = 64 + ((slot / (254 * 256)) % 64) as u8;
            let third = ((slot / 254) % 256) as u8;
            let fourth = ((slot % 254) + 1) as u8;
            Ipv4Addr::new(100, second, third, fourth)
        })
        .collect()
}

pub(crate) fn build_resolver_pool(count: usize) -> Vec<Ipv4Addr> {
    (0..count)
        .map(|index| {
            let third = (index / 203) as u8;
            let fourth = 53 + (index % 203) as u8;
            Ipv4Addr::new(172, 20, third, fourth)
        })
        .collect()
}

pub(crate) fn build_udp_dns_ipv4_packet(
    macs: MacPair,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ipv4_identification: u16,
    ttl: u8,
    dns_payload: &[u8],
) -> Vec<u8> {
    let udp_length = (UDP_HEADER_LEN + dns_payload.len()) as u16;
    let total_length = (IPV4_HEADER_LEN + usize::from(udp_length)) as u16;

    let mut packet = Vec::with_capacity(14 + usize::from(total_length));
    packet.extend_from_slice(&macs.destination);
    packet.extend_from_slice(&macs.source);
    packet.extend_from_slice(&0x0800_u16.to_be_bytes());

    let mut ipv4_header = [0_u8; IPV4_HEADER_LEN];
    ipv4_header[0] = 0x45;
    ipv4_header[1] = 0;
    ipv4_header[2..4].copy_from_slice(&total_length.to_be_bytes());
    ipv4_header[4..6].copy_from_slice(&ipv4_identification.to_be_bytes());
    ipv4_header[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    ipv4_header[8] = ttl;
    ipv4_header[9] = 17;
    ipv4_header[12..16].copy_from_slice(&src_ip.octets());
    ipv4_header[16..20].copy_from_slice(&dst_ip.octets());
    let ip_checksum = internet_checksum(&ipv4_header);
    ipv4_header[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet.extend_from_slice(&ipv4_header);

    let mut udp_segment = Vec::with_capacity(usize::from(udp_length));
    udp_segment.extend_from_slice(&src_port.to_be_bytes());
    udp_segment.extend_from_slice(&dst_port.to_be_bytes());
    udp_segment.extend_from_slice(&udp_length.to_be_bytes());
    udp_segment.extend_from_slice(&0_u16.to_be_bytes());
    udp_segment.extend_from_slice(dns_payload);
    let udp_checksum = udp_checksum_ipv4(src_ip, dst_ip, &udp_segment);
    let final_udp_checksum = if udp_checksum == 0 {
        0xffff
    } else {
        udp_checksum
    };
    udp_segment[6..8].copy_from_slice(&final_udp_checksum.to_be_bytes());
    packet.extend_from_slice(&udp_segment);

    packet
}

pub(crate) fn build_dns_query_payload(
    transaction_id: u16,
    qname: &str,
    qtype: DnsQuestionType,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(128);
    payload.extend_from_slice(&transaction_id.to_be_bytes());
    payload.extend_from_slice(&0x0100_u16.to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    append_dns_name(&mut payload, qname)?;
    payload.extend_from_slice(&qtype.code().to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    Ok(payload)
}

pub(crate) fn build_dns_response_payload(
    transaction_id: u16,
    qname: &str,
    qtype: DnsQuestionType,
    response_code: ResponseCodeKind,
    entropy: u64,
) -> Result<Vec<u8>> {
    let answer = build_dns_answer(qname, qtype, response_code, entropy)?;
    let answer_count = answer.is_some() as u16;
    let mut payload = Vec::with_capacity(192);
    payload.extend_from_slice(&transaction_id.to_be_bytes());
    payload.extend_from_slice(&(0x8180_u16 | response_code.code()).to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&answer_count.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    append_dns_name(&mut payload, qname)?;
    payload.extend_from_slice(&qtype.code().to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());

    if let Some((ttl, rdata)) = answer {
        payload.extend_from_slice(&0xc00c_u16.to_be_bytes());
        payload.extend_from_slice(&qtype.code().to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&ttl.to_be_bytes());
        payload.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        payload.extend_from_slice(&rdata);
    }

    Ok(payload)
}

fn build_dns_answer(
    qname: &str,
    qtype: DnsQuestionType,
    response_code: ResponseCodeKind,
    entropy: u64,
) -> Result<Option<(u32, Vec<u8>)>> {
    if response_code != ResponseCodeKind::NoError {
        return Ok(None);
    }

    let ttl = 60 + (entropy % 840) as u32;
    let mut rdata = Vec::new();

    match qtype {
        DnsQuestionType::A => {
            rdata.extend_from_slice(&synthetic_ipv4_for_name(qname).octets());
            Ok(Some((ttl, rdata)))
        }
        DnsQuestionType::Ns => {
            append_dns_name(&mut rdata, root_name_server_target(entropy))?;
            Ok(Some((172_800, rdata)))
        }
        DnsQuestionType::Aaaa => {
            rdata.extend_from_slice(&synthetic_ipv6_for_name(qname));
            Ok(Some((ttl, rdata)))
        }
        DnsQuestionType::Https | DnsQuestionType::Svcb => {
            rdata.extend_from_slice(&1_u16.to_be_bytes());
            rdata.push(0);
            Ok(Some((ttl, rdata)))
        }
        DnsQuestionType::Txt
        | DnsQuestionType::Srv
        | DnsQuestionType::Cname
        | DnsQuestionType::Mx => Ok(None),
    }
}

fn synthetic_ipv4_for_name(name: &str) -> Ipv4Addr {
    let value = hash(name.as_bytes()).to_be_bytes();
    Ipv4Addr::new(203, 0, 113, value[7].max(1))
}

fn synthetic_ipv6_for_name(name: &str) -> [u8; 16] {
    let value = hash(name.as_bytes()).to_be_bytes();
    [
        0x20,
        0x01,
        0x0d,
        0xb8,
        value[0],
        value[1],
        value[2],
        value[3],
        value[4],
        value[5],
        value[6],
        value[7],
        value[0] ^ value[4],
        value[1] ^ value[5],
        value[2] ^ value[6],
        value[3] ^ value[7],
    ]
}

fn append_dns_name(buffer: &mut Vec<u8>, qname: &str) -> Result<()> {
    if qname.is_empty() {
        return Err(Error::EmptyDnsName);
    }

    let canonical = if qname == "." {
        ""
    } else {
        qname.strip_suffix('.').unwrap_or(qname)
    };

    if canonical.is_empty() {
        buffer.push(0);
        return Ok(());
    }

    for label in canonical.split('.') {
        if label.is_empty() {
            return Err(Error::EmptyDnsLabel {
                qname: qname.to_string(),
            });
        }
        if label.len() > 63 {
            return Err(Error::DnsLabelTooLong {
                label: label.to_string(),
            });
        }
        buffer.push(label.len() as u8);
        buffer.extend_from_slice(label.as_bytes());
    }

    buffer.push(0);
    Ok(())
}

fn root_name_server_target(entropy: u64) -> &'static str {
    ROOT_NAME_SERVER_TARGETS[(entropy as usize) % ROOT_NAME_SERVER_TARGETS.len()]
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum_ipv4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(12 + udp_segment.len() + (udp_segment.len() % 2));
    pseudo_header.extend_from_slice(&src_ip.octets());
    pseudo_header.extend_from_slice(&dst_ip.octets());
    pseudo_header.push(0);
    pseudo_header.push(17);
    pseudo_header.extend_from_slice(&(udp_segment.len() as u16).to_be_bytes());
    pseudo_header.extend_from_slice(udp_segment);
    if udp_segment.len() % 2 == 1 {
        pseudo_header.push(0);
    }
    internet_checksum(&pseudo_header)
}

fn mac_for_ip(ip: Ipv4Addr, role: u8) -> [u8; 6] {
    let octets = ip.octets();
    [0x02, role, octets[0], octets[1], octets[2], octets[3]]
}
