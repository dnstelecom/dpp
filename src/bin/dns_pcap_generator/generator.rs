/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::cli::GeneratorConfig;
use crate::model::{
    DEFAULT_SNAPLEN, GenerationSummary, ResponseCodeKind, TrafficProfile, WeightedDomain,
};
use crate::packet::{
    DNS_PORT, MacPair, build_client_pool, build_dns_query_payload, build_dns_response_payload,
    build_resolver_pool, build_udp_dns_ipv4_packet,
};
use crate::profile::{qtype_weights_for_negative_domain, qtype_weights_for_positive_domain};
use crate::rng::{SplitMix64, pick_weighted};
use anyhow::{Context, Result};
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::{DataLink, Endianness};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug)]
struct ScheduledPacket {
    timestamp: Duration,
    ordinal: u64,
    bytes: Vec<u8>,
}

impl PartialEq for ScheduledPacket {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp && self.ordinal == other.ordinal
    }
}

impl Eq for ScheduledPacket {}

impl PartialOrd for ScheduledPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .timestamp
            .cmp(&self.timestamp)
            .then_with(|| other.ordinal.cmp(&self.ordinal))
    }
}

pub(crate) fn write_capture<W: Write>(
    writer: W,
    config: &GeneratorConfig,
    profile: &TrafficProfile,
) -> Result<(W, GenerationSummary)> {
    let header = PcapHeader {
        snaplen: DEFAULT_SNAPLEN,
        datalink: DataLink::ETHERNET,
        endianness: Endianness::Little,
        ..Default::default()
    };
    let mut pcap_writer =
        PcapWriter::with_header(writer, header).context("failed to initialize PCAP writer")?;
    let mut state = GeneratorState::new(config, profile);
    state.run(&mut pcap_writer)?;
    pcap_writer.flush().context("failed to flush PCAP writer")?;
    let writer = pcap_writer.into_writer();
    Ok((writer, state.summary))
}

struct GeneratorState<'a> {
    config: &'a GeneratorConfig,
    profile: &'a TrafficProfile,
    rng: SplitMix64,
    pending_packets: BinaryHeap<ScheduledPacket>,
    clients: Vec<Ipv4Addr>,
    resolvers: Vec<Ipv4Addr>,
    next_packet_ordinal: u64,
    current_timestamp: Duration,
    summary: GenerationSummary,
}

impl<'a> GeneratorState<'a> {
    fn new(config: &'a GeneratorConfig, profile: &'a TrafficProfile) -> Self {
        Self {
            config,
            profile,
            rng: SplitMix64::new(config.seed),
            pending_packets: BinaryHeap::new(),
            clients: build_client_pool(config.clients),
            resolvers: build_resolver_pool(config.resolvers),
            next_packet_ordinal: 0,
            current_timestamp: Duration::from_secs(config.start_epoch_seconds),
            summary: GenerationSummary::default(),
        }
    }

    fn run<W: Write>(&mut self, writer: &mut PcapWriter<W>) -> Result<()> {
        for _ in 0..self.config.transactions {
            self.summary.logical_transactions += 1;
            let interarrival = self.sample_interarrival_duration();
            self.current_timestamp += interarrival;

            self.flush_due_packets(writer, self.current_timestamp)?;

            let client = self.clients[self.rng.below(self.clients.len() as u64) as usize];
            let resolver = self.resolvers[self.rng.below(self.resolvers.len() as u64) as usize];
            let source_port = self.rng.range_u16(49_152, 65_000);
            let transaction_id = self.rng.next_u64() as u16;
            let duplicate_count = self.sample_duplicate_count();
            let timed_out = self.rng.chance(self.config.timeout_rate);
            let response_code = (!timed_out).then(|| self.sample_response_code());
            let (qname, qtype) = self.sample_query_identity(response_code);

            let base_query = self.build_query_packet(
                client,
                resolver,
                source_port,
                transaction_id,
                qname.name,
                qtype,
            )?;
            self.write_packet(writer, self.current_timestamp, base_query)?;
            self.summary.query_packets += 1;

            let mut last_query_timestamp = self.current_timestamp;
            for retry_index in 0..duplicate_count {
                last_query_timestamp += self.retry_delay(retry_index);
                let retry_packet = self.build_query_packet(
                    client,
                    resolver,
                    source_port,
                    transaction_id,
                    qname.name,
                    qtype,
                )?;
                self.schedule_packet(last_query_timestamp, retry_packet);
                self.summary.query_packets += 1;
                self.summary.duplicate_query_packets += 1;
            }

            match response_code {
                Some(code) => {
                    let response_timestamp = if duplicate_count == 0 {
                        self.current_timestamp + self.fast_response_delay()
                    } else {
                        last_query_timestamp + self.post_retry_response_delay()
                    };
                    let response_packet = self.build_response_packet(
                        resolver,
                        client,
                        source_port,
                        transaction_id,
                        qname.name,
                        qtype,
                        code,
                    )?;
                    self.schedule_packet(response_timestamp, response_packet);
                    self.summary.response_packets += 1;
                    match code {
                        ResponseCodeKind::NoError => self.summary.noerror_responses += 1,
                        ResponseCodeKind::ServFail => self.summary.servfail_responses += 1,
                        ResponseCodeKind::NxDomain => self.summary.nxdomain_responses += 1,
                    }
                }
                None => {
                    self.summary.timed_out_transactions += 1;
                }
            }
        }

        self.flush_due_packets(writer, Duration::MAX)?;
        Ok(())
    }

    fn sample_interarrival_duration(&mut self) -> Duration {
        let uniform = (1.0 - self.rng.next_f64()).clamp(f64::MIN_POSITIVE, 1.0);
        let seconds = -uniform.ln() / self.config.qps;
        Duration::from_micros((seconds.mul_add(1_000_000.0, 0.0).round() as u64).max(1))
    }

    fn sample_duplicate_count(&mut self) -> u8 {
        if !self.rng.chance(self.config.duplicate_rate) {
            return 0;
        }

        let capped = self.config.duplicate_max.min(3);
        let roll = self.rng.below(100);
        match capped {
            1 => 1,
            2 => {
                if roll < 80 {
                    1
                } else {
                    2
                }
            }
            _ => {
                if roll < 72 {
                    1
                } else if roll < 94 {
                    2
                } else {
                    3
                }
            }
        }
    }

    fn sample_response_code(&mut self) -> ResponseCodeKind {
        pick_weighted(self.profile.response_codes, &mut self.rng, |entry| {
            u64::from(entry.weight)
        })
        .code
    }

    fn sample_query_identity(
        &mut self,
        response_code: Option<ResponseCodeKind>,
    ) -> (&'static WeightedDomain, crate::model::DnsQuestionType) {
        match response_code {
            Some(ResponseCodeKind::NxDomain) => {
                let domain = pick_weighted(self.profile.negative_domains, &mut self.rng, |entry| {
                    u64::from(entry.weight)
                });
                let qtype = pick_weighted(
                    qtype_weights_for_negative_domain(),
                    &mut self.rng,
                    |entry| u64::from(entry.weight),
                )
                .qtype;
                (domain, qtype)
            }
            _ => {
                let domain = pick_weighted(self.profile.positive_domains, &mut self.rng, |entry| {
                    u64::from(entry.weight)
                });
                let qtype = pick_weighted(
                    qtype_weights_for_positive_domain(domain.name),
                    &mut self.rng,
                    |entry| u64::from(entry.weight),
                )
                .qtype;
                (domain, qtype)
            }
        }
    }

    fn retry_delay(&mut self, retry_index: u8) -> Duration {
        let millis = match retry_index {
            0 => self.rng.range_inclusive_u64(70, 140),
            1 => self.rng.range_inclusive_u64(180, 320),
            _ => self.rng.range_inclusive_u64(450, 900),
        };
        Duration::from_millis(millis)
    }

    fn fast_response_delay(&mut self) -> Duration {
        Duration::from_millis(self.rng.range_inclusive_u64(6, 120))
    }

    fn post_retry_response_delay(&mut self) -> Duration {
        Duration::from_millis(self.rng.range_inclusive_u64(25, 90))
    }

    fn schedule_packet(&mut self, timestamp: Duration, bytes: Vec<u8>) {
        let packet = ScheduledPacket {
            timestamp,
            ordinal: self.allocate_packet_ordinal(),
            bytes,
        };
        self.pending_packets.push(packet);
    }

    fn allocate_packet_ordinal(&mut self) -> u64 {
        let ordinal = self.next_packet_ordinal;
        self.next_packet_ordinal += 1;
        ordinal
    }

    fn flush_due_packets<W: Write>(
        &mut self,
        writer: &mut PcapWriter<W>,
        watermark: Duration,
    ) -> Result<()> {
        while matches!(self.pending_packets.peek(), Some(packet) if packet.timestamp <= watermark) {
            let packet = self.pending_packets.pop().expect("peek ensured a packet");
            self.write_packet(writer, packet.timestamp, packet.bytes)?;
        }
        Ok(())
    }

    fn write_packet<W: Write>(
        &mut self,
        writer: &mut PcapWriter<W>,
        timestamp: Duration,
        bytes: Vec<u8>,
    ) -> Result<()> {
        self.summary.first_timestamp.get_or_insert(timestamp);
        self.summary.last_timestamp = Some(timestamp);

        writer
            .write_packet(&PcapPacket::new_owned(timestamp, bytes.len() as u32, bytes))
            .context("failed to write generated packet")?;
        Ok(())
    }

    fn build_query_packet(
        &mut self,
        client: Ipv4Addr,
        resolver: Ipv4Addr,
        source_port: u16,
        transaction_id: u16,
        qname: &str,
        qtype: crate::model::DnsQuestionType,
    ) -> Result<Vec<u8>> {
        let payload = build_dns_query_payload(transaction_id, qname, qtype)?;
        Ok(build_udp_dns_ipv4_packet(
            MacPair::for_query(client, resolver),
            client,
            resolver,
            source_port,
            DNS_PORT,
            self.rng.next_u64() as u16,
            64,
            &payload,
        ))
    }

    fn build_response_packet(
        &mut self,
        resolver: Ipv4Addr,
        client: Ipv4Addr,
        source_port: u16,
        transaction_id: u16,
        qname: &str,
        qtype: crate::model::DnsQuestionType,
        response_code: ResponseCodeKind,
    ) -> Result<Vec<u8>> {
        let payload = build_dns_response_payload(
            transaction_id,
            qname,
            qtype,
            response_code,
            self.rng.next_u64(),
        )?;
        Ok(build_udp_dns_ipv4_packet(
            MacPair::for_response(resolver, client),
            resolver,
            client,
            DNS_PORT,
            source_port,
            self.rng.next_u64() as u16,
            63,
            &payload,
        ))
    }
}
