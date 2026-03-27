/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use std::time::Duration;

pub(crate) const DEFAULT_SNAPLEN: u32 = 262_144;
pub(crate) const DEFAULT_START_EPOCH_SECS: u64 = 1_719_792_000;
pub(crate) const DEFAULT_SEED: u64 = 0x5eed_f00d_cafe_beef;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DnsQuestionType {
    A,
    Ns,
    Aaaa,
    Https,
    Svcb,
    Txt,
    Srv,
    Cname,
    Mx,
}

impl DnsQuestionType {
    pub(crate) const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Aaaa => 28,
            Self::Cname => 5,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Srv => 33,
            Self::Svcb => 64,
            Self::Https => 65,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseCodeKind {
    NoError,
    ServFail,
    NxDomain,
}

impl ResponseCodeKind {
    pub(crate) const fn code(self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::ServFail => 2,
            Self::NxDomain => 3,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TypeWeight {
    pub(crate) qtype: DnsQuestionType,
    pub(crate) weight: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct WeightedDomain {
    pub(crate) name: &'static str,
    pub(crate) weight: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ResponseCodeWeight {
    pub(crate) code: ResponseCodeKind,
    pub(crate) weight: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TrafficProfile {
    pub(crate) name: &'static str,
    pub(crate) positive_domains: &'static [WeightedDomain],
    pub(crate) negative_domains: &'static [WeightedDomain],
    pub(crate) response_codes: &'static [ResponseCodeWeight],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct GenerationSummary {
    pub(crate) logical_transactions: u64,
    pub(crate) query_packets: u64,
    pub(crate) duplicate_query_packets: u64,
    pub(crate) response_packets: u64,
    pub(crate) timed_out_transactions: u64,
    pub(crate) noerror_responses: u64,
    pub(crate) servfail_responses: u64,
    pub(crate) nxdomain_responses: u64,
    pub(crate) first_timestamp: Option<Duration>,
    pub(crate) last_timestamp: Option<Duration>,
}

impl GenerationSummary {
    pub(crate) fn total_packets(&self) -> u64 {
        self.query_packets + self.response_packets
    }

    pub(crate) fn capture_span_seconds(&self) -> f64 {
        match (self.first_timestamp, self.last_timestamp) {
            (Some(first), Some(last)) if last >= first => (last - first).as_secs_f64(),
            _ => 0.0,
        }
    }
}
