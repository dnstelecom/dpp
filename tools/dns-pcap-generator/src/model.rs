/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use std::borrow::Cow;
use std::time::Duration;

pub(crate) const DEFAULT_SNAPLEN: u32 = 262_144;
pub(crate) const DEFAULT_START_EPOCH_SECS: u64 = 1_719_792_000;
pub(crate) const DEFAULT_SEED: u64 = 0x5eed_f00d_cafe_beef;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DnsQuestionType {
    A,
    Any,
    Ns,
    Ptr,
    Aaaa,
    Soa,
    Hinfo,
    Naptr,
    Ds,
    Https,
    Svcb,
    Txt,
    Srv,
    Cname,
    Mx,
    Zero,
    Unknown,
}

impl DnsQuestionType {
    pub(crate) const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Zero => 0,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Hinfo => 13,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Naptr => 35,
            Self::Ds => 43,
            Self::Svcb => 64,
            Self::Https => 65,
            Self::Any => 255,
            // Hypothesis: DPP renders this synthetic private-use code as "Unknown",
            // which keeps the fitted qtype tail representable without binding runtime
            // behavior to a specific opaque code from the reference capture.
            Self::Unknown => 65_280,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseCodeKind {
    FormErr,
    NoError,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
}

impl ResponseCodeKind {
    pub(crate) const fn code(self) -> u16 {
        match self {
            Self::FormErr => 1,
            Self::NoError => 0,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TypeWeight {
    pub(crate) qtype: DnsQuestionType,
    pub(crate) weight: u32,
}

#[derive(Clone, Debug)]
pub(crate) enum QueryTypeModel {
    Explicit(ExplicitQueryTypeProfile),
}

#[derive(Clone, Debug)]
pub(crate) struct ExplicitQueryTypeProfile {
    pub(crate) positive: Vec<TypeWeight>,
    pub(crate) negative: Vec<TypeWeight>,
    pub(crate) reverse: Vec<TypeWeight>,
    pub(crate) root: Vec<TypeWeight>,
}

#[derive(Clone, Debug)]
pub(crate) struct WeightedDomain {
    pub(crate) name: Cow<'static, str>,
    pub(crate) weight: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ResponseCodeWeight {
    pub(crate) code: ResponseCodeKind,
    pub(crate) weight: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryCountWeight {
    pub(crate) retry_count: u8,
    pub(crate) weight: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DelayBucket {
    pub(crate) weight: u32,
    pub(crate) min_us: u64,
    pub(crate) max_us: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DelayRange {
    pub(crate) min_us: u64,
    pub(crate) max_us: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProfileGenerationDefaults {
    pub(crate) qps: f64,
    pub(crate) clients: usize,
    pub(crate) resolvers: usize,
    pub(crate) duplicate_rate: f64,
    pub(crate) timeout_rate: f64,
    pub(crate) duplicate_max: u8,
}

#[derive(Clone, Debug)]
pub(crate) struct TrafficProfile {
    pub(crate) name: String,
    pub(crate) positive_domains: Vec<WeightedDomain>,
    pub(crate) negative_domains: Vec<WeightedDomain>,
    pub(crate) query_types: QueryTypeModel,
    pub(crate) response_codes: Vec<ResponseCodeWeight>,
    pub(crate) duplicate_retry_counts: Vec<RetryCountWeight>,
    pub(crate) normal_response_delay_buckets: Vec<DelayBucket>,
    pub(crate) servfail_response_delay_buckets: Vec<DelayBucket>,
    pub(crate) answered_retry_delay_ranges: Vec<DelayRange>,
    pub(crate) unanswered_retry_delay_ranges: Vec<DelayRange>,
    pub(crate) generation_defaults: ProfileGenerationDefaults,
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
