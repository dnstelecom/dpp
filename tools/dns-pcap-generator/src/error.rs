/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use std::io;
use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid value for --qps: expected a finite value greater than 0, got {value}")]
    InvalidQps { value: f64 },

    #[error("--clients must be greater than 0")]
    InvalidClients,

    #[error("invalid value for --clients: expected at most {max}, got {value}")]
    TooManyClients { value: usize, max: usize },

    #[error("--resolvers must be greater than 0")]
    InvalidResolvers,

    #[error("invalid value for --resolvers: expected at most {max}, got {value}")]
    TooManyResolvers { value: usize, max: usize },

    #[error("--duplicate-max must be greater than 0")]
    InvalidDuplicateMax,

    #[error("invalid value for {flag}: expected a value between 0.0 and 1.0, got {value}")]
    RateOutOfRange { flag: &'static str, value: f64 },

    #[error("--transactions must be greater than 0")]
    InvalidTransactions,

    #[error("--duration-seconds must be greater than 0 when --transactions is omitted")]
    InvalidDurationWithoutTransactions,

    #[error("failed to create output directory '{path}'")]
    OutputDirectoryCreate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to create '{path}'")]
    OutputCreate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to initialize PCAP writer")]
    PcapWriterInit {
        #[source]
        source: pcap_file::PcapError,
    },

    #[error("failed to flush PCAP writer")]
    PcapWriterFlush {
        #[source]
        source: pcap_file::PcapError,
    },

    #[error("failed to write generated packet")]
    PcapPacketWrite {
        #[source]
        source: pcap_file::PcapError,
    },

    #[error("invalid catalog row at line {line}")]
    InvalidCatalogRow { line: usize },

    #[error("invalid catalog weight at line {line}")]
    InvalidCatalogWeight {
        line: usize,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error("DNS name cannot be empty")]
    EmptyDnsName,

    #[error("DNS name '{qname}' contains an empty label")]
    EmptyDnsLabel { qname: String },

    #[error("DNS label '{label}' exceeds 63 bytes")]
    DnsLabelTooLong { label: String },

    #[error("profile '{profile}' must expose at least {minimum} positive domains, found {found}")]
    ProfileTooFewPositiveDomains {
        profile: &'static str,
        minimum: usize,
        found: usize,
    },

    #[error("profile '{profile}' contains a disallowed domain '{domain}'")]
    ProfileDisallowedDomain {
        profile: &'static str,
        domain: String,
    },

    #[error("profile '{profile}' has no response code weights")]
    ProfileMissingResponseCodes { profile: &'static str },
}
