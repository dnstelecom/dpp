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

    #[error("failed to read catalog '{path}'")]
    CatalogRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to read fitted profile '{path}'")]
    FittedProfileRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to parse fitted profile '{path}'")]
    FittedProfileParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("invalid fitted profile '{path}': {message}")]
    FittedProfileInvalid {
        path: PathBuf,
        message: String,
    },

    #[error("failed to compute SHA-256 for '{path}'")]
    InputHashOpen {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to read '{path}' while computing SHA-256")]
    InputHashRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error(
        "fitted profile '{profile_path}' references catalog hash {expected_sha256}, but '{catalog_path}' hashed to {actual_sha256}"
    )]
    CatalogHashMismatch {
        profile_path: PathBuf,
        catalog_path: PathBuf,
        expected_sha256: String,
        actual_sha256: String,
    },

    #[error("DNS name cannot be empty")]
    EmptyDnsName,

    #[error("DNS name '{qname}' contains an empty label")]
    EmptyDnsLabel { qname: String },

    #[error("DNS label '{label}' exceeds 63 bytes")]
    DnsLabelTooLong { label: String },

    #[error("profile '{profile}' must expose at least {minimum} positive domains, found {found}")]
    ProfileTooFewPositiveDomains {
        profile: String,
        minimum: usize,
        found: usize,
    },

    #[error("profile '{profile}' contains a disallowed domain '{domain}'")]
    ProfileDisallowedDomain { profile: String, domain: String },

    #[error("profile '{profile}' has no response code weights")]
    ProfileMissingResponseCodes { profile: String },

    #[error("profile '{profile}' has no duplicate retry-count weights")]
    ProfileMissingDuplicateRetryCounts { profile: String },

    #[error("profile '{profile}' has no query-type weights for {category}")]
    ProfileMissingQueryTypeWeights {
        profile: String,
        category: &'static str,
    },

    #[error("profile '{profile}' has no response-delay buckets for {bucket_family}")]
    ProfileMissingResponseDelayBuckets {
        profile: String,
        bucket_family: &'static str,
    },

    #[error("profile '{profile}' has no retry-delay ranges for {range_family}")]
    ProfileMissingRetryDelayRanges {
        profile: String,
        range_family: &'static str,
    },
}
