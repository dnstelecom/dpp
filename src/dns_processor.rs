/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

mod anonymizer;
mod matcher;
mod parser;
mod pipeline;
#[cfg(test)]
mod tests;
mod types;

#[cfg(test)]
use crate::config::DEFAULT_MATCH_TIMEOUT_MS;
pub(crate) use pipeline::ProcessingCounters;
use std::io;
use std::net::IpAddr;
use std::path::Path;

pub struct DnsProcessor {
    anonymizer: anonymizer::Anonymizer,
    dns_wire_fast_path: bool,
    match_timeout_micros: i64,
    monotonic_capture: bool,
}

impl DnsProcessor {
    /// Constructs a new instance of `DnsProcessor`.
    #[cfg(test)]
    pub fn new(anonymize_key_path: Option<&Path>) -> io::Result<Self> {
        Self::new_with_runtime_options(
            anonymize_key_path,
            false,
            i64::try_from(DEFAULT_MATCH_TIMEOUT_MS).expect("default match timeout fits into i64")
                * 1_000,
            false,
        )
    }

    #[cfg(test)]
    pub fn new_with_dns_wire_fast_path(
        anonymize_key_path: Option<&Path>,
        dns_wire_fast_path: bool,
    ) -> io::Result<Self> {
        Self::new_with_runtime_options(
            anonymize_key_path,
            dns_wire_fast_path,
            i64::try_from(DEFAULT_MATCH_TIMEOUT_MS).expect("default match timeout fits into i64")
                * 1_000,
            false,
        )
    }

    pub fn new_with_runtime_options(
        anonymize_key_path: Option<&Path>,
        dns_wire_fast_path: bool,
        match_timeout_micros: i64,
        monotonic_capture: bool,
    ) -> io::Result<Self> {
        Ok(DnsProcessor {
            anonymizer: anonymizer::Anonymizer::new(anonymize_key_path)?,
            dns_wire_fast_path,
            match_timeout_micros,
            monotonic_capture,
        })
    }

    fn anonymize_ip(&self, ip: &IpAddr) -> IpAddr {
        self.anonymizer.anonymize_ip(ip)
    }
}
