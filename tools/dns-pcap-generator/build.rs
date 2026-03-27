/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

const DNS_PCAP_GENERATOR_TUNING_PATH: &str = "config/dns-pcap-generator.toml";
const RESPONSE_DELAY_UNIT_US: &str = "us";
const SHARE_PER_MILLE_TOTAL: u32 = 1000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsPcapGeneratorTuningToml {
    response_codes: ResponseCodesToml,
    response_delay: ResponseDelayToml,
    retry_delay: RetryDelayToml,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseCodesToml {
    noerror: u32,
    nxdomain: u32,
    servfail: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseDelayToml {
    unit: String,
    normal: DelayDistributionToml,
    servfail: DelayDistributionToml,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetryDelayToml {
    answered_ranges_us: Vec<[u64; 2]>,
    unanswered_ranges_us: Vec<[u64; 2]>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelayDistributionToml {
    buckets: Vec<NamedDelayBucketToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedDelayBucketToml {
    name: String,
    share_per_mille: u32,
    range_us: [u64; 2],
    #[serde(rename = "note")]
    _note: Option<String>,
}

pub fn main() -> Result<()> {
    generate_dns_pcap_generator_tuning()
}

fn generate_dns_pcap_generator_tuning() -> Result<()> {
    println!("cargo:rerun-if-changed={DNS_PCAP_GENERATOR_TUNING_PATH}");

    let config_text = fs::read_to_string(DNS_PCAP_GENERATOR_TUNING_PATH)
        .with_context(|| format!("failed to read '{DNS_PCAP_GENERATOR_TUNING_PATH}'"))?;
    let config: DnsPcapGeneratorTuningToml = toml::from_str(&config_text)
        .with_context(|| format!("failed to parse '{DNS_PCAP_GENERATOR_TUNING_PATH}'"))?;
    validate_dns_pcap_generator_tuning(&config)?;

    let out_dir = PathBuf::from(env::var("OUT_DIR").context("OUT_DIR is not set")?);
    let out_path = out_dir.join("dns_pcap_generator_tuning.rs");
    fs::write(&out_path, render_dns_pcap_generator_tuning(&config)?)
        .with_context(|| format!("failed to write '{}'", out_path.display()))?;

    Ok(())
}

fn validate_dns_pcap_generator_tuning(config: &DnsPcapGeneratorTuningToml) -> Result<()> {
    validate_positive_weight("response_codes.noerror", config.response_codes.noerror)?;
    validate_positive_weight("response_codes.nxdomain", config.response_codes.nxdomain)?;
    validate_positive_weight("response_codes.servfail", config.response_codes.servfail)?;
    validate_response_delay_unit(&config.response_delay.unit)?;
    validate_delay_distribution("response_delay.normal", &config.response_delay.normal)?;
    validate_delay_distribution("response_delay.servfail", &config.response_delay.servfail)?;
    validate_delay_ranges(
        "retry_delay.answered_ranges_us",
        &config.retry_delay.answered_ranges_us,
    )?;
    validate_delay_ranges(
        "retry_delay.unanswered_ranges_us",
        &config.retry_delay.unanswered_ranges_us,
    )?;
    Ok(())
}

fn validate_response_delay_unit(unit: &str) -> Result<()> {
    if unit != RESPONSE_DELAY_UNIT_US {
        bail!("response_delay.unit must be '{RESPONSE_DELAY_UNIT_US}'");
    }
    Ok(())
}

fn validate_positive_weight(path: &str, value: u32) -> Result<()> {
    if value == 0 {
        bail!("{path} must be greater than 0");
    }
    Ok(())
}

fn validate_delay_distribution(path: &str, distribution: &DelayDistributionToml) -> Result<()> {
    if distribution.buckets.is_empty() {
        bail!("{path}.buckets must not be empty");
    }

    let mut names = BTreeSet::new();
    let mut total_share_per_mille = 0_u32;

    for (index, bucket) in distribution.buckets.iter().enumerate() {
        let bucket_path = format!("{path}.buckets[{index}]");
        if bucket.name.trim().is_empty() {
            bail!("{bucket_path}.name must not be empty");
        }
        if !names.insert(bucket.name.as_str()) {
            bail!("{path}.buckets contains duplicate name '{}'", bucket.name);
        }

        validate_positive_weight(
            &format!("{bucket_path}.share_per_mille"),
            bucket.share_per_mille,
        )?;
        validate_delay_range(
            &format!("{bucket_path}.range_us"),
            bucket.range_us[0],
            bucket.range_us[1],
        )?;
        total_share_per_mille = total_share_per_mille
            .checked_add(bucket.share_per_mille)
            .with_context(|| format!("{path}.buckets share_per_mille total overflowed"))?;
    }

    if total_share_per_mille != SHARE_PER_MILLE_TOTAL {
        bail!(
            "{path}.buckets share_per_mille must sum to {SHARE_PER_MILLE_TOTAL}, got {total_share_per_mille}"
        );
    }

    Ok(())
}

fn validate_delay_ranges(path: &str, ranges: &[[u64; 2]]) -> Result<()> {
    if ranges.is_empty() {
        bail!("{path} must not be empty");
    }

    for (index, range) in ranges.iter().enumerate() {
        validate_delay_range(&format!("{path}[{index}]"), range[0], range[1])?;
    }

    Ok(())
}

fn validate_delay_range(path: &str, min_us: u64, max_us: u64) -> Result<()> {
    if min_us > max_us {
        bail!("{path} must satisfy min_us <= max_us");
    }
    Ok(())
}

fn render_dns_pcap_generator_tuning(config: &DnsPcapGeneratorTuningToml) -> Result<String> {
    let mut output = String::new();
    output.push_str("// @generated by build.rs from config/dns-pcap-generator.toml\n\n");

    writeln!(
        output,
        "pub(crate) const RESPONSE_CODES: &[ResponseCodeWeight] = &["
    )?;
    writeln!(
        output,
        "    ResponseCodeWeight {{ code: ResponseCodeKind::NoError, weight: {} }},",
        config.response_codes.noerror
    )?;
    writeln!(
        output,
        "    ResponseCodeWeight {{ code: ResponseCodeKind::NxDomain, weight: {} }},",
        config.response_codes.nxdomain
    )?;
    writeln!(
        output,
        "    ResponseCodeWeight {{ code: ResponseCodeKind::ServFail, weight: {} }},",
        config.response_codes.servfail
    )?;
    output.push_str("];\n\n");

    render_weighted_delay_buckets(
        &mut output,
        "NORMAL_RESPONSE_DELAY_BUCKETS",
        &config.response_delay.normal,
    )?;
    render_weighted_delay_buckets(
        &mut output,
        "SERVFAIL_RESPONSE_DELAY_BUCKETS",
        &config.response_delay.servfail,
    )?;
    render_delay_ranges(
        &mut output,
        "ANSWERED_RETRY_DELAY_RANGES",
        &config.retry_delay.answered_ranges_us,
    )?;
    render_delay_ranges(
        &mut output,
        "UNANSWERED_RETRY_DELAY_RANGES",
        &config.retry_delay.unanswered_ranges_us,
    )?;

    Ok(output)
}

fn render_weighted_delay_buckets(
    output: &mut String,
    const_name: &str,
    distribution: &DelayDistributionToml,
) -> Result<()> {
    writeln!(output, "pub(crate) const {const_name}: &[DelayBucket] = &[")?;
    let mut buckets = distribution.buckets.iter().collect::<Vec<_>>();
    buckets.sort_by(|left, right| {
        left.range_us[0]
            .cmp(&right.range_us[0])
            .then(left.range_us[1].cmp(&right.range_us[1]))
            .then(left.name.cmp(&right.name))
    });
    for bucket in buckets {
        writeln!(
            output,
            "    DelayBucket {{ weight: {}, min_us: {}, max_us: {} }},",
            bucket.share_per_mille, bucket.range_us[0], bucket.range_us[1]
        )?;
    }
    output.push_str("];\n\n");
    Ok(())
}

fn render_delay_ranges(output: &mut String, const_name: &str, ranges: &[[u64; 2]]) -> Result<()> {
    writeln!(output, "pub(crate) const {const_name}: &[DelayRange] = &[")?;
    for range in ranges {
        writeln!(
            output,
            "    DelayRange {{ min_us: {}, max_us: {} }},",
            range[0], range[1]
        )?;
    }
    output.push_str("];\n\n");
    Ok(())
}
