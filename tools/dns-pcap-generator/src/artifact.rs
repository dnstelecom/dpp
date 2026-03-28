/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::catalog::load_catalog_file;
use crate::model::{
    DelayBucket, DelayRange, DnsQuestionType, ExplicitQueryTypeProfile, ProfileGenerationDefaults,
    QueryTypeModel, ResponseCodeKind, ResponseCodeWeight, RetryCountWeight, TrafficProfile,
    TypeWeight,
};
use crate::profile::builtin_negative_domains;
use crate::{Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

const FITTED_PROFILE_FILE_NAME: &str = "fitted-generator.toml";
const FITTED_PROFILE_SCHEMA_VERSION: u32 = 1;
const RESPONSE_DELAY_UNIT_US: &str = "us";
const SHARE_PER_MILLE_TOTAL: u32 = 1000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFittedGeneratorProfile {
    schema_version: u32,
    profile_name: String,
    #[serde(default, rename = "description")]
    _description: Option<String>,
    catalog_path: PathBuf,
    catalog_sha256: String,
    generation_defaults: RawGenerationDefaults,
    latent: RawLatent,
    query_types: RawQueryTypes,
    duplicate_model: RawDuplicateModel,
    response_codes: RawResponseCodes,
    response_delay: RawResponseDelay,
    retry_delay: RawRetryDelay,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGenerationDefaults {
    qps: f64,
    clients: u32,
    resolvers: u32,
    duplicate_max: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLatent {
    logical_timeout_rate: f64,
    duplicate_transaction_rate: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQueryTypes {
    positive: Vec<RawQueryTypeWeight>,
    negative: Vec<RawQueryTypeWeight>,
    reverse: Vec<RawQueryTypeWeight>,
    root: Vec<RawQueryTypeWeight>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQueryTypeWeight {
    qtype: RawDnsQuestionType,
    weight: u32,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum RawDnsQuestionType {
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDuplicateModel {
    retry_count_weights: Vec<RawRetryCountWeight>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRetryCountWeight {
    retry_count: u8,
    weight: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResponseCodes {
    formerr: u32,
    noerror: u32,
    nxdomain: u32,
    notimp: u32,
    refused: u32,
    servfail: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResponseDelay {
    unit: String,
    normal: RawDelayDistribution,
    servfail: RawDelayDistribution,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDelayDistribution {
    buckets: Vec<RawNamedDelayBucket>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNamedDelayBucket {
    name: String,
    share_per_mille: u32,
    range_us: [u64; 2],
    #[serde(default, rename = "note")]
    _note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRetryDelay {
    answered_steps: Vec<RawRetryStep>,
    unanswered_steps: Vec<RawRetryStep>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRetryStep {
    step: u32,
    range_us: [u64; 2],
    #[serde(default)]
    representative_us: Option<u64>,
    #[serde(default, rename = "note")]
    _note: Option<String>,
}

pub(crate) fn load_profile_dir(profile_dir: &Path) -> Result<TrafficProfile> {
    let fitted_path = profile_dir.join(FITTED_PROFILE_FILE_NAME);
    let fitted_toml =
        fs::read_to_string(&fitted_path).map_err(|source| Error::FittedProfileRead {
            path: fitted_path.clone(),
            source,
        })?;
    let fitted: RawFittedGeneratorProfile =
        toml::from_str(&fitted_toml).map_err(|source| Error::FittedProfileParse {
            path: fitted_path.clone(),
            source,
        })?;
    validate_fitted_profile(&fitted, &fitted_path)?;

    let catalog_path = profile_dir.join(&fitted.catalog_path);
    let actual_catalog_sha256 = sha256_file(&catalog_path)?;
    if actual_catalog_sha256 != fitted.catalog_sha256 {
        return Err(Error::CatalogHashMismatch {
            profile_path: fitted_path,
            catalog_path,
            expected_sha256: fitted.catalog_sha256,
            actual_sha256: actual_catalog_sha256,
        });
    }
    let positive_domains = load_catalog_file(&catalog_path)?;

    Ok(TrafficProfile {
        name: fitted.profile_name,
        positive_domains,
        negative_domains: builtin_negative_domains(),
        query_types: QueryTypeModel::Explicit(ExplicitQueryTypeProfile {
            positive: fitted
                .query_types
                .positive
                .into_iter()
                .map(map_query_type_weight)
                .collect(),
            negative: fitted
                .query_types
                .negative
                .into_iter()
                .map(map_query_type_weight)
                .collect(),
            reverse: fitted
                .query_types
                .reverse
                .into_iter()
                .map(map_query_type_weight)
                .collect(),
            root: fitted
                .query_types
                .root
                .into_iter()
                .map(map_query_type_weight)
                .collect(),
        }),
        response_codes: vec![
            ResponseCodeWeight {
                code: ResponseCodeKind::FormErr,
                weight: fitted.response_codes.formerr,
            },
            ResponseCodeWeight {
                code: ResponseCodeKind::NoError,
                weight: fitted.response_codes.noerror,
            },
            ResponseCodeWeight {
                code: ResponseCodeKind::NxDomain,
                weight: fitted.response_codes.nxdomain,
            },
            ResponseCodeWeight {
                code: ResponseCodeKind::NotImp,
                weight: fitted.response_codes.notimp,
            },
            ResponseCodeWeight {
                code: ResponseCodeKind::Refused,
                weight: fitted.response_codes.refused,
            },
            ResponseCodeWeight {
                code: ResponseCodeKind::ServFail,
                weight: fitted.response_codes.servfail,
            },
        ],
        duplicate_retry_counts: fitted
            .duplicate_model
            .retry_count_weights
            .into_iter()
            .map(|weight| RetryCountWeight {
                retry_count: weight.retry_count,
                weight: weight.weight,
            })
            .collect(),
        normal_response_delay_buckets: fitted
            .response_delay
            .normal
            .buckets
            .into_iter()
            .map(|bucket| DelayBucket {
                weight: bucket.share_per_mille,
                min_us: bucket.range_us[0],
                max_us: bucket.range_us[1],
            })
            .collect(),
        servfail_response_delay_buckets: fitted
            .response_delay
            .servfail
            .buckets
            .into_iter()
            .map(|bucket| DelayBucket {
                weight: bucket.share_per_mille,
                min_us: bucket.range_us[0],
                max_us: bucket.range_us[1],
            })
            .collect(),
        answered_retry_delay_ranges: fitted
            .retry_delay
            .answered_steps
            .into_iter()
            .map(|step| DelayRange {
                min_us: step.range_us[0],
                max_us: step.range_us[1],
            })
            .collect(),
        unanswered_retry_delay_ranges: fitted
            .retry_delay
            .unanswered_steps
            .into_iter()
            .map(|step| DelayRange {
                min_us: step.range_us[0],
                max_us: step.range_us[1],
            })
            .collect(),
        generation_defaults: ProfileGenerationDefaults {
            qps: fitted.generation_defaults.qps,
            clients: fitted.generation_defaults.clients as usize,
            resolvers: fitted.generation_defaults.resolvers as usize,
            duplicate_rate: fitted.latent.duplicate_transaction_rate,
            timeout_rate: fitted.latent.logical_timeout_rate,
            duplicate_max: fitted.generation_defaults.duplicate_max,
        },
    })
}

fn validate_fitted_profile(profile: &RawFittedGeneratorProfile, path: &Path) -> Result<()> {
    if profile.schema_version != FITTED_PROFILE_SCHEMA_VERSION {
        return Err(invalid_fitted_profile(
            path,
            format!(
                "unsupported schema_version {}, expected {}",
                profile.schema_version, FITTED_PROFILE_SCHEMA_VERSION
            ),
        ));
    }

    validate_nonempty(
        path,
        "profile_name",
        profile.profile_name.trim().is_empty(),
        "must not be empty",
    )?;
    validate_nonempty(
        path,
        "catalog_path",
        profile.catalog_path.as_os_str().is_empty(),
        "must not be empty",
    )?;
    validate_nonempty(
        path,
        "catalog_sha256",
        profile.catalog_sha256.is_empty(),
        "must not be empty",
    )?;
    if profile.catalog_sha256.len() != 64
        || !profile
            .catalog_sha256
            .chars()
            .all(|ch| ch.is_ascii_hexdigit())
    {
        return Err(invalid_fitted_profile(
            path,
            "catalog_sha256 must be a 64-character hexadecimal SHA-256 digest".to_string(),
        ));
    }

    if !(profile.generation_defaults.qps.is_finite() && profile.generation_defaults.qps > 0.0) {
        return Err(invalid_fitted_profile(
            path,
            format!(
                "generation_defaults.qps must be finite and greater than 0, got {}",
                profile.generation_defaults.qps
            ),
        ));
    }
    if profile.generation_defaults.clients == 0 {
        return Err(invalid_fitted_profile(
            path,
            "generation_defaults.clients must be greater than 0".to_string(),
        ));
    }
    if profile.generation_defaults.resolvers == 0 {
        return Err(invalid_fitted_profile(
            path,
            "generation_defaults.resolvers must be greater than 0".to_string(),
        ));
    }
    if profile.generation_defaults.duplicate_max == 0 {
        return Err(invalid_fitted_profile(
            path,
            "generation_defaults.duplicate_max must be greater than 0".to_string(),
        ));
    }

    validate_probability(
        path,
        "latent.logical_timeout_rate",
        profile.latent.logical_timeout_rate,
    )?;
    validate_probability(
        path,
        "latent.duplicate_transaction_rate",
        profile.latent.duplicate_transaction_rate,
    )?;

    validate_query_type_weights(path, "query_types.positive", &profile.query_types.positive)?;
    validate_query_type_weights(path, "query_types.negative", &profile.query_types.negative)?;
    validate_query_type_weights(path, "query_types.reverse", &profile.query_types.reverse)?;
    validate_query_type_weights(path, "query_types.root", &profile.query_types.root)?;

    validate_retry_count_weights(
        path,
        "duplicate_model.retry_count_weights",
        &profile.duplicate_model.retry_count_weights,
    )?;
    validate_response_codes(path, &profile.response_codes)?;
    validate_response_delay(path, &profile.response_delay)?;
    validate_retry_steps(
        path,
        "retry_delay.answered_steps",
        &profile.retry_delay.answered_steps,
    )?;
    validate_retry_steps(
        path,
        "retry_delay.unanswered_steps",
        &profile.retry_delay.unanswered_steps,
    )?;
    Ok(())
}

fn validate_nonempty(path: &Path, field: &str, empty: bool, message: &str) -> Result<()> {
    if empty {
        return Err(invalid_fitted_profile(path, format!("{field} {message}")));
    }
    Ok(())
}

fn validate_probability(path: &Path, field: &str, value: f64) -> Result<()> {
    if !(value.is_finite() && (0.0..=1.0).contains(&value)) {
        return Err(invalid_fitted_profile(
            path,
            format!("{field} must be a finite probability in [0, 1], got {value}"),
        ));
    }
    Ok(())
}

fn validate_query_type_weights(
    path: &Path,
    field: &str,
    weights: &[RawQueryTypeWeight],
) -> Result<()> {
    if weights.is_empty() {
        return Err(invalid_fitted_profile(
            path,
            format!("{field} must not be empty"),
        ));
    }
    for (index, weight) in weights.iter().enumerate() {
        if weight.weight == 0 {
            return Err(invalid_fitted_profile(
                path,
                format!("{field}[{index}].weight must be greater than 0"),
            ));
        }
    }
    Ok(())
}

fn validate_retry_count_weights(
    path: &Path,
    field: &str,
    weights: &[RawRetryCountWeight],
) -> Result<()> {
    if weights.is_empty() {
        return Err(invalid_fitted_profile(
            path,
            format!("{field} must not be empty"),
        ));
    }
    let mut previous = 0_u8;
    for (index, weight) in weights.iter().enumerate() {
        if weight.retry_count == 0 {
            return Err(invalid_fitted_profile(
                path,
                format!("{field}[{index}].retry_count must be greater than 0"),
            ));
        }
        if weight.weight == 0 {
            return Err(invalid_fitted_profile(
                path,
                format!("{field}[{index}].weight must be greater than 0"),
            ));
        }
        if weight.retry_count <= previous {
            return Err(invalid_fitted_profile(
                path,
                format!("{field} must be strictly increasing by retry_count"),
            ));
        }
        previous = weight.retry_count;
    }
    Ok(())
}

fn validate_response_codes(path: &Path, codes: &RawResponseCodes) -> Result<()> {
    for (field, value) in [
        ("response_codes.formerr", codes.formerr),
        ("response_codes.noerror", codes.noerror),
        ("response_codes.nxdomain", codes.nxdomain),
        ("response_codes.notimp", codes.notimp),
        ("response_codes.refused", codes.refused),
        ("response_codes.servfail", codes.servfail),
    ] {
        if value == 0 {
            return Err(invalid_fitted_profile(
                path,
                format!("{field} must be greater than 0"),
            ));
        }
    }
    Ok(())
}

fn validate_response_delay(path: &Path, response_delay: &RawResponseDelay) -> Result<()> {
    if response_delay.unit != RESPONSE_DELAY_UNIT_US {
        return Err(invalid_fitted_profile(
            path,
            format!(
                "response_delay.unit must be '{RESPONSE_DELAY_UNIT_US}', got '{}'",
                response_delay.unit
            ),
        ));
    }
    validate_delay_distribution(path, "response_delay.normal", &response_delay.normal)?;
    validate_delay_distribution(path, "response_delay.servfail", &response_delay.servfail)?;
    Ok(())
}

fn validate_delay_distribution(
    path: &Path,
    field: &str,
    distribution: &RawDelayDistribution,
) -> Result<()> {
    if distribution.buckets.is_empty() {
        return Err(invalid_fitted_profile(
            path,
            format!("{field}.buckets must not be empty"),
        ));
    }

    let mut names = BTreeSet::new();
    let mut total_share = 0_u32;
    for (index, bucket) in distribution.buckets.iter().enumerate() {
        if bucket.name.trim().is_empty() {
            return Err(invalid_fitted_profile(
                path,
                format!("{field}.buckets[{index}].name must not be empty"),
            ));
        }
        if !names.insert(bucket.name.as_str()) {
            return Err(invalid_fitted_profile(
                path,
                format!("{field}.buckets contains duplicate name '{}'", bucket.name),
            ));
        }
        if bucket.share_per_mille == 0 {
            return Err(invalid_fitted_profile(
                path,
                format!("{field}.buckets[{index}].share_per_mille must be greater than 0"),
            ));
        }
        validate_delay_range(
            path,
            &format!("{field}.buckets[{index}].range_us"),
            bucket.range_us[0],
            bucket.range_us[1],
        )?;
        total_share = total_share
            .checked_add(bucket.share_per_mille)
            .ok_or_else(|| {
                invalid_fitted_profile(path, format!("{field}.buckets share_per_mille overflowed"))
            })?;
    }

    if total_share != SHARE_PER_MILLE_TOTAL {
        return Err(invalid_fitted_profile(
            path,
            format!(
                "{field}.buckets share_per_mille must sum to {SHARE_PER_MILLE_TOTAL}, got {total_share}"
            ),
        ));
    }
    Ok(())
}

fn validate_retry_steps(path: &Path, field: &str, steps: &[RawRetryStep]) -> Result<()> {
    if steps.is_empty() {
        return Err(invalid_fitted_profile(
            path,
            format!("{field} must not be empty"),
        ));
    }
    for (index, step) in steps.iter().enumerate() {
        let expected = (index + 1) as u32;
        if step.step != expected {
            return Err(invalid_fitted_profile(
                path,
                format!(
                    "{field}[{index}].step must be {expected}, got {}",
                    step.step
                ),
            ));
        }
        validate_delay_range(
            path,
            &format!("{field}[{index}].range_us"),
            step.range_us[0],
            step.range_us[1],
        )?;
        if let Some(representative_us) = step.representative_us {
            if representative_us < step.range_us[0] || representative_us > step.range_us[1] {
                return Err(invalid_fitted_profile(
                    path,
                    format!(
                        "{field}[{index}].representative_us must fall inside range_us, got {representative_us}"
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_delay_range(path: &Path, field: &str, min_us: u64, max_us: u64) -> Result<()> {
    if min_us > max_us {
        return Err(invalid_fitted_profile(
            path,
            format!("{field} must satisfy min_us <= max_us"),
        ));
    }
    Ok(())
}

fn invalid_fitted_profile(path: &Path, message: String) -> Error {
    Error::FittedProfileInvalid {
        path: path.to_path_buf(),
        message,
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = fs::File::open(path).map_err(|source| Error::InputHashOpen {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|source| Error::InputHashRead {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn map_query_type_weight(weight: RawQueryTypeWeight) -> TypeWeight {
    TypeWeight {
        qtype: map_query_type(weight.qtype),
        weight: weight.weight,
    }
}

fn map_query_type(qtype: RawDnsQuestionType) -> DnsQuestionType {
    match qtype {
        RawDnsQuestionType::A => DnsQuestionType::A,
        RawDnsQuestionType::Any => DnsQuestionType::Any,
        RawDnsQuestionType::Ns => DnsQuestionType::Ns,
        RawDnsQuestionType::Ptr => DnsQuestionType::Ptr,
        RawDnsQuestionType::Aaaa => DnsQuestionType::Aaaa,
        RawDnsQuestionType::Soa => DnsQuestionType::Soa,
        RawDnsQuestionType::Hinfo => DnsQuestionType::Hinfo,
        RawDnsQuestionType::Naptr => DnsQuestionType::Naptr,
        RawDnsQuestionType::Ds => DnsQuestionType::Ds,
        RawDnsQuestionType::Https => DnsQuestionType::Https,
        RawDnsQuestionType::Svcb => DnsQuestionType::Svcb,
        RawDnsQuestionType::Txt => DnsQuestionType::Txt,
        RawDnsQuestionType::Srv => DnsQuestionType::Srv,
        RawDnsQuestionType::Cname => DnsQuestionType::Cname,
        RawDnsQuestionType::Mx => DnsQuestionType::Mx,
        RawDnsQuestionType::Zero => DnsQuestionType::Zero,
        RawDnsQuestionType::Unknown => DnsQuestionType::Unknown,
    }
}
