/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::config::{
    AppConfig, DEFAULT_MATCH_TIMEOUT_MS, InputSource, MAX_MATCH_TIMEOUT_MS, OutputFormat,
    OutputTarget, ReportFormat, output_target_for_path,
};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Arg, ArgAction, ArgMatches, Command};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::{env, fs, thread};

/// Parses command-line and environment configuration into the canonical runtime config.
pub(crate) fn parse_args() -> Result<AppConfig> {
    let version = env!("CARGO_PKG_VERSION");
    let env_filename = env::var_os("DPP_FILENAME").map(PathBuf::from);
    let env_format = env::var("DPP_FORMAT").ok();
    let env_report_format = env::var("DPP_REPORT_FORMAT").ok();
    let env_match_timeout_ms = env::var("DPP_MATCH_TIMEOUT_MS").ok();
    let env_output_filename = env::var_os("DPP_OUTPUT_FILENAME").map(PathBuf::from);
    let env_silent = parse_env_bool("DPP_SILENT");
    let env_anonymize = env::var_os("DPP_ANONYMIZE").map(PathBuf::from);
    let env_zstd = parse_env_bool("DPP_ZSTD");
    let env_v2 = parse_env_bool("DPP_V2");
    let env_affinity = parse_env_bool("DPP_AFFINITY");
    let env_dns_wire_fast_path = parse_env_bool("DPP_DNS_WIRE_FAST_PATH");
    let env_monotonic_capture = parse_env_bool("DPP_MONOTONIC_CAPTURE");
    let env_threads = env::var("DPP_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    let env_bonded = env::var("DPP_BONDED")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());

    let matches = build_cli(version).get_matches();

    let input_source = matches
        .get_one::<String>("filename")
        .map(PathBuf::from)
        .or(env_filename)
        .map(InputSource::from_path)
        .ok_or_else(|| anyhow!("Input filename is required"))?;
    validate_input_source(&input_source)?;

    let anonymize = matches
        .get_one::<String>("anonymize")
        .map(PathBuf::from)
        .or(env_anonymize);
    validate_anonymize_path(anonymize.as_deref())?;

    let format = resolved_option(&matches, "format", env_format.as_deref(), "csv")
        .parse::<OutputFormat>()?;
    let report_format = resolved_option(
        &matches,
        "report_format",
        env_report_format.as_deref(),
        "text",
    )
    .parse::<ReportFormat>()?;
    let match_timeout_ms = resolve_match_timeout_ms(&matches, env_match_timeout_ms.as_deref())?;

    let num_cpus = thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1);

    let requested_threads = matches
        .get_one::<String>("threads")
        .and_then(|value| value.parse::<usize>().ok())
        .or(env_threads);

    let bonded = matches
        .get_one::<String>("bonded")
        .and_then(|value| value.parse::<usize>().ok())
        .or(env_bonded)
        .unwrap_or(0);

    let output_filename = matches
        .get_one::<String>("output_filename")
        .map(PathBuf::from)
        .or(env_output_filename)
        .unwrap_or_else(|| PathBuf::from(format.default_output_filename()));

    let output_target = output_target_for_path(&output_filename);
    validate_output_path(&output_filename)?;
    validate_output_mode(output_target, format, report_format)?;

    let zstd = matches.get_flag("zstd") || env_zstd;
    let v2 = matches.get_flag("v2") || env_v2;
    let silent = resolve_silent_mode(&matches, env_silent, output_target);
    let affinity = matches.get_flag("affinity") || env_affinity;
    let dns_wire_fast_path = matches.get_flag("dns_wire_fast_path") || env_dns_wire_fast_path;
    let monotonic_capture = matches.get_flag("monotonic_capture") || env_monotonic_capture;

    validate_parquet_only_flags(format, zstd, v2)?;

    Ok(AppConfig {
        input_source,
        output_filename,
        format,
        report_format,
        match_timeout_ms,
        monotonic_capture,
        zstd,
        v2,
        silent,
        num_cpus,
        requested_threads,
        affinity,
        bonded,
        anonymize,
        dns_wire_fast_path,
    })
}

fn build_cli(version: &'static str) -> Command {
    Command::new("DNS Packet Parser (DPP) community edition")
        .version(version)
        .author("Nameto Oy (c) 2026")
        .about("Parses DNS traffic from a PCAP file and exports the results to CSV or Parquet format")
        .after_help(
            "ENVIRONMENT VARIABLES:
  DPP_OUTPUT_FILENAME   Name of the output file (use '-' to write CSV records to stdout; used if [output_filename] argument is not provided)
  DPP_ANONYMIZE         Path to the key file
  DPP_FILENAME          Path to the input PCAP file, or '-' to read the capture from stdin (used if [filename] argument is not provided)
  DPP_AFFINITY          Set to 'true' to use cpu affinity
  DPP_DNS_WIRE_FAST_PATH
                        Set to 'true' to enable the optional question-only DNS wire fast path with hickory fallback
  DPP_MONOTONIC_CAPTURE
                        Set to 'true' to assume globally monotonic packet timestamps, enable batched timeout eviction, and abort on timestamp regressions
  DPP_REPORT_FORMAT     Final process report format: text or json (used if --report-format is not specified; json cannot be combined with stdout output)
  DPP_MATCH_TIMEOUT_MS  DNS match timeout in milliseconds; allowed range is 1..=5000, default is 1200
  DPP_BONDED=N          Set IO channel capacity to 'N'; 0 uses the safe default bounded capacity
  DPP_FORMAT            Output format: csv, parquet, or pq (used if --format option is not specified)
  DPP_SILENT            Set to 'true' to suppress all info-level output messages (used if --silent is not specified)
  DPP_ZSTD              Set to 'true' to use Zstd compression (used if --zstd is not specified, only valid with parquet format)
  DPP_V2                Set to 'true' to use Parquet Version 2 (used if --v2 is not specified, only valid with parquet format)

EXAMPLES:
  dpp -s -f parquet input.pcap dns_output.pq
  dpp input.pcap - > output.csv
  cat input.pcap | dpp - dns_output.csv
  DPP_FILENAME=input.pcap DPP_FORMAT=parquet dpp

LICENSE INFORMATION:
  Nameto Oy (c) 2026. All rights reserved.
  Licensed under GNU GPLv3.
  Commercial licensing options: carrier-support@dnstele.com
  GitHub: https://github.com/dnstelecom/dpp
  ",
        )
        .arg(
            Arg::new("silent")
                .short('s')
                .long("silent")
                .help("Suppress all info-level output messages")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("filename")
                .help("Path to the input PCAP file, or '-' to read the capture stream from stdin")
                .index(1),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .short('f')
                .help("Output format: csv or parquet|pq; stdout output is supported only for csv")
                .num_args(1)
                .value_parser(["csv", "parquet", "pq"]),
        )
        .arg(
            Arg::new("report_format")
                .long("report-format")
                .help("Final process report format: text or json; json cannot be combined with stdout output")
                .value_name("text|json")
                .num_args(1)
                .value_parser(["text", "json"]),
        )
        .arg(
            Arg::new("match_timeout_ms")
                .long("match-timeout-ms")
                .help("DNS query-response match timeout in milliseconds (allowed range: 1..=5000, default: 1200)")
                .value_name("MS")
                .num_args(1),
        )
        .arg(
            Arg::new("monotonic_capture")
                .long("monotonic-capture")
                .help("Assume globally monotonic packet timestamps, enable batched timeout eviction, and abort if a regression is detected")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .short('t')
                .hide(true)
                .value_name("N")
                .num_args(1),
        )
        .arg(
            Arg::new("bonded")
                .long("bonded")
                .short('b')
                .help("Set IO channel capacity to 'N'; 0 uses the safe default bounded capacity")
                .value_name("N")
                .num_args(1),
        )
        .arg(
            Arg::new("zstd")
                .long("zstd")
                .short('z')
                .help("Use Zstd compression (only valid with parquet format)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("v2")
                .long("v2")
                .help("Parquet Version 2 (only valid with parquet format)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("affinity")
                .long("affinity")
                .short('a')
                .help("Use core affinity")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dns_wire_fast_path")
                .long("dns-wire-fast-path")
                .help("Enable the optional question-only DNS wire fast path with hickory fallback")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("anonymize")
                .long("anonymize")
                .help("Name of the key file")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("output_filename")
                .help(
                    "Name of the output file; use '-' to write CSV records to stdout (if not specified, defaults to 'dns_output.csv' or 'dns_output.parquet')",
                )
                .required(false)
                .index(2),
        )
}

fn resolved_option<'a>(
    matches: &'a ArgMatches,
    key: &str,
    env_value: Option<&'a str>,
    default: &'static str,
) -> &'a str {
    matches
        .get_one::<String>(key)
        .map(String::as_str)
        .or(env_value)
        .unwrap_or(default)
}

fn parse_env_bool(key: &str) -> bool {
    env::var(key).is_ok_and(|value| {
        value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("y")
            || value.eq_ignore_ascii_case("yes")
            || value.eq_ignore_ascii_case("enabled")
            || value.eq_ignore_ascii_case("on")
            || value == "1"
    })
}

fn resolve_match_timeout_ms(matches: &ArgMatches, env_value: Option<&str>) -> Result<u64> {
    match matches
        .get_one::<String>("match_timeout_ms")
        .map(String::as_str)
        .or(env_value)
    {
        Some(value) => parse_match_timeout_ms(value),
        None => Ok(DEFAULT_MATCH_TIMEOUT_MS),
    }
}

fn resolve_silent_mode(
    matches: &ArgMatches,
    env_silent: bool,
    output_target: OutputTarget,
) -> bool {
    matches.get_flag("silent") || env_silent || matches!(output_target, OutputTarget::Stdout)
}

fn validate_parquet_only_flags(format: OutputFormat, zstd: bool, v2: bool) -> Result<()> {
    if (zstd || v2) && format != OutputFormat::Parquet {
        bail!(
            "The '--zstd' and '--v2' flags|env_vars can only be used with the '--format parquet' option|env_var."
        );
    }

    Ok(())
}

fn parse_match_timeout_ms(value: &str) -> Result<u64> {
    let timeout_ms = value
        .parse::<u64>()
        .with_context(|| format!("Failed to parse match timeout from '{value}'"))?;

    if timeout_ms == 0 {
        bail!("DNS match timeout must be greater than 0 milliseconds.");
    }

    if timeout_ms > MAX_MATCH_TIMEOUT_MS {
        bail!(
            "DNS match timeout must be less than or equal to {} milliseconds.",
            MAX_MATCH_TIMEOUT_MS
        );
    }

    Ok(timeout_ms)
}

fn validate_output_path(output_path: &Path) -> Result<()> {
    if matches!(output_target_for_path(output_path), OutputTarget::Stdout) {
        return Ok(());
    }

    if output_path.exists() {
        let metadata = fs::symlink_metadata(output_path)
            .context("Failed to retrieve file metadata for the output file")?;
        if metadata.file_type().is_symlink() {
            bail!(
                "Error: The output file points to a symbolic link, aborting to prevent security issues."
            );
        }
    }

    if output_path.is_dir() {
        bail!("Error: The output file path is a directory, not a file.");
    }

    Ok(())
}

fn validate_output_mode(
    output_target: OutputTarget,
    format: OutputFormat,
    report_format: ReportFormat,
) -> Result<()> {
    if output_target == OutputTarget::Stdout && !matches!(format, OutputFormat::Csv) {
        bail!("Error: stdout output is supported only for '--format csv'.");
    }

    if output_target == OutputTarget::Stdout && matches!(report_format, ReportFormat::Json) {
        bail!("Error: '--report-format json' cannot be used when output_filename is '-'.");
    }

    Ok(())
}

fn validate_input_source(input_source: &InputSource) -> Result<()> {
    match input_source {
        InputSource::Stdin => validate_stdin_input(),
        InputSource::File(path) => validate_input_path(path),
    }
}

fn validate_input_path(input_path: &Path) -> Result<()> {
    if !input_path.exists() {
        bail!(
            "Error: The specified pcap file '{}' does not exist.",
            input_path.display()
        );
    }

    let metadata = fs::metadata(input_path).with_context(|| {
        format!(
            "Failed to retrieve metadata for the input pcap file '{}'",
            input_path.display()
        )
    })?;

    if !metadata.is_file() {
        bail!(
            "Error: The input pcap path '{}' is not a regular file.",
            input_path.display()
        );
    }

    Ok(())
}

fn validate_stdin_input() -> Result<()> {
    #[cfg(windows)]
    {
        bail!("Error: Reading the input capture from stdin is not supported on Windows.");
    }

    #[cfg(not(windows))]
    {
        if std::io::stdin().is_terminal() {
            bail!("Error: Input filename '-' requires a PCAP stream on stdin.");
        }
    }

    Ok(())
}

fn validate_anonymize_path(anonymize_path: Option<&Path>) -> Result<()> {
    let Some(anonymize_path) = anonymize_path else {
        return Ok(());
    };

    if !anonymize_path.exists() {
        bail!(
            "Error: The anonymization key file '{}' does not exist.",
            anonymize_path.display()
        );
    }

    let metadata = fs::metadata(anonymize_path).with_context(|| {
        format!(
            "Failed to retrieve metadata for the anonymization key file '{}'",
            anonymize_path.display()
        )
    })?;

    if !metadata.is_file() {
        bail!(
            "Error: The anonymization key path '{}' is not a regular file.",
            anonymize_path.display()
        );
    }

    fs::File::open(anonymize_path).with_context(|| {
        format!(
            "Failed to open the anonymization key file '{}'",
            anonymize_path.display()
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time is valid")
            .as_nanos();
        std::env::temp_dir().join(format!("dpp-{name}-{unique}"))
    }

    #[test]
    fn env_format_wins_when_cli_format_is_absent() {
        let matches = build_cli("test")
            .try_get_matches_from(["dpp", "input.pcap"])
            .expect("cli parses");

        let resolved = resolved_option(&matches, "format", Some("pq"), "csv");

        assert_eq!(resolved, "pq");
        assert_eq!(
            resolved.parse::<OutputFormat>().expect("format parses"),
            OutputFormat::Parquet
        );
    }

    #[test]
    fn cli_format_overrides_env_format() {
        let matches = build_cli("test")
            .try_get_matches_from(["dpp", "--format", "csv", "input.pcap"])
            .expect("cli parses");

        let resolved = resolved_option(&matches, "format", Some("pq"), "csv");

        assert_eq!(resolved, "csv");
    }

    #[test]
    fn env_report_format_wins_when_cli_is_absent() {
        let matches = build_cli("test")
            .try_get_matches_from(["dpp", "input.pcap"])
            .expect("cli parses");

        let resolved = resolved_option(&matches, "report_format", Some("json"), "text");

        assert_eq!(resolved, "json");
        assert_eq!(
            resolved
                .parse::<ReportFormat>()
                .expect("report format parses"),
            ReportFormat::Json
        );
    }

    #[test]
    fn cli_report_format_overrides_env_report_format() {
        let matches = build_cli("test")
            .try_get_matches_from(["dpp", "--report-format", "text", "input.pcap"])
            .expect("cli parses");

        let resolved = resolved_option(&matches, "report_format", Some("json"), "text");

        assert_eq!(resolved, "text");
    }

    #[test]
    fn match_timeout_uses_default_when_not_configured() {
        let matches = build_cli("test")
            .try_get_matches_from(["dpp", "input.pcap"])
            .expect("cli parses");

        let resolved = resolve_match_timeout_ms(&matches, None).expect("timeout resolves");

        assert_eq!(resolved, DEFAULT_MATCH_TIMEOUT_MS);
    }

    #[test]
    fn env_match_timeout_wins_when_cli_is_absent() {
        let matches = build_cli("test")
            .try_get_matches_from(["dpp", "input.pcap"])
            .expect("cli parses");

        let resolved = resolve_match_timeout_ms(&matches, Some("2500")).expect("timeout resolves");

        assert_eq!(resolved, 2_500);
    }

    #[test]
    fn cli_match_timeout_overrides_env_value() {
        let matches = build_cli("test")
            .try_get_matches_from(["dpp", "--match-timeout-ms", "500", "input.pcap"])
            .expect("cli parses");

        let resolved = resolve_match_timeout_ms(&matches, Some("2500")).expect("timeout resolves");

        assert_eq!(resolved, 500);
    }

    #[test]
    fn cli_monotonic_capture_flag_is_recognized() {
        let matches = build_cli("test")
            .try_get_matches_from(["dpp", "--monotonic-capture", "input.pcap"])
            .expect("cli parses");

        assert!(matches.get_flag("monotonic_capture"));
    }

    #[test]
    fn zero_match_timeout_is_rejected() {
        let error = parse_match_timeout_ms("0").expect_err("zero timeout is invalid");

        assert!(
            error
                .to_string()
                .contains("DNS match timeout must be greater than 0 milliseconds.")
        );
    }

    #[test]
    fn match_timeout_above_maximum_is_rejected() {
        let error = parse_match_timeout_ms("5001").expect_err("timeout above maximum is invalid");

        assert!(
            error
                .to_string()
                .contains("DNS match timeout must be less than or equal to 5000 milliseconds.")
        );
    }

    #[test]
    fn missing_anonymize_key_is_rejected_early() {
        let path = unique_temp_path("missing-anonymize.key");

        let error = validate_anonymize_path(Some(path.as_path()))
            .expect_err("missing anonymization key must be rejected");

        assert!(error.to_string().contains("The anonymization key file"));
    }

    #[test]
    fn readable_anonymize_key_is_accepted() {
        let path = unique_temp_path("anonymize.key");
        fs::write(&path, "secret").expect("writes temp anonymization key");

        validate_anonymize_path(Some(path.as_path()))
            .expect("readable anonymization key is accepted");

        fs::remove_file(path).expect("removes temp anonymization key");
    }

    #[test]
    fn stdout_output_sentinel_is_accepted() {
        validate_output_path(Path::new("-")).expect("stdout sentinel is accepted");
    }

    #[test]
    fn stdin_input_sentinel_is_accepted() {
        validate_input_source(&InputSource::from_path(PathBuf::from("-")))
            .expect("stdin sentinel is accepted when the test stdin is not a tty");
    }

    #[test]
    fn missing_input_pcap_is_rejected() {
        let path = unique_temp_path("missing-input.pcap");

        let error = validate_input_path(path.as_path()).expect_err("missing input must fail");

        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn json_report_format_is_rejected_for_stdout_output() {
        let error =
            validate_output_mode(OutputTarget::Stdout, OutputFormat::Csv, ReportFormat::Json)
                .expect_err("json report format must be rejected for stdout output");

        assert!(
            error
                .to_string()
                .contains("'--report-format json' cannot be used when output_filename is '-'")
        );
    }

    #[test]
    fn parquet_format_is_rejected_for_stdout_output() {
        let error = validate_output_mode(
            OutputTarget::Stdout,
            OutputFormat::Parquet,
            ReportFormat::Text,
        )
        .expect_err("parquet format must be rejected for stdout output");

        assert!(
            error
                .to_string()
                .contains("stdout output is supported only for '--format csv'")
        );
    }

    #[test]
    fn text_report_format_is_allowed_for_stdout_output() {
        validate_output_mode(OutputTarget::Stdout, OutputFormat::Csv, ReportFormat::Text)
            .expect("text report format remains valid for stdout output");
    }
}
