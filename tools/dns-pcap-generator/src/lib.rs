/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

mod artifact;
mod catalog;
mod cli;
mod error;
mod generator;
mod model;
mod packet;
mod profile;
mod rng;

#[cfg(test)]
mod tests;

use clap::Parser;
use cli::{Cli, GeneratorConfig};
use generator::write_capture;
use model::{GenerationSummary, ProfileGenerationDefaults, TrafficProfile};
use profile::validate_profile;
use std::error::Error as StdError;
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::Path;

pub use error::{Error, Result};
pub use profile::is_disallowed_domain;

pub(crate) struct RuntimeProfile {
    inner: TrafficProfile,
}

pub fn report_error(error: &Error) {
    eprintln!("Error: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("Caused by: {cause}");
        source = cause.source();
    }
}

pub(crate) fn load_profile_dir(path: &Path) -> Result<RuntimeProfile> {
    let profile = artifact::load_profile_dir(path)?;
    validate_profile(&profile)?;
    Ok(RuntimeProfile { inner: profile })
}

pub(crate) fn profile_name(profile: &RuntimeProfile) -> &str {
    &profile.inner.name
}

pub(crate) fn profile_generation_defaults(profile: &RuntimeProfile) -> &ProfileGenerationDefaults {
    &profile.inner.generation_defaults
}

pub(crate) fn generate_capture_to_path(
    output: &Path,
    config: &GeneratorConfig,
    profile: &RuntimeProfile,
) -> Result<GenerationSummary> {
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|source| Error::OutputDirectoryCreate {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let file = File::create(output).map_err(|source| Error::OutputCreate {
        path: output.to_path_buf(),
        source,
    })?;
    let writer = BufWriter::new(file);
    let (_, summary) = write_capture(writer, config, &profile.inner)?;
    Ok(summary)
}

pub fn run_generator() -> Result<()> {
    let cli = Cli::parse();
    let profile = load_profile_dir(&cli.profile_dir)?;
    let config = GeneratorConfig::from_cli(
        &cli,
        profile_generation_defaults(&profile),
        profile_name(&profile),
    )?;
    let summary = generate_capture_to_path(&cli.output, &config, &profile)?;

    println!(
        "Wrote {} packets to {} using profile '{}' ({} logical queries, {} duplicate retries, {} responses, {} timeouts, span {:.3}s, seed {}).",
        summary.total_packets(),
        cli.output.display(),
        profile_name(&profile),
        summary.logical_transactions,
        summary.duplicate_query_packets,
        summary.response_packets,
        summary.timed_out_transactions,
        summary.capture_span_seconds(),
        config.seed
    );

    Ok(())
}
