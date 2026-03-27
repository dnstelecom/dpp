/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

mod catalog;
mod catalog_builder;
mod cli;
mod error;
mod generator;
mod model;
mod packet;
mod profile;
mod rng;
mod tuning;

#[cfg(test)]
mod tests;

use catalog_builder::{BuilderCli, build_catalog_file};
use clap::Parser;
use cli::{Cli, GeneratorConfig};
use generator::write_capture;
use profile::{profile_for, validate_profile};
use std::error::Error as StdError;
use std::fs::{self, File};
use std::io::BufWriter;

pub use error::{Error, Result};

pub fn report_error(error: &Error) {
    eprintln!("Error: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("Caused by: {cause}");
        source = cause.source();
    }
}

pub fn run_generator() -> Result<()> {
    let cli = Cli::parse();
    let config = GeneratorConfig::try_from(&cli)?;
    let profile = profile_for(cli.profile);
    validate_profile(&profile)?;

    if let Some(parent) = cli
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| Error::OutputDirectoryCreate {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let file = File::create(&cli.output).map_err(|source| Error::OutputCreate {
        path: cli.output.clone(),
        source,
    })?;
    let writer = BufWriter::new(file);
    let (_, summary) = write_capture(writer, &config, &profile)?;

    println!(
        "Wrote {} packets to {} using profile '{}' ({} logical queries, {} duplicate retries, {} responses, {} timeouts, span {:.3}s, seed {}).",
        summary.total_packets(),
        cli.output.display(),
        profile.name,
        summary.logical_transactions,
        summary.duplicate_query_packets,
        summary.response_packets,
        summary.timed_out_transactions,
        summary.capture_span_seconds(),
        config.seed
    );

    Ok(())
}

pub fn run_catalog_builder() -> Result<()> {
    let cli = BuilderCli::parse();
    let summary = build_catalog_file(&cli)?;

    println!(
        "Wrote {} domains to {} from {} CSV rows ({} unique names, {} filtered).",
        summary.emitted_domains,
        cli.output.display(),
        summary.rows_read,
        summary.unique_domains,
        summary.filtered_domains
    );

    Ok(())
}
