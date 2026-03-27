/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

#[path = "dns_pcap_generator/catalog.rs"]
mod catalog;
#[path = "dns_pcap_generator/cli.rs"]
mod cli;
#[path = "dns_pcap_generator/generator.rs"]
mod generator;
#[path = "dns_pcap_generator/model.rs"]
mod model;
#[path = "dns_pcap_generator/packet.rs"]
mod packet;
#[path = "dns_pcap_generator/profile.rs"]
mod profile;
#[path = "dns_pcap_generator/rng.rs"]
mod rng;

#[cfg(test)]
#[path = "dns_pcap_generator/tests.rs"]
mod tests;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, GeneratorConfig};
use generator::write_capture;
use profile::{profile_for, validate_profile};
use std::fs::{self, File};
use std::io::BufWriter;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = GeneratorConfig::try_from(&cli)?;
    let profile = profile_for(cli.profile);
    validate_profile(&profile)?;

    if let Some(parent) = cli
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory '{}'", parent.display()))?;
    }

    let file = File::create(&cli.output)
        .with_context(|| format!("failed to create '{}'", cli.output.display()))?;
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
