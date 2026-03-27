/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::model::{DEFAULT_SEED, DEFAULT_START_EPOCH_SECS};
use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "dns-pcap-generator",
    about = "Generate standalone synthetic DNS classic-PCAP traffic without client-specific or Russian domains"
)]
pub(crate) struct Cli {
    #[arg(value_name = "OUTPUT_PCAP")]
    pub(crate) output: PathBuf,

    #[arg(long, value_enum, default_value_t = ProfileKind::Server1Jul2024Sanitized)]
    pub(crate) profile: ProfileKind,

    #[arg(long)]
    pub(crate) transactions: Option<u64>,

    #[arg(long, default_value_t = 300)]
    pub(crate) duration_seconds: u64,

    #[arg(long, default_value_t = 1200.0)]
    pub(crate) qps: f64,

    #[arg(long, default_value_t = 2048)]
    pub(crate) clients: usize,

    #[arg(long, default_value_t = 3)]
    pub(crate) resolvers: usize,

    #[arg(long, default_value_t = 0.08)]
    pub(crate) duplicate_rate: f64,

    #[arg(long, default_value_t = 0.03)]
    pub(crate) timeout_rate: f64,

    #[arg(long, default_value_t = 3)]
    pub(crate) duplicate_max: u8,

    #[arg(long, default_value_t = DEFAULT_SEED)]
    pub(crate) seed: u64,

    #[arg(long, default_value_t = DEFAULT_START_EPOCH_SECS)]
    pub(crate) start_epoch_seconds: u64,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ProfileKind {
    Server1Jul2024Sanitized,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct GeneratorConfig {
    pub(crate) transactions: u64,
    pub(crate) qps: f64,
    pub(crate) clients: usize,
    pub(crate) resolvers: usize,
    pub(crate) duplicate_rate: f64,
    pub(crate) timeout_rate: f64,
    pub(crate) duplicate_max: u8,
    pub(crate) seed: u64,
    pub(crate) start_epoch_seconds: u64,
}

impl TryFrom<&Cli> for GeneratorConfig {
    type Error = anyhow::Error;

    fn try_from(cli: &Cli) -> Result<Self> {
        if !(cli.qps.is_finite() && cli.qps > 0.0) {
            bail!("--qps must be a finite value greater than 0");
        }
        if cli.clients == 0 {
            bail!("--clients must be greater than 0");
        }
        if cli.resolvers == 0 {
            bail!("--resolvers must be greater than 0");
        }
        if cli.resolvers > 203 * 256 {
            bail!(
                "--resolvers must be at most {} (203 addresses × 256 subnets)",
                203 * 256
            );
        }
        if cli.duplicate_max == 0 {
            bail!("--duplicate-max must be greater than 0");
        }
        for (flag, value) in [
            ("--duplicate-rate", cli.duplicate_rate),
            ("--timeout-rate", cli.timeout_rate),
        ] {
            if !(0.0..=1.0).contains(&value) {
                bail!("{flag} must be between 0.0 and 1.0");
            }
        }

        let transactions = match cli.transactions {
            Some(value) if value > 0 => value,
            Some(_) => bail!("--transactions must be greater than 0"),
            None => {
                if cli.duration_seconds == 0 {
                    bail!(
                        "--duration-seconds must be greater than 0 when --transactions is omitted"
                    );
                }
                ((cli.duration_seconds as f64 * cli.qps).round() as u64).max(1)
            }
        };

        Ok(Self {
            transactions,
            qps: cli.qps,
            clients: cli.clients,
            resolvers: cli.resolvers,
            duplicate_rate: cli.duplicate_rate,
            timeout_rate: cli.timeout_rate,
            duplicate_max: cli.duplicate_max,
            seed: cli.seed,
            start_epoch_seconds: cli.start_epoch_seconds,
        })
    }
}
