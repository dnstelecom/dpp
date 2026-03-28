/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::error::{Error, Result};
use crate::model::{DEFAULT_SEED, DEFAULT_START_EPOCH_SECS, ProfileGenerationDefaults};
use crate::packet::{MAX_SYNTHETIC_CLIENTS, MAX_SYNTHETIC_RESOLVERS};
use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "dns-pcap-generator",
    about = "Generate standalone synthetic DNS classic-PCAP traffic with a sanitized domain catalog"
)]
pub(crate) struct Cli {
    #[arg(value_name = "OUTPUT_PCAP")]
    pub(crate) output: PathBuf,

    #[arg(long, value_name = "DIR", required = true)]
    pub(crate) profile_dir: PathBuf,

    #[arg(long)]
    pub(crate) transactions: Option<u64>,

    #[arg(long)]
    pub(crate) duration_seconds: Option<u64>,

    #[arg(long)]
    pub(crate) qps: Option<f64>,

    #[arg(long)]
    pub(crate) clients: Option<usize>,

    #[arg(long)]
    pub(crate) resolvers: Option<usize>,

    #[arg(long, default_value_t = DEFAULT_SEED)]
    pub(crate) seed: u64,

    #[arg(long, default_value_t = DEFAULT_START_EPOCH_SECS)]
    pub(crate) start_epoch_seconds: u64,
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

impl GeneratorConfig {
    pub(crate) fn from_cli(
        cli: &Cli,
        defaults: &ProfileGenerationDefaults,
        _profile_name: &str,
    ) -> Result<Self> {
        let qps = cli.qps.unwrap_or(defaults.qps);
        if !(qps.is_finite() && qps > 0.0) {
            return Err(Error::InvalidQps { value: qps });
        }

        let clients = cli.clients.unwrap_or(defaults.clients);
        if clients == 0 {
            return Err(Error::InvalidClients);
        }
        if clients > MAX_SYNTHETIC_CLIENTS {
            return Err(Error::TooManyClients {
                value: clients,
                max: MAX_SYNTHETIC_CLIENTS,
            });
        }

        let resolvers = cli.resolvers.unwrap_or(defaults.resolvers);
        if resolvers == 0 {
            return Err(Error::InvalidResolvers);
        }
        if resolvers > MAX_SYNTHETIC_RESOLVERS {
            return Err(Error::TooManyResolvers {
                value: resolvers,
                max: MAX_SYNTHETIC_RESOLVERS,
            });
        }

        let transactions = match cli.transactions {
            Some(value) if value > 0 => value,
            Some(_) => return Err(Error::InvalidTransactions),
            None => {
                let duration_seconds = cli.duration_seconds.unwrap_or(300);
                if duration_seconds == 0 {
                    return Err(Error::InvalidDurationWithoutTransactions);
                }
                ((duration_seconds as f64 * qps).round() as u64).max(1)
            }
        };

        Ok(Self {
            transactions,
            qps,
            clients,
            resolvers,
            duplicate_rate: defaults.duplicate_rate,
            timeout_rate: defaults.timeout_rate,
            duplicate_max: defaults.duplicate_max,
            seed: cli.seed,
            start_epoch_seconds: cli.start_epoch_seconds,
        })
    }
}
