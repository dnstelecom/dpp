/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::error::{Error, Result};
use crate::model::{DEFAULT_SEED, DEFAULT_START_EPOCH_SECS};
use crate::packet::{MAX_SYNTHETIC_CLIENTS, MAX_SYNTHETIC_RESOLVERS};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "dns-pcap-generator",
    about = "Generate standalone synthetic DNS classic-PCAP traffic with a sanitized domain catalog"
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
    #[value(name = "server1-jul-2024-sanitized")]
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
    type Error = Error;

    fn try_from(cli: &Cli) -> Result<Self> {
        if !(cli.qps.is_finite() && cli.qps > 0.0) {
            return Err(Error::InvalidQps { value: cli.qps });
        }
        if cli.clients == 0 {
            return Err(Error::InvalidClients);
        }
        if cli.clients > MAX_SYNTHETIC_CLIENTS {
            return Err(Error::TooManyClients {
                value: cli.clients,
                max: MAX_SYNTHETIC_CLIENTS,
            });
        }
        if cli.resolvers == 0 {
            return Err(Error::InvalidResolvers);
        }
        if cli.resolvers > MAX_SYNTHETIC_RESOLVERS {
            return Err(Error::TooManyResolvers {
                value: cli.resolvers,
                max: MAX_SYNTHETIC_RESOLVERS,
            });
        }
        if cli.duplicate_max == 0 {
            return Err(Error::InvalidDuplicateMax);
        }
        for (flag, value) in [
            ("--duplicate-rate", cli.duplicate_rate),
            ("--timeout-rate", cli.timeout_rate),
        ] {
            if !(0.0..=1.0).contains(&value) {
                return Err(Error::RateOutOfRange { flag, value });
            }
        }

        let transactions = match cli.transactions {
            Some(value) if value > 0 => value,
            Some(_) => return Err(Error::InvalidTransactions),
            None => {
                if cli.duration_seconds == 0 {
                    return Err(Error::InvalidDurationWithoutTransactions);
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
