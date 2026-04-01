/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

mod allocator;
mod app;
mod cli;
mod config;
mod csv_writer;
mod custom_types;
mod dns_processor;
mod error;
mod monitor_memory;
mod output;
mod packet_parser;
mod parquet_writer;
mod pipeio;
mod record;
mod runtime;
#[cfg(test)]
mod test_support;

fn main() -> anyhow::Result<()> {
    allocator::initialize_allocator_runtime();
    let args = cli::parse_args()?;
    runtime::configure_logger(args.silent, args.report_format)?;
    app::run(args)?;
    Ok(())
}
