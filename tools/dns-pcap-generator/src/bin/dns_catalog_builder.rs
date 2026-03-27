/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use std::process::ExitCode;

fn main() -> ExitCode {
    match dns_pcap_generator::run_catalog_builder() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            dns_pcap_generator::report_error(&error);
            ExitCode::FAILURE
        }
    }
}
