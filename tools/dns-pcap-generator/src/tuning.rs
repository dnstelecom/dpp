/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::model::{ResponseCodeKind, ResponseCodeWeight};

#[derive(Clone, Copy)]
pub(crate) struct DelayBucket {
    pub(crate) weight: u32,
    pub(crate) min_us: u64,
    pub(crate) max_us: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct DelayRange {
    pub(crate) min_us: u64,
    pub(crate) max_us: u64,
}

include!(concat!(env!("OUT_DIR"), "/dns_pcap_generator_tuning.rs"));
