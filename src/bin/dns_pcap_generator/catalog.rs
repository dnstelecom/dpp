/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::model::WeightedDomain;
use anyhow::{Context, Result};
use std::sync::LazyLock;

pub(crate) static SERVER1_JUL_2024_POSITIVE_DOMAINS: LazyLock<Vec<WeightedDomain>> =
    LazyLock::new(|| {
        load_catalog(include_str!("catalog_data.tsv")).expect("catalog data must decode")
    });

fn load_catalog(tsv: &str) -> Result<Vec<WeightedDomain>> {
    let mut domains = Vec::new();
    for (line_number, line) in tsv.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (weight, name) = line
            .split_once('\t')
            .with_context(|| format!("invalid catalog row at line {}", line_number + 1))?;
        let weight = weight
            .parse::<u32>()
            .with_context(|| format!("invalid weight at line {}", line_number + 1))?;
        let name = Box::leak(name.to_string().into_boxed_str());
        domains.push(WeightedDomain { name, weight });
    }

    Ok(domains)
}
