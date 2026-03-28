/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::error::{Error, Result};
use crate::model::WeightedDomain;
use std::borrow::Cow;
use std::fs;
use std::path::Path;

pub(crate) fn load_catalog(tsv: &str) -> Result<Vec<WeightedDomain>> {
    let mut domains = Vec::new();
    for (line_number, line) in tsv.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (weight, name) = line.split_once('\t').ok_or(Error::InvalidCatalogRow {
            line: line_number + 1,
        })?;
        let weight = weight
            .parse::<u32>()
            .map_err(|source| Error::InvalidCatalogWeight {
                line: line_number + 1,
                source,
            })?;
        domains.push(WeightedDomain {
            name: Cow::Owned(name.to_string()),
            weight,
        });
    }

    Ok(domains)
}

pub(crate) fn load_catalog_file(path: &Path) -> Result<Vec<WeightedDomain>> {
    let tsv = fs::read_to_string(path).map_err(|source| Error::CatalogRead {
        path: path.to_path_buf(),
        source,
    })?;
    load_catalog(&tsv)
}
