/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::profile::is_disallowed_domain;
use crate::{Error, Result};
use clap::Parser;
use csv::StringRecord;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "dns-catalog-builder",
    about = "Build a sanitized DNS catalog TSV from a CSV file"
)]
pub(crate) struct BuilderCli {
    #[arg(value_name = "INPUT_CSV")]
    pub(crate) input: PathBuf,

    #[arg(value_name = "OUTPUT_TSV")]
    pub(crate) output: PathBuf,

    #[arg(long, default_value_t = 10_000)]
    pub(crate) top: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CatalogBuildSummary {
    pub(crate) rows_read: u64,
    pub(crate) unique_domains: usize,
    pub(crate) filtered_domains: usize,
    pub(crate) emitted_domains: usize,
}

#[derive(Debug, Eq, PartialEq)]
struct CatalogEntry {
    count: u64,
    name: String,
}

pub(crate) fn build_catalog_file(cli: &BuilderCli) -> Result<CatalogBuildSummary> {
    if cli.top == 0 {
        return Err(Error::InvalidCatalogTop);
    }

    let input = File::open(&cli.input).map_err(|source| Error::InputOpen {
        path: cli.input.clone(),
        source,
    })?;
    let output_parent = cli
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf);
    if let Some(parent) = &output_parent {
        fs::create_dir_all(parent).map_err(|source| Error::OutputDirectoryCreate {
            path: parent.clone(),
            source,
        })?;
    }

    let (entries, summary) = build_catalog(BufReader::new(input), cli.top)?;
    write_catalog_atomic(&cli.output, &entries)?;
    Ok(summary)
}

fn build_catalog<R: Read>(
    reader: R,
    top: usize,
) -> Result<(Vec<CatalogEntry>, CatalogBuildSummary)> {
    let mut csv = csv::Reader::from_reader(reader);
    let headers = csv
        .headers()
        .map_err(|source| Error::CsvHeader { source })?
        .iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let name_index = headers
        .iter()
        .position(|header| header == "name")
        .ok_or(Error::MissingCsvNameColumn)?;

    let mut counts = HashMap::<String, u64>::new();
    let mut rows_read = 0_u64;

    for row in csv.records() {
        let next_row = rows_read + 1;
        let row = row.map_err(|source| Error::CsvRow {
            row: next_row,
            source,
        })?;
        rows_read = next_row;
        if let Some(name) = normalized_name(&row, name_index) {
            *counts.entry(name).or_insert(0) += 1;
        }
    }

    let unique_domains = counts.len();
    let mut entries = counts
        .into_iter()
        .filter_map(|(name, count)| {
            (!is_disallowed_domain(&name)).then_some(CatalogEntry { count, name })
        })
        .collect::<Vec<_>>();
    let filtered_domains = unique_domains.saturating_sub(entries.len());
    let emitted_domains = entries.len().min(top);

    entries.sort_unstable_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    entries.truncate(top);

    Ok((
        entries,
        CatalogBuildSummary {
            rows_read,
            unique_domains,
            filtered_domains,
            emitted_domains,
        },
    ))
}

fn normalized_name(row: &StringRecord, name_index: usize) -> Option<String> {
    let name = row.get(name_index)?.trim();
    if name.is_empty() {
        return None;
    }

    Some(name.to_ascii_lowercase())
}

fn write_catalog_atomic(output: &Path, entries: &[CatalogEntry]) -> Result<()> {
    let temp_path = temporary_output_path(output)?;
    {
        let file = File::create(&temp_path).map_err(|source| Error::TemporaryCatalogCreate {
            path: temp_path.clone(),
            source,
        })?;
        let mut writer = BufWriter::new(file);
        for entry in entries {
            writeln!(writer, "{}\t{}", entry.count, entry.name).map_err(|source| {
                Error::CatalogRowWrite {
                    name: entry.name.clone(),
                    source,
                }
            })?;
        }
        writer.flush().map_err(|source| Error::OutputFlush {
            path: temp_path.clone(),
            source,
        })?;
    }

    fs::rename(&temp_path, output).map_err(|source| Error::CatalogRename {
        temp_path,
        output_path: output.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn temporary_output_path(output: &Path) -> Result<PathBuf> {
    let file_name = output
        .file_name()
        .ok_or_else(|| Error::OutputPathMissingFileName {
            path: output.to_path_buf(),
        })?
        .to_string_lossy();
    Ok(output.with_file_name(format!(".{file_name}.tmp")))
}

#[cfg(test)]
mod tests {
    use super::build_catalog;

    #[test]
    fn build_catalog_aggregates_filters_and_sorts_rows() {
        assert!(!crate::profile::is_disallowed_domain("api.vk.com"));

        let csv = "\
request_timestamp,response_timestamp,source_ip,source_port,id,name,query_type,response_code
1,2,1.1.1.1,1000,1,WWW.Google.com,A,No Error
1,2,1.1.1.1,1000,1,www.google.com,A,No Error
1,2,1.1.1.1,1000,1,android.clients.google.com,A,No Error
1,2,1.1.1.1,1000,1,api.vk.com,A,No Error
1,2,1.1.1.1,1000,1,.,NS,No Error
1,2,1.1.1.1,1000,1,example.com,A,No Error
";
        let (entries, summary) = build_catalog(csv.as_bytes(), 10).expect("catalog builds");

        let rendered = entries
            .into_iter()
            .map(|entry| format!("{}\t{}", entry.count, entry.name))
            .collect::<Vec<_>>();
        assert_eq!(
            rendered,
            vec![
                "2\twww.google.com",
                "1\t.",
                "1\tapi.vk.com",
                "1\texample.com"
            ]
        );
        assert_eq!(summary.rows_read, 6);
        assert_eq!(summary.unique_domains, 5);
        assert_eq!(summary.filtered_domains, 1);
        assert_eq!(summary.emitted_domains, 4);
    }

    #[test]
    fn build_catalog_requires_name_column() {
        let csv = "id,query_type\n1,A\n";
        let error = build_catalog(csv.as_bytes(), 10).expect_err("missing name column");
        assert!(error.to_string().contains("'name' column"));
    }
}
