/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use clap::Parser;
use csv::StringRecord;
use dns_pcap_generator::is_disallowed_domain;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

type Result<T> = std::result::Result<T, Error>;

static TEMPORARY_CATALOG_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const TEMPORARY_CATALOG_ATTEMPTS: usize = 100;

#[derive(Debug, Parser)]
#[command(
    name = "dns-catalog-builder",
    about = "Build a sanitized DNS catalog TSV from a CSV file"
)]
struct Cli {
    #[arg(value_name = "INPUT_CSV")]
    input: PathBuf,

    #[arg(value_name = "OUTPUT_TSV")]
    output: PathBuf,

    #[arg(long, default_value_t = 10_000)]
    top: usize,
}

#[derive(Debug, Error)]
enum Error {
    #[error("--top must be greater than 0")]
    InvalidTop,

    #[error("failed to open '{path}'")]
    InputOpen {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to create output directory '{path}'")]
    OutputDirectoryCreate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to read CSV header")]
    CsvHeader {
        #[source]
        source: csv::Error,
    },

    #[error("CSV must contain a 'name' column")]
    MissingCsvNameColumn,

    #[error("failed to decode CSV row {row}")]
    CsvRow {
        row: u64,
        #[source]
        source: csv::Error,
    },

    #[error("output path must include a file name: '{path}'")]
    OutputPathMissingFileName { path: PathBuf },

    #[error("failed to create temporary catalog '{path}'")]
    TemporaryCatalogCreate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to write catalog row for '{name}'")]
    CatalogRowWrite {
        name: String,
        #[source]
        source: io::Error,
    },

    #[error("failed to flush '{path}'")]
    OutputFlush {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to sync '{path}'")]
    OutputSync {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to move temporary catalog '{temp_path}' into '{output_path}'")]
    CatalogRename {
        temp_path: PathBuf,
        output_path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Eq, PartialEq)]
struct CatalogBuildSummary {
    rows_read: u64,
    unique_domains: usize,
    filtered_domains: usize,
    emitted_domains: usize,
}

#[derive(Debug, Eq, PartialEq)]
struct CatalogEntry {
    count: u64,
    name: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_error(&error);
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let summary = build_catalog_file(&cli)?;

    println!(
        "Wrote {} domains to {} from {} CSV rows ({} unique names, {} filtered).",
        summary.emitted_domains,
        cli.output.display(),
        summary.rows_read,
        summary.unique_domains,
        summary.filtered_domains
    );

    Ok(())
}

fn report_error(error: &Error) {
    eprintln!("Error: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("Caused by: {cause}");
        source = cause.source();
    }
}

fn build_catalog_file(cli: &Cli) -> Result<CatalogBuildSummary> {
    if cli.top == 0 {
        return Err(Error::InvalidTop);
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
    let (temporary, file) = TemporaryCatalog::create(output, &TEMPORARY_CATALOG_SEQUENCE)?;
    {
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
            path: temporary.path.clone(),
            source,
        })?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|source| Error::OutputSync {
                path: temporary.path.clone(),
                source,
            })?;
    }

    temporary.publish(output)
}

#[derive(Debug)]
struct TemporaryCatalog {
    path: PathBuf,
    published: bool,
}

impl TemporaryCatalog {
    fn create(output: &Path, sequence: &AtomicU64) -> Result<(Self, File)> {
        let mut attempts = 0;
        loop {
            let id = sequence.fetch_add(1, Ordering::Relaxed);
            let path = temporary_output_path(output, id)?;
            let candidate_name = path.file_name().expect("temporary path has a file name");
            if output.file_name().is_some_and(|name| {
                candidate_name
                    .as_encoded_bytes()
                    .eq_ignore_ascii_case(name.as_encoded_bytes())
            }) {
                continue;
            }
            attempts += 1;
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    return Ok((
                        Self {
                            path,
                            published: false,
                        },
                        file,
                    ));
                }
                Err(source)
                    if source.kind() == io::ErrorKind::AlreadyExists
                        && attempts < TEMPORARY_CATALOG_ATTEMPTS => {}
                Err(source) => return Err(Error::TemporaryCatalogCreate { path, source }),
            }
        }
    }

    fn publish(mut self, output: &Path) -> Result<()> {
        fs::rename(&self.path, output).map_err(|source| Error::CatalogRename {
            temp_path: self.path.clone(),
            output_path: output.to_path_buf(),
            source,
        })?;
        self.published = true;
        Ok(())
    }
}

impl Drop for TemporaryCatalog {
    fn drop(&mut self) {
        if !self.published {
            // Preserve the original I/O error if cleanup itself fails.
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn temporary_output_path(output: &Path, id: u64) -> Result<PathBuf> {
    if output.file_name().is_none() {
        return Err(Error::OutputPathMissingFileName {
            path: output.to_path_buf(),
        });
    }
    Ok(output.with_file_name(format!(".dns-catalog.{}.{id}.tmp", std::process::id())))
}

#[cfg(test)]
mod tests {
    use super::{
        CatalogEntry, Error, TEMPORARY_CATALOG_ATTEMPTS, TemporaryCatalog, build_catalog,
        temporary_output_path, write_catalog_atomic,
    };
    use std::fs;
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            loop {
                let id = SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("dns-catalog-builder-{}-{id}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create test directory: {error}"),
                }
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn write_catalog_atomic_replaces_complete_catalog() {
        let directory = TestDirectory::new();
        let output = directory.0.join("catalog.tsv");
        fs::write(&output, "previous catalog").unwrap();

        write_catalog_atomic(
            &output,
            &[
                CatalogEntry {
                    count: 7,
                    name: "example.com".into(),
                },
                CatalogEntry {
                    count: 3,
                    name: "example.org".into(),
                },
            ],
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(&output).unwrap(),
            "7\texample.com\n3\texample.org\n"
        );
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn long_output_file_name_publishes_successfully() {
        let directory = TestDirectory::new();
        let output = directory.0.join("c".repeat(250));
        write_catalog_atomic(
            &output,
            &[CatalogEntry {
                count: 7,
                name: "example.com".into(),
            }],
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&output).unwrap(), "7\texample.com\n");
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn temporary_candidate_cannot_create_destination_before_publication() {
        for uppercase in [false, true] {
            let directory = TestDirectory::new();
            let candidate = temporary_output_path(&directory.0.join("catalog.tsv"), 0).unwrap();
            let output = if uppercase {
                candidate.with_file_name(candidate.file_name().unwrap().to_ascii_uppercase())
            } else {
                candidate
            };
            let (temporary, mut file) =
                TemporaryCatalog::create(&output, &AtomicU64::new(0)).unwrap();
            file.write_all(b"7\texample.com\n").unwrap();
            file.sync_all().unwrap();
            drop(file);
            assert!(!output.exists());

            temporary.publish(&output).unwrap();
            assert_eq!(fs::read_to_string(&output).unwrap(), "7\texample.com\n");
            assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
        }
    }

    #[test]
    fn overlapping_publisher_abort_preserves_written_catalog() {
        let directory = TestDirectory::new();
        let output = directory.0.join("catalog.tsv");
        let (first, mut first_file) =
            TemporaryCatalog::create(&output, &AtomicU64::new(0)).unwrap();
        first_file.write_all(b"7\texample.com\n").unwrap();

        // The second publisher starts after the first has written, then exits before writing.
        let (second, second_file) = TemporaryCatalog::create(&output, &AtomicU64::new(0)).unwrap();
        assert_ne!(first.path, second.path);
        drop(second_file);
        drop(second);

        first_file.sync_all().unwrap();
        drop(first_file);
        first.publish(&output).unwrap();
        assert_eq!(fs::read_to_string(&output).unwrap(), "7\texample.com\n");
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn overlapping_publishers_each_replace_with_their_complete_catalog() {
        let directory = TestDirectory::new();
        let output = directory.0.join("catalog.tsv");
        let sequence = AtomicU64::new(0);
        let (first, mut first_file) = TemporaryCatalog::create(&output, &sequence).unwrap();
        let (second, mut second_file) = TemporaryCatalog::create(&output, &sequence).unwrap();
        first_file.write_all(b"7\texample.com\n").unwrap();
        second_file.write_all(b"3\texample.org\n").unwrap();
        first_file.sync_all().unwrap();
        second_file.sync_all().unwrap();
        drop(first_file);
        drop(second_file);

        first.publish(&output).unwrap();
        assert_eq!(fs::read_to_string(&output).unwrap(), "7\texample.com\n");
        second.publish(&output).unwrap();
        assert_eq!(fs::read_to_string(&output).unwrap(), "3\texample.org\n");
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn temporary_catalog_collision_preserves_existing_file() {
        let directory = TestDirectory::new();
        let output = directory.0.join("catalog.tsv");
        let existing_temp = temporary_output_path(&output, 0).unwrap();
        fs::write(&output, "previous catalog").unwrap();
        fs::write(&existing_temp, "another publisher").unwrap();

        let (temporary, file) = TemporaryCatalog::create(&output, &AtomicU64::new(0)).unwrap();
        assert_ne!(temporary.path, existing_temp);
        drop(file);
        drop(temporary);

        assert_eq!(
            fs::read_to_string(&existing_temp).unwrap(),
            "another publisher"
        );
        assert_eq!(fs::read_to_string(&output).unwrap(), "previous catalog");
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }

    #[test]
    fn temporary_catalog_collision_exhaustion_preserves_existing_files() {
        let directory = TestDirectory::new();
        let output = directory.0.join("catalog.tsv");
        for id in 0..TEMPORARY_CATALOG_ATTEMPTS as u64 {
            fs::write(
                temporary_output_path(&output, id).unwrap(),
                "another publisher",
            )
            .unwrap();
        }

        let error = TemporaryCatalog::create(&output, &AtomicU64::new(0)).unwrap_err();
        assert!(matches!(error, Error::TemporaryCatalogCreate { source, .. }
            if source.kind() == io::ErrorKind::AlreadyExists));
        for id in 0..TEMPORARY_CATALOG_ATTEMPTS as u64 {
            assert_eq!(
                fs::read_to_string(temporary_output_path(&output, id).unwrap()).unwrap(),
                "another publisher"
            );
        }
        assert_eq!(
            fs::read_dir(&directory.0).unwrap().count(),
            TEMPORARY_CATALOG_ATTEMPTS
        );
    }

    #[test]
    fn failed_publication_removes_only_its_temporary_file() {
        let directory = TestDirectory::new();
        let output = directory.0.join("catalog.tsv");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("keep"), "existing destination").unwrap();
        let unrelated = directory.0.join("another-publisher.tmp");
        fs::write(&unrelated, "another publisher").unwrap();

        let error = write_catalog_atomic(
            &output,
            &[CatalogEntry {
                count: 7,
                name: "example.com".into(),
            }],
        )
        .unwrap_err();
        assert!(matches!(error, Error::CatalogRename { .. }));
        assert_eq!(
            fs::read_to_string(output.join("keep")).unwrap(),
            "existing destination"
        );
        assert_eq!(fs::read_to_string(&unrelated).unwrap(), "another publisher");
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }

    #[test]
    fn build_catalog_aggregates_filters_and_sorts_rows() {
        assert!(!dns_pcap_generator::is_disallowed_domain("api.vk.com"));

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
