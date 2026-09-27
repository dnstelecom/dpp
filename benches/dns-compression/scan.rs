// Isolated RR-owner validation benchmark. Build with the same optimizer and
// allocator as both E2E binaries. See the compression benchmark report for the
// rustc --extern command. Inputs are *.dns files generated alongside PCAPs by
// dns-compression-benchmark.py. Each iteration starts a new message-local cache.
//
// Usage: dns-compression-scan FIXTURE_DIR [RUNS=10] [SAMPLE_MILLISECONDS=100]
// Stdout is CSV: timings and paired ratios for every measured repetition.
// One unrecorded warm-up pair precedes each case/limit configuration.
// The uncached control is the scanner from 7807751 plus the configurable cap.
use std::{hint::black_box, time::Instant};
const DNS_POINTER_MASK: u8 = 0xc0;
const DNS_POINTER_TAG: u8 = 0xc0;
const DNS_LABEL_LEN_MASK: u8 = 0x3f;
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
struct Old;
impl Old {
    fn skip_wire_domain_name(
        dns_data: &[u8],
        cursor: &mut usize,
        max_jumps: usize,
    ) -> Result<bool, &'static str> {
        let start = *cursor;
        let mut position = *cursor;
        let mut resume_position = None;
        let mut segment_start = position;
        let mut segment_end = dns_data.len();
        let mut jumps = 0;

        loop {
            let length = *dns_data
                .get(..segment_end)
                .and_then(|segment| segment.get(position))
                .ok_or("DNS name truncated")?;

            match length {
                0 => {
                    position += 1;
                    *cursor = resume_position.unwrap_or(position);
                    return Ok(resume_position.is_none() && position == start + 1);
                }
                _ if (length & DNS_POINTER_MASK) == DNS_POINTER_TAG => {
                    let next = *dns_data
                        .get(..segment_end)
                        .and_then(|segment| segment.get(position + 1))
                        .ok_or("DNS compression pointer truncated")?;
                    let offset =
                        (((length & DNS_LABEL_LEN_MASK) as usize) << 8) | usize::from(next);

                    jumps += 1;
                    if max_jumps != 0 && jumps > max_jumps {
                        return Err("DNS compression jump limit exceeded");
                    }
                    if offset >= segment_start {
                        return Err("DNS compression pointer is not prior to name");
                    }

                    if resume_position.is_none() {
                        resume_position = Some(position + 2);
                    }

                    // Historical uncached walker, with the same configurable hop cap
                    // as the candidate, isolates cache/bookkeeping cost from limit cost.
                    segment_end = segment_start;
                    segment_start = offset;
                    position = offset;
                }
                _ if (length & DNS_POINTER_MASK) != 0 => {
                    return Err("Unsupported DNS label encoding");
                }
                _ => {
                    let label_len = usize::from(length);
                    dns_data
                        .get(..segment_end)
                        .and_then(|segment| segment.get(position + 1..position + 1 + label_len))
                        .ok_or("DNS label truncated")?;
                    position += 1 + label_len;
                }
            }
        }
    }
}
#[allow(dead_code)]
#[path = "../../src/dns_processor/name_decoder.rs"]
mod candidate;
#[inline(never)]
fn old(data: &[u8], limit: usize) -> usize {
    let count: usize = [6, 8, 10]
        .into_iter()
        .map(|offset| usize::from(u16::from_be_bytes([data[offset], data[offset + 1]])))
        .sum();
    let mut cursor = 12;
    black_box(Old::skip_wire_domain_name(data, &mut cursor, limit).unwrap());
    cursor += 4;
    for _ in 0..count {
        black_box(Old::skip_wire_domain_name(data, &mut cursor, limit).unwrap());
        let n = u16::from_be_bytes([data[cursor + 8], data[cursor + 9]]) as usize;
        cursor += 10 + n;
    }
    assert_eq!(cursor, data.len());
    cursor
}
#[inline(never)]
fn new(data: &[u8], limit: usize) -> usize {
    let mut decoder = candidate::DnsNameDecoder::new(data, limit);
    let count: usize = [6, 8, 10]
        .into_iter()
        .map(|offset| usize::from(u16::from_be_bytes([data[offset], data[offset + 1]])))
        .sum();
    let mut cursor = 12;
    black_box(decoder.skip(&mut cursor).unwrap());
    cursor += 4;
    for _ in 0..count {
        black_box(decoder.skip(&mut cursor).unwrap());
        let n = u16::from_be_bytes([data[cursor + 8], data[cursor + 9]]) as usize;
        cursor += 10 + n;
    }
    assert_eq!(cursor, data.len());
    cursor
}
fn main() {
    let mut args = std::env::args().skip(1);
    let directory = std::path::PathBuf::from(args.next().expect("fixture directory required"));
    let repetitions: usize = args.next().map(|v| v.parse().unwrap()).unwrap_or(10);
    let milliseconds: u128 = args.next().map(|v| v.parse().unwrap()).unwrap_or(100);
    assert!(repetitions > 0 && milliseconds > 0);
    assert!(args.next().is_none(), "too many arguments");
    let mut fixtures: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "dns"))
        .collect();
    fixtures.sort();
    assert!(!fixtures.is_empty(), "no .dns fixtures found");
    println!("case,limit,run,old_ns,new_ns,ratio");
    for path in fixtures {
        let case = path.file_stem().unwrap().to_str().unwrap();
        let data = std::fs::read(&path).unwrap();
        for limit in [32, 0] {
            // The generated deep case intentionally needs unlimited traversal.
            if case == "deep-4600" && limit == 32 {
                continue;
            }
            for round in 0..=repetitions {
                let mut numbers = [0., 0.];
                for variant in [round % 2, (round + 1) % 2] {
                    let scan = if variant == 0 { old } else { new };
                    let mut runs = 0;
                    let started = Instant::now();
                    // Avoid a 100-packet batch overshooting the duration on deep chains.
                    let batch = if data.len() > 16_000 { 1 } else { 100 };
                    while started.elapsed().as_millis() < milliseconds {
                        for _ in 0..batch {
                            black_box(scan(black_box(&data), black_box(limit)));
                        }
                        runs += batch;
                    }
                    numbers[variant] = started.elapsed().as_secs_f64() * 1e9 / runs as f64;
                }
                if round != 0 {
                    println!(
                        "{case},{limit},{round},{:.2},{:.2},{:.6}",
                        numbers[0],
                        numbers[1],
                        numbers[1] / numbers[0]
                    );
                }
            }
        }
    }
}
