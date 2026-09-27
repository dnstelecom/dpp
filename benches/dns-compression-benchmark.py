#!/usr/bin/env python3
r"""Compare two prebuilt DPP binaries on generated DNS compression workloads.

Uses only synthetic captures, never downloads inputs, and validates transaction
counters and CSV checksums before reporting paired timing ratios. Build both
binaries with the same Cargo profile, compiler and features (prefer `perf`).

Example:
  python3 benches/dns-compression-benchmark.py \
    --baseline /tmp/dpp-before --candidate target/perf/dpp \
    --outdir /tmp/dpp-compression-benchmark --runs 5

By default the baseline is a binary predating --max-dns-compression-jumps, so
the option is omitted for it. Use --baseline-limit for a same-policy control.
The candidate is exercised with 32 and 0; capped runs omit deeper-chain cases.
For an uncontaminated timing comparison, do not compile or run other benchmarks
concurrently. CPU scheduling and CSV/matcher work can mask parser-only costs.
"""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import struct
import subprocess
import time


def pointer(offset):
    assert 0 <= offset <= 0x3FFF
    return struct.pack("!H", 0xC000 | offset)


def dns_messages(case):
    count, style = CASES[case]
    qname = b"\x01a\x00"
    if case == "three-label-eight":
        qname = b"\x03www\x07example\x03com\x00"
    elif case == "long-name-eight":
        qname = (b"\x14abcdefghijklmnopqrst" * 10) + b"\x00"
    question = qname + struct.pack("!HH", 16, 1)
    query = struct.pack("!6H", 0, 0x0100, 1, 0, 0, 0) + question
    answer_count = 0 if case in ("authority-eight", "additional-eight") else count
    authority_count = count if case == "authority-eight" else 0
    additional_count = count if case == "additional-eight" else 0
    response = bytearray(struct.pack("!6H", 0, 0x8180, 1, answer_count,
                                     authority_count, additional_count) + question)
    previous, depth = 12, 0
    max_depth = 0
    for index in range(count):
        start = len(response)
        if style == "literal":
            owner = b"\x01a\x00"
            owner_depth = 0
        elif style == "distinct":
            label = f"rr{index}".encode("ascii")
            owner = bytes([len(label)]) + label + b"\x01a\x00"
            owner_depth = 0
        elif style == "suffix":
            label = f"rr{index}".encode("ascii")
            owner = bytes([len(label)]) + label + pointer(12)
            owner_depth = 1
        elif style.startswith("chain") or style == "deep":
            owner = pointer(previous)
            owner_depth = depth + 1
        else:
            owner = pointer(12)
            owner_depth = 1
        response += owner + struct.pack("!HHIH", 16, 1, 60, 2) + b"\x01x"
        max_depth = max(max_depth, owner_depth)
        if start <= 0x3FFF and (style == "deep" or style.startswith("chain") and owner_depth < int(style[5:])):
            previous, depth = start, owner_depth
    assert len(response) <= 65507
    return query, bytes(response), max_depth


CASES = {
    "empty": (0, "direct"),
    "one": (1, "direct"),
    "two": (2, "direct"),
    "eight": (8, "direct"),
    "authority-eight": (8, "direct"),
    "additional-eight": (8, "direct"),
    "three-label-eight": (8, "direct"),
    "long-name-eight": (8, "direct"),
    "literal-eight": (8, "literal"),
    "chain2-eight": (8, "chain2"),
    "chain8-eight": (8, "chain8"),
    "distinct-128": (128, "distinct"),
    "suffix-128": (128, "suffix"),
    "chain32-128": (128, "chain32"),
    "flat-4600": (4600, "direct"),
    "deep-4600": (4600, "deep"),
}


def frame(message, transaction, response):
    client = bytes([10, 0, 0, 1])
    server = bytes([1, 1, 1, 1])
    source, destination = (server, client) if response else (client, server)
    port = 53000 + transaction % 1000
    udp = struct.pack("!4H", 53 if response else port, port if response else 53,
                      8 + len(message), 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(message),
                     transaction & 0xFFFF, 0, 64, 17, 0, source, destination)
    message = struct.pack("!H", transaction & 0xFFFF) + message[2:]
    return bytes(12) + b"\x08\x00" + ip + udp + message


def make_capture(path, case, transactions):
    query, response, max_depth = dns_messages(case)
    path.with_suffix(".dns").write_bytes(response)
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for transaction in range(transactions):
            for is_response, message in enumerate((query, response)):
                packet = frame(message, transaction, is_response)
                micros = 1_000_000 + transaction * 200 + is_response * 100
                handle.write(struct.pack("<4I", micros // 1_000_000,
                                         micros % 1_000_000, len(packet), len(packet)))
                handle.write(packet)
    return {"transactions": transactions, "response_bytes": len(response),
            "max_jumps": max_depth, "pcap_bytes": path.stat().st_size}


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return number


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def csv_checksum(path):
    # Parallel execution may emit matched transactions in a different order.
    with path.open(newline="") as handle:
        records = csv.reader(handle)
        header = next(records)
        rows = sorted(records)
    return hashlib.sha256(json.dumps([header, rows], separators=(",", ":")).encode()).hexdigest()


def percentile(values, fraction):
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def run_one(binary, capture, output, fast, threads, limit, expected, environment):
    command = [str(binary), str(capture), str(output), "--threads", str(threads),
               "--report-format", "json"]
    if fast:
        command.append("--dns-wire-fast-path")
    if limit is not None:
        command += ["--max-dns-compression-jumps", str(limit)]
    started = time.perf_counter()
    result = subprocess.run(command, capture_output=True, text=True, env=environment)
    wall = time.perf_counter() - started
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {command}\n{result.stderr}")
    report = json.loads(result.stdout)
    metrics = report["metrics"]
    required = {"total_packets_processed": 2 * expected,
                "total_dns_queries_processed": expected,
                "total_dns_responses_processed": expected,
                "total_matched_query_response_pairs": expected,
                "timed_out_queries": 0}
    for key, value in required.items():
        if metrics[key] != value:
            raise RuntimeError(f"{capture.name}: {key} = {metrics[key]}, expected {value}")
    return report, wall, sha256(output) if threads == 1 else csv_checksum(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--outdir", required=True, type=Path)
    parser.add_argument("--runs", default=5, type=positive)
    parser.add_argument("--transactions", default=200_000, type=positive,
                        help="Transactions for short messages; dense cases are scaled down")
    parser.add_argument("--threads", default="1", help="Comma-separated execution budgets")
    parser.add_argument("--limits", default="32,0", help="Comma-separated candidate jump limits")
    parser.add_argument("--baseline-limit", type=nonnegative,
                        help="Explicit baseline jump limit, for a baseline that supports the option")
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--decoders", choices=("both", "default", "fast"), default="both")
    args = parser.parse_args()
    cases = args.cases.split(",")
    if any(case not in CASES for case in cases):
        parser.error("unknown case; choose from " + ",".join(CASES))
    threads_list = [positive(value) for value in args.threads.split(",")]
    limits = [nonnegative(value) for value in args.limits.split(",")]
    args.outdir.mkdir(parents=True, exist_ok=True)
    binaries = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    metadata = {"platform": platform.platform(), "python": platform.python_version(),
                "measurement": {"paired_runs": args.runs, "warmup_pairs": 1,
                                "threads": threads_list, "limits": limits,
                                "baseline_limit": args.baseline_limit,
                                "decoders": args.decoders},
                "binaries": {name: {"path": str(path), "sha256": sha256(path)}
                             for name, path in binaries.items()}, "fixtures": {}}
    for case in cases:
        rr_count = CASES[case][0]
        transactions = max(128, args.transactions // (1 if rr_count <= 8 else 20 if rr_count <= 128 else 1000))
        metadata["fixtures"][case] = make_capture(args.outdir / f"{case}.pcap", case, transactions)
    (args.outdir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("DPP_")}
    rows = []
    summaries = []
    fields = ["case", "decoder", "threads", "limit", "run", "binary", "wall_seconds",
              "processing_seconds", "rss_kib", "output_sha256"]
    decoders = [False, True] if args.decoders == "both" else [args.decoders == "fast"]
    with (args.outdir / "metrics.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for case in cases:
            fixture = metadata["fixtures"][case]
            for fast in decoders:
                for threads in threads_list:
                    for limit in [value for value in limits if value == 0 or value >= fixture["max_jumps"]]:
                        for run in range(args.runs + 1):
                            # Alternate order to reduce systematic temperature/cache bias.
                            order = ["baseline", "candidate"] if run % 2 == 0 else ["candidate", "baseline"]
                            hashes = []
                            for name in order:
                                output = args.outdir / f"{case}-{name}.csv"
                                report, wall, digest = run_one(
                                    binaries[name], args.outdir / f"{case}.pcap", output,
                                    fast, threads, limit if name == "candidate" else args.baseline_limit,
                                    fixture["transactions"], environment)
                                hashes.append(digest)
                                if run == 0:
                                    continue
                                metrics = report["metrics"]
                                row = {"case": case, "decoder": "fast" if fast else "default",
                                       "threads": threads, "limit": limit, "run": run, "binary": name,
                                       "wall_seconds": wall, "processing_seconds": metrics["processing_seconds"],
                                       "rss_kib": metrics["max_memory_usage_kib"], "output_sha256": digest}
                                writer.writerow(row)
                                rows.append(row)
                            if hashes[0] != hashes[1]:
                                raise RuntimeError(f"CSV mismatch: {case}, fast={fast}, threads={threads}, limit={limit}")
                            handle.flush()
                        selected = [row for row in rows if row["case"] == case and row["decoder"] == ("fast" if fast else "default")
                                    and row["threads"] == threads and row["limit"] == limit]
                        baseline = statistics.median(row["processing_seconds"] for row in selected if row["binary"] == "baseline")
                        candidate = statistics.median(row["processing_seconds"] for row in selected if row["binary"] == "candidate")
                        paired = {run: {row["binary"]: row["processing_seconds"] for row in selected if row["run"] == run}
                                  for run in range(1, args.runs + 1)}
                        ratios = [pair["candidate"] / pair["baseline"] for pair in paired.values()]
                        summary = {"case": case, "decoder": "fast" if fast else "default",
                                   "threads": threads, "limit": limit, "runs": args.runs,
                                   "baseline_median_seconds": baseline, "candidate_median_seconds": candidate,
                                   "paired_ratio_median": statistics.median(ratios),
                                   "paired_ratio_p25": percentile(ratios, .25),
                                   "paired_ratio_p75": percentile(ratios, .75),
                                   "paired_ratio_min": min(ratios), "paired_ratio_max": max(ratios)}
                        summaries.append(summary)
                        (args.outdir / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
                        print(f"{case:16} {'fast' if fast else 'default':7} threads={threads} limit={limit:2} "
                              f"baseline={baseline:.6f}s candidate={candidate:.6f}s "
                              f"paired-ratio={summary['paired_ratio_median']:.3f} "
                              f"IQR=[{summary['paired_ratio_p25']:.3f},{summary['paired_ratio_p75']:.3f}]", flush=True)


if __name__ == "__main__":
    main()
