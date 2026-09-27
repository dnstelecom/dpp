#!/usr/bin/env python3
"""Build the standalone scanner microbenchmark with current Cargo artifacts.

Uses the perf profile and default jemalloc feature, matching the recorded runs.
Cargo JSON selects artifacts for the active compiler; stale .rlib files from
another toolchain in target/perf/deps are deliberately ignored.
"""

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    root = directory.parent.parent
    build = subprocess.run(
        ["cargo", "build", "-p", "dpp", "--profile", "perf", "--locked", "--offline",
         "--message-format=json"],
        cwd=root, capture_output=True, text=True, check=True,
    )
    sys.stderr.write(build.stderr)
    libraries = {"arrayvec": set(), "tikv_jemallocator": set()}
    for line in build.stdout.splitlines():
        record = json.loads(line)
        if record.get("reason") != "compiler-artifact":
            continue
        name = record["target"]["name"]
        if name in libraries:
            libraries[name].update(path for path in record["filenames"] if path.endswith(".rlib"))
    if any(len(paths) != 1 for paths in libraries.values()):
        raise RuntimeError(f"Expected one current artifact per dependency: {libraries}")
    selected = {name: Path(next(iter(paths))) for name, paths in libraries.items()}
    if len({path.parent for path in selected.values()}) != 1:
        raise RuntimeError("Dependency artifacts use different target directories")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [os.environ.get("RUSTC", "rustc"), "--edition=2024", "-C", "opt-level=3",
               "-C", "lto", "-C", "codegen-units=1", "-C", "panic=abort",
               "-C", "overflow-checks=off", str(directory / "scan.rs"),
               "-L", f"dependency={selected['arrayvec'].parent}"]
    for name, path in selected.items():
        command += ["--extern", f"{name}={path}"]
    command += ["-o", str(output)]
    print(shlex.join(command), flush=True)
    subprocess.run(command, cwd=root, check=True)


if __name__ == "__main__":
    main()
