# RFC 0002 — CLI and Runtime Bootstrap Boundaries

Status: Accepted  
Date: 2025-02-07

## Problem

The project used to have a single `src/utils.rs` that did everything: CLI parsing, environment
overrides, output-path validation, logger init, Rayon pool creation, memory-monitor startup,
and duration formatting. It worked, but it was the kind of "works" where adding a new CLI flag
meant touching the same file that sets up the thread pool.

The real cost wasn't bugs — it was review friction. Every PR that touched CLI precedence also
touched runtime bootstrap, and vice versa. Ownership was blurry.

## Decision

Split the responsibilities into three focused modules:

1. **`src/cli.rs`** — CLI parsing, environment-variable precedence, output-path validation.
   This is where you go when you need a new flag or want to change how env vars override CLI args.

2. **`src/runtime.rs`** — Runtime bootstrap: logger setup, build/system info logging, optional
   memory monitoring, signal handling, Rayon pool creation. Side-effectful host setup that
   shouldn't leak into argument resolution.

3. **`src/app.rs`** — Ordered run orchestration and reporting. Doesn't parse arguments, doesn't
   set up loggers, doesn't create thread pools. Just runs the pipeline and reports results.

`src/main.rs` composes all three and stays thin.

## Why this split

- CLI precedence has one owner. If someone asks "does the env var override the flag or the other
  way around?", the answer is always in `cli.rs`.
- Bootstrap side effects are isolated. Logger init, signal handlers, and thread-pool creation
  don't contaminate configuration resolution.
- Unit tests for CLI precedence don't need to reach through a mixed helper module anymore.

## Consequences

- New CLI flags or environment variables → `src/cli.rs`.
- New bootstrap concerns (logger tweaks, monitoring, pool config) → `src/runtime.rs`.
- If bootstrap grows unwieldy again, decompose *within* `src/runtime.rs` — don't recreate
  a catch-all utils module.
