# RFC 0002 — CLI and runtime bootstrap boundaries

**Status:** Accepted · **Date:** 2025-02-07

## Problem

The former `src/utils.rs` combined CLI parsing, environment overrides, output-path validation,
logger initialization, Rayon pool creation, memory-monitor startup, and duration formatting.

This mixed argument resolution with host setup. Changes to CLI precedence and runtime bootstrap
shared the same module, making ownership and review harder to follow.

## Decision

Split the responsibilities into three focused modules:

| Module | Responsibility | Change here when… |
| --- | --- | --- |
| [`cli.rs`](../../src/cli.rs) | CLI parsing, environment-variable precedence, and output-path validation | Adding a flag or changing argument resolution |
| [`runtime.rs`](../../src/runtime.rs) | Logger setup, build/system logging, optional memory monitoring, signal handling, and Rayon pool creation | Changing host setup or bootstrap side effects |
| [`app.rs`](../../src/app.rs) | Ordered run orchestration and reporting | Changing how the pipeline runs or reports results |

[`main.rs`](../../src/main.rs) composes all three and stays thin. `app.rs` does not parse
arguments, initialize loggers, or create thread pools.

## Why this split

- CLI precedence has one owner: `cli.rs`.
- Bootstrap side effects stay separate from configuration resolution.
- CLI precedence can be unit-tested without going through a mixed helper module.

## Consequences

- Keep new CLI flags and environment variables in `src/cli.rs`.
- Keep new bootstrap concerns in `src/runtime.rs`.
- If bootstrap needs further decomposition, split it within its existing boundary. Do not
  recreate a catch-all utilities module.
