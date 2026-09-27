# Contributing

DPP welcomes contributions that improve correctness, determinism, maintainability, portability,
documentation, test coverage, and measurable performance within the Community Edition scope.

## Before you start

| Before changing… | Read |
| --- | --- |
| Product behavior or supported features | [README](README.md) |
| Runtime behavior or ownership boundaries | [Architecture](docs/architecture.md) |
| A long-lived design decision | [RFC index](docs/rfc/README.md) |
| Performance, or making a performance claim | [Benchmark contract](benches/README.md) |

For larger changes, please open an issue or start a discussion before investing in a large patch.
Early alignment is the easiest way to avoid rework.

## Contribution guidelines

- Preserve ownership boundaries.
- Do not introduce a second source of truth.
- Do not weaken validation semantics to make tests pass.
- Prefer minimal, reviewable changes.
- Keep comments, documentation, and user-facing text in English.
- Update documentation when behavior changes.
- Call out hot-path performance risk when touching parser, matcher, pipeline, or writer code.
- Mark unsupported assumptions as hypotheses.

## Testing expectations

At minimum:

- Run targeted tests for the code you touched.
- Run additional checks that match the change type.
- Include benchmark evidence for hot-path performance claims.

| Change | Additional validation |
| --- | --- |
| Parser or matcher | Targeted `cargo test` coverage. |
| Writer | Output compatibility and shutdown behavior. |
| Benchmark harness | `bash -n benches/benchmark.sh` and a dry run. |

## Rebuilding a missing release asset

Once the corrected release workflow is on `main`, rebuild one platform from an existing tag:

```bash
gh workflow run rust.yml --ref main -f tag=v0.4.0 -f runner=ubuntu-22.04
```

This runs the current workflow but checks out `refs/tags/v0.4.0`. It does not move the tag or
overwrite existing release assets.

- Runner choices are `ubuntu-22.04`, `ubuntu-24.04`, and `ubuntu-24.04-arm`.
- Tag pushes build all three platforms.
- Re-running an old failed run uses its original workflow revision and does not pick up a later
  workflow fix.

## Community and Commercial scope

DPP Community Edition and DPP Commercial Edition intentionally have different scopes.

Contributions are reviewed against the Community Edition roadmap and maintenance budget. Changes
that improve the shared foundation are welcome, including work on correctness, testing,
documentation, portability, tooling, and broadly applicable performance improvements.

Features that are specific to the Commercial Edition, or that would collapse the boundary between
the Community and Commercial offerings, will usually not be accepted into the Community Edition.
This is not a statement about code quality; it is a product-scope decision.

If you are unsure whether a proposed feature belongs in the Community Edition, please ask before
implementing it.

## Licensing

By submitting a contribution, you agree that your contribution may be distributed under the
repository license.
