# Contributing

Thank you for considering a contribution to DPP.

Community contributions are welcome, especially when they improve correctness, determinism,
maintainability, portability, documentation, test coverage, and measurable performance on the
community-supported feature set.

## Before You Start

- Read [README.md](README.md) for the product scope and operator-facing contract.
- Read [docs/architecture.md](docs/architecture.md) before changing runtime behavior or ownership
  boundaries.
- Read [docs/rfc/README.md](docs/rfc/README.md) for architecture decisions and long-lived design
  context.
- Read [benches/README.md](benches/README.md) before making or claiming performance changes.

For larger changes, please open an issue or start a discussion before investing in a large patch.
Early alignment is the easiest way to avoid rework.

## Contribution Guidelines

- Preserve ownership boundaries.
- Do not introduce a second source of truth.
- Do not weaken validation semantics to make tests pass.
- Prefer minimal, reviewable changes.
- Keep comments, documentation, and user-facing text in English.
- Update documentation when behavior changes.
- Call out hot-path performance risk when touching parser, matcher, pipeline, or writer code.
- Mark unsupported assumptions as hypotheses.

## Testing Expectations

At minimum:

- Run targeted tests for the code you touched.
- Run additional checks that match the change type.
- Include benchmark evidence for hot-path performance claims.

Examples:

- Parser or matcher changes should include targeted `cargo test` coverage.
- Writer changes should verify output compatibility and shutdown behavior.
- Benchmark harness changes should be validated with `bash -n benches/benchmark.sh` and a dry run.

## Community and Commercial Scope

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
