# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0rc1] - unreleased

First release candidate. Not yet published to PyPI.

### Added

- `slopguard scan` with terminal, JSON, Markdown and SARIF 2.1.0 output; `--diff`, `--staged`,
  baselines, inline suppressions, and `slopguard.toml` or `[tool.slopguard]` configuration.
- Rules: SEC-01; LLM-01 to LLM-06, LLM-08, LLM-09, LLM-12; HAL-01 to HAL-04; INC-01, INC-02,
  INC-04, INC-05, INC-06, INC-08. See [docs/rules.md](docs/rules.md).
- A taint tracker for model output, untrusted input and agent-tool arguments (within one function).
- `scan --spec` requirement checking (SPC-02), with an offline heuristic and optional model judging.
- Opt-in style drift rules DRF-01 to DRF-03.
- `slopguard regress` for deleted, skipped or weakened tests and tests that stopped passing (REG-01, REG-02).
- `slopguard gen-tests` with a sandbox (Docker, Linux namespaces, or explicit local).
- `slopguard fix`, a verify-and-repair loop that is a dry run unless `--apply` is given.
- LLM clients for Anthropic, OpenAI and Ollama over plain HTTPS.
- `slopguard bench`, a labelled corpus, `benchmarks/compare.py` and `benchmarks/realworld.py`.
- A composite GitHub Action that uploads SARIF, a pre-commit hook, CI and release workflows.

### Changed after the real-world check

Scanning 1.5 million lines of well-reviewed packages found many false positives, and the rules
were tightened ([details](docs/real-world-check.md)):

- SEC-01 no longer flags environment-variable names, endpoints, dotted keys, values that repeat
  the variable name, key headers without key material, or documented example keys.
- SEC-01 now also finds variables named exactly `token`, `secret` or `password` (they were missed).
- INC-01 only flags imperative placeholders such as "add your code here".
- INC-02 reports hollow methods and typed `...` stubs as low severity, and skips functions whose
  docstring explains the intent (hook, override, no-op).
- INC-04 flags only broad or bare `except ... : pass` with no explanatory comment.
- HAL-01 knows more import-name aliases and recent stdlib modules, and reports optional, lazy and
  `TYPE_CHECKING` imports as medium.

### Added since the first draft of this release

- `slopguard.scan()` and `slopguard.scan_source()`, a supported Python API with a `py.typed` marker.
- `[packages] private` to tell the HAL rules about imports from a private index.
- Generated reference pages (`slopguard.docgen`) kept in sync by tests, a full documentation set, and
  contributor files: code of conduct, support guide, issue and pull-request templates, Dependabot,
  `Makefile`, `.editorconfig` and a pre-commit config.
- A release workflow that dry-runs to TestPyPI and publishes to PyPI by trusted publishing.

### Safety

- `slopguard fix` never sends a file containing a hardcoded credential to a model.
- The terminal output warns when no supported files were found, so an unsupported language is not mistaken for a clean scan.

### Removed

- The `[llm] max_tokens` setting, which was accepted but never used.

### Known limitations

- The taint tracker does not follow values across functions or through instance attributes.
- The LLM clients and the Docker sandbox backend have not been run against live services.
- The spec checker without a model can show that code exists, not that it behaves correctly.
- Python only; see [docs/decisions/0001-javascript-typescript.md](docs/decisions/0001-javascript-typescript.md).
- The benchmark corpus is small and written by the maintainers.
