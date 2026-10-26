# slopguard

Verify AI-generated code. slopguard is an open-source Python CLI that checks whether code
written by an AI assistant is **secure, complete and real**: it traces model output into
dangerous calls, flags imports of packages that do not exist, and finds stubs, placeholders
and swallowed errors.

> Status: **alpha (Phase 2)**. The full plan is in the product and requirements
> document linked from [docs/PRD.md](docs/PRD.md).

## Install

```bash
pipx install slopguard        # once published
# or from a clone:
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
```

## Use

```bash
slopguard scan .                       # scan the current folder
slopguard scan src --format sarif -o slopguard.sarif
slopguard scan --staged                # only files staged for commit
slopguard scan . --no-network          # skip PyPI lookups
slopguard rules                        # list every rule
slopguard explain LLM-02               # why a rule exists and how to fix it
slopguard init                         # write a starter slopguard.toml
```

Exit codes: `0` clean or below `--fail-on`, `1` findings at or above it (default `high`),
`2` usage or config error, `3` internal error.

## Rules in this release

| ID | Severity | Detects |
| --- | --- | --- |
| SEC-01 | critical | Hardcoded API keys, tokens and private keys (values are masked in output) |
| LLM-01 | high | Untrusted input (request data, `input()`, CLI args, fetched pages) in the system prompt of a model call |
| LLM-02 | critical | Model output flowing into `eval`, `exec` or `compile` |
| LLM-03 | critical | Model output flowing into `os.system`, `subprocess` and similar |
| LLM-04 | high | Model output used as SQL text |
| LLM-05 | high | Model output used as a file path |
| LLM-06 | high | Model output used as a request URL (SSRF) |
| LLM-08 | high | Agent tools whose model-chosen arguments reach shell, code, SQL, files or the network; shell and Python REPL toolkits; `allow_dangerous_*=True` |
| LLM-09 | medium | Destructive agent tools with no confirmation step |
| LLM-12 | low | OpenAI-style model calls with no output token cap |
| HAL-01 | high | Imports of packages that do not exist on PyPI |
| HAL-02 | medium | Imports of packages first published only days ago (experimental) |
| HAL-03 | medium | Import names one typo away from a popular package |
| HAL-04 | medium | Imports not declared in `requirements*.txt` or `pyproject.toml` |
| INC-01 | medium | Placeholder comments such as "rest of code here" |
| INC-02 | medium | Hollow functions: `pass`, `...`, `raise NotImplementedError` |
| INC-04 | medium | Swallowed exceptions |
| INC-05 | high | Chat text or markdown fences left inside source |
| INC-06 | low | High TODO/FIXME density |
| INC-08 | high | Files that do not parse (often truncated output) |

The LLM flow rules use a small taint tracker with three kinds of flow: model output,
untrusted input and agent-tool arguments. It follows values through assignments, attribute
access, f-strings, `str.format` and string methods **inside one function**. It does not yet
follow values across functions or through instance attributes, so a clean result is not a
proof of safety. The benchmark corpus includes two labelled examples of exactly these misses.

## Benchmark

```bash
slopguard bench                          # score the shipped corpus
slopguard bench --min-precision 0.85     # exit 1 if any rule falls below
```

`benchmarks/corpus/` holds labelled files (`# expect: RULE-ID` or `# expect: none`).
Scoring is per file. The corpus is small and written by the maintainers, so treat its numbers
as a regression gate, not as a claim about accuracy on real projects. Comparison against
other scanners is planned for Phase 4.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write       # for the SARIF upload
steps:
  - uses: actions/checkout@v4
  - uses: patsypppe/slopguard@main
    with:
      fail-on: high
```

The action scans, uploads SARIF to code scanning, writes a summary to the job page and fails
the job at `fail-on` or above. Set `upload-sarif: "false"` if code scanning is unavailable.

## pre-commit

```yaml
repos:
  - repo: https://github.com/patsypppe/slopguard
    rev: main
    hooks:
      - id: slopguard
```

## Configuration

`slopguard.toml` (or `[tool.slopguard]` in `pyproject.toml`). Run `slopguard init` for a
commented starter file. Suppress one finding with `# slopguard: ignore[RULE-ID]` on the
line or the line above it.

## Privacy

Source code never leaves your machine. The only network call is a package-name lookup on
PyPI for HAL-01; turn it off with `--no-network`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Clean-room note

slopguard is independent work. It borrows no code, rules, messages or structure from other
tools. See [docs/clean-room.md](docs/clean-room.md).

## License

MIT. See [LICENSE](LICENSE).
