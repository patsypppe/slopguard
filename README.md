# slopguard

Verify AI-generated code. slopguard is an open-source Python CLI that checks whether code
written by an AI assistant is **secure, complete and real**: it traces model output into
dangerous calls, flags imports of packages that do not exist, and finds stubs, placeholders
and swallowed errors.

> Status: **alpha (Phase 1 MVP)**. The full plan is in the product and requirements
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
| LLM-02 | critical | Model output flowing into `eval`, `exec` or `compile` |
| LLM-03 | critical | Model output flowing into `os.system`, `subprocess` and similar |
| HAL-01 | high | Imports of packages that do not exist on PyPI |
| HAL-04 | medium | Imports not declared in `requirements*.txt` or `pyproject.toml` |
| INC-01 | medium | Placeholder comments such as "rest of code here" |
| INC-02 | medium | Hollow functions: `pass`, `...`, `raise NotImplementedError` |
| INC-04 | medium | Swallowed exceptions |
| INC-05 | high | Chat text or markdown fences left inside source |
| INC-06 | low | High TODO/FIXME density |
| INC-08 | high | Files that do not parse (often truncated output) |

LLM-02 and LLM-03 use a small taint tracker. It follows model output from SDK calls
(Anthropic, OpenAI, Ollama and LangChain-style `.invoke`) through assignments, attribute
access, f-strings and string methods inside one function. It does not yet follow values
across functions, so a clean result is not a proof of safety.

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
