# slopguard

[![CI](https://github.com/patsypppe/slopguard/actions/workflows/ci.yml/badge.svg)](https://github.com/patsypppe/slopguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](docs/getting-started.md)
[![Status: release candidate](https://img.shields.io/badge/status-1.0.0rc1-orange.svg)](CHANGELOG.md)

**Check AI-written code before you trust it.** slopguard is an open-source Python command-line tool
that finds the problems assistants and LLM-powered apps tend to introduce, and that general
scanners were not built to look for.

- **Is it safe?** Does model output reach `eval`, a shell or a SQL query? Does untrusted input end up
  in a system prompt? Does an agent tool hand the model a shell?
- **Is it real?** Does that imported package exist, or is it invented (or one typo from a popular one)?
- **Is it finished?** Stubs, "rest of code here" comments, swallowed errors, truncated files.
- **Is it what you asked for?** Does the code meet each requirement in your spec, and did the change
  delete or weaken tests to get there?

It runs locally, never executes the code it scans, needs no account, and has no telemetry.

> **Status: release candidate (1.0.0rc1), not yet on PyPI.** Install from a clone for now. The model-assisted
> commands have not yet been run against live providers; see [known limitations](#honest-limits).
> Python only ([why](docs/decisions/0001-javascript-typescript.md)).

## See it work

```console
$ slopguard scan examples/vulnerable_agent
vulnerable_agent/app.py
  16   HIGH   LLM-08  Tool `run_command` passes a model-chosen argument to subprocess.run() (shell)
        ↳ line 14: tool argument `command` is chosen by the model
        ↳ line 16: passed to subprocess.run()
  21   HIGH   LLM-01  Untrusted input reaches the system prompt of client.messages.create()
        ↳ line 20: untrusted input request.args
        ↳ line 20: stored in `topic`
        ↳ line 21: placed in the system prompt of client.messages.create()
  27   CRITICAL   LLM-02  Model output reaches eval() without validation
        ↳ line 21: model output from client.messages.create()
        ↳ line 21: stored in `reply`
        ↳ line 27: passed to eval()
  30   MEDIUM   INC-02  `parse_invoice` has no implementation (pass)
  34   CRITICAL   SEC-01  Hardcoded credential assignment (q9X$…(21 chars))

1 files scanned: 2 critical, 2 high, 1 medium
```

Every flow finding shows the path the data took, so you can judge it in seconds. Each finding also has a
`fix:` line and a longer explanation: `slopguard explain LLM-02`.

## Install

Not on PyPI yet. From a clone:

```bash
git clone https://github.com/patsypppe/slopguard
cd slopguard
python -m venv .venv && . .venv/bin/activate
pip install -e .
slopguard --version
```

Once published: `pipx install --pre slopguard`. Maintainers: see [releasing](docs/releasing.md).

## Quickstart

```bash
slopguard scan .                              # scan the current folder
slopguard scan . --no-network                 # skip the PyPI package check
slopguard scan --staged                       # only what you are about to commit
slopguard scan . --format sarif -o out.sarif  # for GitHub code scanning
slopguard scan src --spec SPEC.md             # check the code against a requirements file
slopguard explain LLM-02                      # why a rule exists, and how to fix it
```

**In CI (GitHub Actions):**

```yaml
permissions: { contents: read, security-events: write }
steps:
  - uses: actions/checkout@v4
  - uses: patsypppe/slopguard@main
```

**From Python**, for example to check an assistant's answer before saving it:

```python
import slopguard

blockers = [f for f in slopguard.scan_source(answer) if f.severity >= slopguard.Severity.HIGH]
```

New to it? The [getting-started guide](docs/getting-started.md) takes five minutes. Adopting on a big
codebase? Start with a [baseline](docs/suppressing-findings.md#3-a-baseline-for-existing-code) so only new
problems fail.

## What it checks

| Family | Rules | Catches |
| --- | --- | --- |
| **LLM-app security** | LLM-01 to LLM-06, LLM-08, LLM-09, LLM-12 | Prompt-injection paths, model output reaching `eval`, shell, SQL, file paths and URLs, over-permissive agent tools, destructive tools with no confirmation, unbounded model calls |
| **Secrets** | SEC-01 | Hardcoded API keys, tokens and private keys (masked in all output) |
| **Hallucinated packages** | HAL-01 to HAL-04 | Imports that do not exist on PyPI, brand-new packages, typosquats, undeclared dependencies |
| **Unfinished code** | INC-01, INC-02, INC-04, INC-05, INC-06, INC-08 | Placeholder comments, stubs, swallowed exceptions, chat text pasted into files, many TODOs, truncated files |
| **Intent and consistency** | SPC-02, DRF-01 to DRF-03, REG-01, REG-02 | Unmet requirements, style drift from the rest of the repo, deleted or skipped tests |

The full list, with severity and fix advice for each rule, is the [rules reference](docs/rules.md).
Beyond scanning, there are optional model-assisted commands: [`gen-tests`](docs/beyond-scanning.md#generated-tests)
and [`fix`](docs/beyond-scanning.md#repair-loop) (a dry run unless you pass `--apply`).

## How well does it work?

Three checks, each reproducible from this repository. None is a guarantee; the caveats matter.

**1. Labelled corpus** (`slopguard bench`, 34 files). Every rule scores 1.00 precision; recall is 0.91,
with two labelled misses (a value that crosses a function boundary, or goes through `self`). The corpus is
small and was used to tune the rules, so treat it as a regression gate.

**2. Other scanners on that corpus** ([full report](docs/benchmarks.md)): files flagged at medium
severity or higher, run as external programs.

| Tool | LLM-app security (15) | Secrets (1) | Incomplete code (4) | Hallucinated packages (1) | False alarms on 13 safe files |
| --- | ---: | ---: | ---: | ---: | ---: |
| slopguard | 12 | 1 | 3 | 1 | 0 |
| Bandit | 6 | 0 | 0 | 0 | 1 |
| Semgrep, public python rules | 8 | 0 | 2 | 0 | 2 |
| Semgrep, public ai rules | 12 | 0 | 0 | 0 | 6 |
| vibechck | 0 | 0 | 2 | 0 | 1 |

The corpus targets what slopguard was built for, so it flatters slopguard. Bandit and Semgrep are broader
tools not designed for these cases, and Semgrep's `ai` rules are SDK best-practice lints. Semgrep also
catches the two cross-function cases slopguard misses, because it flags any dynamic `eval`.

**3. Mature packages as a false-positive control** ([report](docs/real-world-check.md)): 1.5 million lines
across twelve well-reviewed packages, including the OpenAI, Anthropic, LangChain and LiteLLM SDKs.
**0 critical or high findings** after tuning. The first run had 122 critical findings and about 900 medium
ones; fixing them is in the [changelog](CHANGELOG.md). About 25 medium and a few hundred low findings remain.
This measures noise only: those packages are not AI-generated.

## Honest limits

- **A clean scan is not proof of safety.** The flow rules follow values inside one function. They miss a
  value returned from a helper and `eval`-ed elsewhere, and values stored on `self`
  ([how it works](docs/how-it-works.md#what-it-cannot-see)).
- **Without a model, the spec check compares names and words.** It can show code exists, not that it behaves
  correctly. In the demo it reports a requirement as met while the code does the opposite.
- **Not yet run live:** the Anthropic, OpenAI and Ollama clients are tested against local servers that mimic
  their wire formats, and the Docker sandbox backend has not run against a Docker daemon.
- **Python only.** JavaScript and TypeScript files are skipped, and the scan says so when it finds nothing to read.
- **Linux CI only.** macOS and Windows should work for scanning but are untested.

## Documentation

| | |
| --- | --- |
| [Getting started](docs/getting-started.md) | Install, first scan, reading output |
| [Configuration](docs/configuration.md) | Every `slopguard.toml` setting |
| [CI integration](docs/ci-integration.md) | GitHub Action, pre-commit, GitLab |
| [Suppressing findings](docs/suppressing-findings.md) | Comments, baselines, ignores |
| [Beyond scanning](docs/beyond-scanning.md) | Spec checks, generated tests, drift, regression, repair |
| [Python API](docs/python-api.md) | Use it from your own code or agent |
| [Privacy and safety](docs/privacy-and-safety.md) | What runs, what is sent, the sandbox |
| [How it works](docs/how-it-works.md) | Pipeline and taint tracking |
| [FAQ and troubleshooting](docs/faq.md) | Common questions and fixes |
| [All docs](docs/README.md) | The full index |

## Contributing

Contributions are welcome: rules, false-positive reports, docs and tests. The most valuable thing you can
do is **report a false positive or a miss with the smallest code that shows it**; every confirmed report
becomes a regression test. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and
[writing a rule](docs/writing-rules.md), and please follow the [code of conduct](CODE_OF_CONDUCT.md).
Questions go in [Discussions or issues](SUPPORT.md); security problems in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). slopguard is independent work: it takes no code, rules, messages or structure from other
tools. The [clean-room record](docs/clean-room.md) explains how, and why other scanners are only ever *run*,
never copied. Thanks to the authors of Bandit, Semgrep and vibechck for the prior art that made the
comparison possible.
