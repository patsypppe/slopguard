# Getting started

This takes about five minutes. You need Python 3.10 or newer and `git` (only for `--diff`, `--staged`
and `regress`).

## 1. Install

slopguard is not on PyPI yet (see [releasing](releasing.md)). Until it is, install from a clone:

```bash
git clone https://github.com/patsypppe/slopguard
cd slopguard
python -m venv .venv && . .venv/bin/activate
pip install -e .
slopguard --version
```

Once published, use `pipx install --pre slopguard` (or `pip install --pre slopguard` inside a
virtual environment). `pipx` keeps the tool out of your project's dependencies.

## 2. Scan the demo

```bash
slopguard scan examples/vulnerable_agent
```

You will see findings grouped by file:

```text
examples/vulnerable_agent/app.py
  27   CRITICAL   LLM-02  Model output reaches eval() without validation
        return eval(reply.content[0].text)
        ↳ line 21: model output from client.messages.create()
        ↳ line 21: stored in `reply`
        ↳ line 27: passed to eval()
        fix: Never execute model output. Ask for structured data (JSON), ...
```

How to read a finding:

| Part | Meaning |
| --- | --- |
| `27` | Line number |
| `CRITICAL` | Severity: `critical`, `high`, `medium`, `low` or `info` |
| `LLM-02` | Rule ID. Run `slopguard explain LLM-02` for the long explanation |
| `↳ ...` | For flow rules, the path from where the data came from to where it is used |
| `fix:` | What to do about it |

The last line summarises the scan. Exit code `1` means at least one finding at or above `--fail-on`
(default `high`).

## 3. Scan your own code

```bash
cd your-project
slopguard scan .
```

The first run does a few PyPI lookups to check that imported packages exist; they are cached for
24 hours. Add `--no-network` to skip them. Folders such as `.venv`, `node_modules`, `build` and `dist`
are skipped automatically.

**Adopting on an existing codebase?** Record what is there today, then fail only on new problems:

```bash
slopguard scan . --write-baseline .slopguard-baseline.json
slopguard scan . --baseline .slopguard-baseline.json
```

## 4. Deal with what it finds

For each finding you can fix it, or tell slopguard it is intentional.

- **Fix it.** `slopguard explain RULE-ID` says why it matters and how to fix it.
- **It is intentional.** Add `# slopguard: ignore[RULE-ID] reason` on the line. See
  [suppressing findings](suppressing-findings.md).
- **It is noise.** Please [report a false positive](https://github.com/patsypppe/slopguard/issues/new/choose).
  Rules are tuned against real code, and your example makes them better.

## 5. Put it in CI

The shortest useful setup, in `.github/workflows/slopguard.yml`:

```yaml
name: slopguard
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: patsypppe/slopguard@main
```

More options, pre-commit and GitLab are in [CI integration](ci-integration.md).

## 6. Optional: use a model

The scan itself never calls a model. Three commands can, when you configure a provider:

| Command | What the model does |
| --- | --- |
| `scan --spec SPEC.md --llm` | Judges whether code meets each requirement |
| `gen-tests` | Writes pytest tests for each requirement |
| `fix` | Proposes repairs, which slopguard re-checks before keeping them |

Create `slopguard.toml` (or run `slopguard init`) and set the provider, then export the key:

```toml
[llm]
provider = "anthropic"      # or "openai", or "ollama" for a local model
model = "your-model-id"
```

```bash
export ANTHROPIC_API_KEY=...
slopguard scan src --spec SPEC.md --llm
```

slopguard tells you what it is about to send before it sends it. Details in
[privacy and safety](privacy-and-safety.md).

## Where next

[Configuration](configuration.md), [rules reference](rules.md), [how it works](how-it-works.md).
