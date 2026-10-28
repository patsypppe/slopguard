# CI integration

slopguard exits `0` when nothing is at or above `--fail-on` (default `high`) and `1` otherwise, so any
CI system can use it. It also writes SARIF for GitHub code scanning.

## GitHub Actions

```yaml
name: slopguard
on: [pull_request]

permissions:
  contents: read
  security-events: write     # lets the SARIF upload reach code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: patsypppe/slopguard@main
        with:
          fail-on: high
```

The action installs slopguard from the action's own checkout (so the action version and the tool
version always match), scans, uploads SARIF, writes a summary to the job page, and fails the job at
`fail-on` or above. Pin `@main` to a tag such as `@v1.0.0` once releases exist.

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Files or folders to scan (space separated) |
| `fail-on` | `high` | Failing threshold, or `none` |
| `no-network` | `false` | Skip PyPI lookups (turns off HAL-01 and HAL-02) |
| `upload-sarif` | `true` | Upload to code scanning. Needs `security-events: write` |
| `python-version` | `3.12` | Python used to run slopguard |
| `extra-args` | empty | Extra arguments for `slopguard scan`, for example `--baseline .slopguard-baseline.json` |

| Output | Meaning |
| --- | --- |
| `sarif-file` | Path of the SARIF report |
| `exit-code` | `0` or `1` |

**Private repositories** need GitHub Advanced Security for the SARIF upload. Without it, set
`upload-sarif: "false"`; you still get the job summary and the failing status.

**Pull requests from forks** run with a read-only token, so the SARIF upload step is skipped by GitHub.
The scan and the pass/fail result still work.

### Only scan what a pull request changed

```yaml
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: patsypppe/slopguard@main
        with:
          extra-args: --diff origin/${{ github.base_ref }}
```

`--diff REF` scans the files that differ from `REF`. Style drift (`-m drf`) compares them with the
rest of the repo.

### Catch deleted or weakened tests

AI assistants sometimes make a failing test pass by deleting it. `regress` compares against the base:

```yaml
      - run: pip install slopguard
      - run: slopguard regress --base origin/${{ github.base_ref }}
```

Add `--run-tests` to also run the suite at the base and now. That executes your project's tests on
the runner, as your own CI already does.

## pre-commit

```yaml
repos:
  - repo: https://github.com/patsypppe/slopguard
    rev: main            # use a release tag once there is one
    hooks:
      - id: slopguard
```

The hook runs `slopguard scan --no-network --fail-on high` on the staged Python files. Override the
arguments with `args: [--fail-on, medium]`.

## GitLab CI

GitLab's security dashboards use their own report format, so use slopguard as a pass/fail job and keep
the SARIF as an artifact:

```yaml
slopguard:
  image: python:3.12
  script:
    - pip install slopguard
    - slopguard scan . --format sarif --output slopguard.sarif --fail-on high
  artifacts:
    when: always
    paths: [slopguard.sarif]
```

## Any other CI

```bash
pip install slopguard
slopguard scan . --fail-on high
```

Use `--format json` for your own tooling. The JSON has a `version` field, a `summary`, the `findings`
(each with rule, severity, confidence, path, line, message, fix, trace) and any `errors`.

## Tuning for a team

| Goal | How |
| --- | --- |
| Adopt on an existing codebase | A [baseline](suppressing-findings.md#3-a-baseline-for-existing-code) |
| Stop a noisy rule | `[rules."ID"] enabled = false` or `ignore = [globs]` |
| Block less | `--fail-on critical` |
| Block more | `--fail-on medium` (expect more noise: see [the real-world check](real-world-check.md)) |
| Faster pre-commit | `--no-network` |
