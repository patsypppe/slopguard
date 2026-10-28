# slopguard documentation

| Start here | |
| --- | --- |
| [Getting started](getting-started.md) | Install, first scan, reading the output, fixing what it finds |
| [Command reference](cli.md) | Every command and option (generated) |
| [Rules reference](rules.md) | Every rule: why it matters, how to fix it (generated) |

| Guides | |
| --- | --- |
| [Configuration](configuration.md) | Every `slopguard.toml` setting |
| [Suppressing findings](suppressing-findings.md) | Inline comments, baselines, per-rule ignores |
| [CI integration](ci-integration.md) | GitHub Action, pre-commit, GitLab CI, SARIF, diff scanning |
| [Python API](python-api.md) | Use slopguard from your own code or agent |
| [Privacy and safety](privacy-and-safety.md) | What leaves your machine, what runs, and the sandbox |
| [FAQ and troubleshooting](faq.md) | Common questions and fixes |

| Understanding it | |
| --- | --- |
| [How it works](how-it-works.md) | Pipeline, taint tracking, and what it cannot see |
| [Benchmarks](benchmarks.md) | Comparison with Bandit, Semgrep and vibechck (generated) |
| [Real-world check](real-world-check.md) | False-positive measurement on mature packages (generated) |
| [Product and requirements document](PRD.md) | The plan behind the project |

| Contributing and maintaining | |
| --- | --- |
| [Contributing](../CONTRIBUTING.md) | Set up, checks, and the clean-room rule |
| [Writing a rule](writing-rules.md) | Rule anatomy, tests, and the benchmark corpus |
| [Releasing](releasing.md) | PyPI trusted publishing and the release checklist |
| [Decisions](decisions/) | Why Python only, and other recorded choices |
| [Clean-room record](clean-room.md) | How independence from other tools is kept |
