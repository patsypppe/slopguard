# FAQ and troubleshooting

## Questions

**Is this a replacement for Bandit, Semgrep or CodeQL?**
No. They are broader and mature. slopguard targets problems specific to AI-written code and
LLM-powered apps, which general scanners mostly do not model: model output reaching `eval`, prompt
injection paths, over-permissive agent tools, invented packages, stubs, and unmet requirements.
Run it alongside them. [The benchmark](benchmarks.md) shows what each catches, with its caveats.

**Does a clean scan mean my code is safe?**
No. It means slopguard's rules found nothing. The flow rules only follow values inside one function.
See [what it cannot see](how-it-works.md#what-it-cannot-see).

**Does it need an API key or the internet?**
The scan needs neither. Package-existence checks use PyPI (names only) and are skipped with
`--no-network`. A model and its key are needed only for `--spec --llm`, `gen-tests` and `fix`.

**Does it send my code anywhere?**
Not unless you use one of those three model features, and it tells you first. There is no telemetry.
See [privacy and safety](privacy-and-safety.md).

**Why only Python?**
See the [decision record](decisions/0001-javascript-typescript.md). In short: the valuable part is the
Python-specific flow analysis and its measured accuracy, and a thin second language would dilute it.

**Which operating systems work?**
Scanning is plain Python and should run anywhere Python 3.10+ does, but CI only runs on Linux. The
sandbox backends need Linux (Docker also on macOS). macOS and Windows are untested; please report what you find.

**How fast is it?**
About 100,000 lines of Python take a few seconds. A 930,000-line package scanned in under a minute.

**Why does the spec check say "met" for something that is wrong?**
Without `--llm` it only checks names and words, and says so. The demo in the README shows a requirement
reported as met while the code does the opposite. A model, `--llm`, can judge behaviour, with its own
limits.

**Why are empty methods "low" and `except Exception: pass` "low"?**
Because on well-reviewed human code they are usually deliberate (hooks, best-effort cleanup). We
measured this; see the [real-world check](real-world-check.md). They are still worth a look in code you
did not write.

## Troubleshooting

**`0 files scanned` / "no supported files found".**
You pointed slopguard at a folder with no Python (or `.env`/config) files, or everything is excluded.
JavaScript and TypeScript are not supported. Check `[scan] exclude` and the always-skipped folders in
[configuration](configuration.md).

**A rule flags an import that does exist (HAL-01).**
The import name differs from the PyPI name, or the package is private. Private: add the import name to
`[packages] private`. Public with a different name: please
[report it](https://github.com/patsypppe/slopguard/issues/new/choose) so it can be added to the alias table.
As a workaround, suppress the line.

**HAL-01 is slow or fails offline.**
Lookups time out after a few seconds and an unknown answer is never reported as a finding, so an
offline run is quiet, not wrong. Use `--no-network` for speed.

**`slopguard: command not found`.**
With `pipx`, run `pipx ensurepath` and restart the shell. In a virtual environment, activate it.

**Exit code 2.**
A usage or configuration error: an unknown rule or module, a bad format, a missing path or spec, or an
invalid `slopguard.toml`. The message says which.

**`no LLM provider configured`.**
Add an `[llm]` section with `provider` and `model`, and export the provider's key. See
[configuration](configuration.md#llm).

**`no isolated backend available` from `gen-tests --run`.**
Neither a Docker daemon nor Linux user namespaces work here. Install Docker, or set
`[sandbox] backend = "local"` if you accept running generated tests without network isolation.

**The SARIF upload fails.**
The workflow needs `permissions: security-events: write`, and private repositories need GitHub Advanced
Security. Set `upload-sarif: "false"` otherwise.

**A finding is wrong.**
Please [open a "false positive" issue](https://github.com/patsypppe/slopguard/issues/new/choose) with the
smallest code that shows it. Every confirmed false positive becomes a regression test.
