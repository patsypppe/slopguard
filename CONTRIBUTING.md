# Contributing to slopguard

Thank you for helping. slopguard gets better mostly from **real examples**: code it flagged wrongly, code
it missed, and rules for new ways assistants go wrong. You do not need to write code to help.

By taking part you agree to follow the [code of conduct](CODE_OF_CONDUCT.md).

## Ways to help, easiest first

1. **Report a false positive or a miss** with the smallest code that shows it. Use the
   [issue forms](https://github.com/patsypppe/slopguard/issues/new/choose). Each confirmed report becomes a
   regression test.
2. **Improve the docs**: a confusing sentence, a missing example, a typo. Edit the file and open a pull request.
3. **Try it on your own project** and tell us what the noise level was like.
4. **Write or improve a rule**: see [writing a rule](docs/writing-rules.md).
5. **Run the unverified parts**: the live model providers and the Docker sandbox backend have not been run by the
   maintainers (see the [changelog](CHANGELOG.md)). A report of what happened is valuable.

## Set up

You need Python 3.10 or newer and git.

```bash
git clone https://github.com/patsypppe/slopguard
cd slopguard
python -m venv .venv && . .venv/bin/activate
make install        # pip install -e ".[dev]"
make check          # lint, tests, scan itself, benchmark gate: what CI runs
```

Other targets: `make test`, `make lint`, `make docs` (regenerate `docs/rules.md` and `docs/cli.md`),
`make build`, `make help`. Without `make`, read the [Makefile](Makefile); every target is one short command.
Optionally `pip install pre-commit && pre-commit install` to run the basic checks on every commit.

## Making a change

1. Open an issue first for anything bigger than a small fix, so we can agree on the approach.
2. Branch from `main`: `git switch -c fix-short-description`.
3. Make the change **with tests**. A new rule needs positive tests *and* negative tests (code that must not
   trigger it), plus labelled files in `benchmarks/corpus/`.
4. Run `make check`. If you changed rules or commands, run `make docs` and commit the result.
5. If the change is user-visible, add a line under "unreleased" in [CHANGELOG.md](CHANGELOG.md).
6. Open a pull request and fill in the template. Small, focused pull requests are reviewed fastest.

CI runs on Python 3.10 to 3.13 and must be green to merge.

## The clean-room rule

slopguard is MIT-licensed and must stay free of code from copyleft tools. Before writing a rule that
resembles one in another scanner, read [docs/clean-room.md](docs/clean-room.md). In short: use public
documentation for ideas, write your own implementation, and do not read another tool's source while writing
the matching rule. Other tools may be *run* for benchmarking, never imported, vendored or copied. A pull
request that looks derived from another tool's code will be declined.

## Standards

- **Honesty over polish.** If a rule has a blind spot, say so in the docs and add a labelled `gap_` file to the
  corpus. If something is unverified, say so.
- **False positives are bugs.** A rule that is noisy on well-reviewed code is not ready. Run
  `python benchmarks/realworld.py --no-network` and read what your change does to real packages.
- **Severity is a promise.** `high` and `critical` fail builds by default. Use them only when the finding is
  very likely a real problem.
- **Style.** Match the surrounding code. Comments only for the non-obvious. Error messages say what went wrong
  and what to do next. No new runtime dependencies without a strong reason.
- **No secrets in tests.** Build secret-looking strings at runtime (`"sk-" + "..."`) so no key-shaped value is
  committed.

## Project layout

```text
src/slopguard/
  cli.py            commands and options          api.py        the supported Python API
  engine.py         discovery, running, baselines  config.py     slopguard.toml
  taint.py          the flow tracker               rules/        one module per rule family
  spec.py           requirement checking           drift.py      repo-convention mining
  regress.py        test-regression checks         repair.py     verify-and-repair loop
  llm.py            provider clients               sandbox.py    isolated test runs
  reporters.py      terminal, JSON, Markdown, SARIF
tests/              pytest; fixtures build projects in temp folders
benchmarks/         labelled corpus, comparison and real-world scripts
docs/               guides; rules.md and cli.md are generated
```

## Maintainers

The project is maintained by [@patsypppe](https://github.com/patsypppe). Decisions that change behaviour or
scope are recorded in [docs/decisions](docs/decisions/). Releases follow [docs/releasing.md](docs/releasing.md).
If you would like to help maintain, say so in an issue after a few merged contributions.

## Security and conduct

Security problems in slopguard itself: [SECURITY.md](SECURITY.md). Conduct concerns:
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
