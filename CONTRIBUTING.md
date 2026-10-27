# Contributing

## Set up

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check src tests benchmarks/*.py
slopguard scan . --no-network && slopguard bench --min-precision 0.85
```

CI runs the same four checks on Python 3.10 to 3.13.

## The clean-room rule

slopguard is MIT-licensed and must stay free of code from copyleft tools. Before writing a rule
that resembles one in another scanner, read [docs/clean-room.md](docs/clean-room.md). In short:
use public documentation for ideas, write your own implementation, and do not read another tool's
source while writing the matching rule. Other tools may be *run* for benchmarking, never imported.

## Adding a rule

1. Add a class with a `RuleMeta` in `src/slopguard/rules/` and decorate it with `@register`.
   Give it an ID from the catalogue, an honest severity, a plain-language explanation and a fix,
   and CWE or OWASP references where they apply. Mark new rules `status="experimental"`.
2. Add tests with **positive and negative cases**. For every false positive you can imagine on
   ordinary code, add a negative case.
3. Add labelled files to `benchmarks/corpus/` (`# expect: RULE-ID` or `# expect: none`).
4. Run `slopguard rules --markdown > docs/rules.md`; a test fails if the reference is stale.
5. Run `python benchmarks/realworld.py --no-network` and read what the rule says about real code.
   A rule that is noisy on well-reviewed packages is not ready.

## Style

Match the surrounding code. Keep comments for the non-obvious. Error messages say what went wrong
and what to do next. No new runtime dependencies without a strong reason.

## Reporting a problem

Open an issue with the smallest input that shows it. For a security problem in slopguard itself,
see [SECURITY.md](SECURITY.md).
