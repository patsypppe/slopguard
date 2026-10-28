## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `make check` passes (lint, tests, self-scan, benchmark gate)
- [ ] Tests added, **including cases that must not trigger** (negative tests)
- [ ] For a new or changed rule: corpus files in `benchmarks/corpus/`, and I read what
      `python benchmarks/realworld.py --no-network` reports on real code
- [ ] `make docs` run if rules or commands changed
- [ ] `CHANGELOG.md` "unreleased" updated for user-visible changes
- [ ] I did not copy code, rules, regexes or messages from another scanner ([clean-room](docs/clean-room.md))
