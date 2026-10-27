# Releasing

Releases are built and published by `.github/workflows/release.yml` when a tag like `v1.0.0` is
pushed. Publishing uses PyPI trusted publishing, so no token is stored in the repository.

## One-time setup (needs the PyPI account owner)

1. On pypi.org, create the project `slopguard` (or add a *pending publisher* before the first upload).
2. Add a trusted publisher: owner `patsypppe`, repository `slopguard`, workflow `release.yml`,
   environment `pypi`.
3. In the GitHub repository settings, create an environment named `pypi`. Consider requiring a reviewer.
4. Optionally repeat on test.pypi.org with environment `testpypi` for a dry run.

## Each release

1. Update `__version__` in `src/slopguard/__init__.py` and move the changelog entry from
   "unreleased" to the version and date.
2. Run the checks in [CONTRIBUTING.md](../CONTRIBUTING.md), then `python -m build` and `twine check dist/*`.
3. Regenerate the reports if rules changed:
   `slopguard rules --markdown > docs/rules.md`, `python benchmarks/compare.py ... --write docs/benchmarks.md`,
   `python benchmarks/realworld.py --write docs/real-world-check.md`.
4. Commit, tag (`git tag v1.0.0`) and push the tag. The workflow checks that the tag matches the
   package version before publishing.

## Before calling it 1.0.0

The release candidate is deliberately `1.0.0rc1`. Do not drop the suffix until:

- `scan --spec --llm`, `gen-tests` and `fix` have been run against a live provider on a real project.
- The Docker sandbox backend has been run once on a machine with a Docker daemon.
- The CI run on the tag is green on all four Python versions.
