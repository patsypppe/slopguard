# Releasing to PyPI

Releases are built and published by [`.github/workflows/release.yml`](../.github/workflows/release.yml)
using **PyPI trusted publishing** (OpenID Connect). No API token is ever stored in the repository.

| You do | What happens |
| --- | --- |
| Run the workflow manually ("Actions" tab, "Release", "Run workflow") | Builds, tests the wheel in a clean environment, publishes to **TestPyPI** |
| Push a tag such as `v1.0.0rc1` | Builds, checks the tag matches the package version, publishes to **PyPI** |

## One-time setup (only the project owner can do this)

The name `slopguard` was free on both PyPI and TestPyPI when this was written. Names are first come,
first served and a pending publisher does **not** reserve one, so do step 1 and your first upload soon.

**1. Register the publisher on PyPI**, with no account token needed:

1. Sign in at <https://pypi.org> and turn on two-factor authentication.
2. Open <https://pypi.org/manage/account/publishing/> and, under *Add a new pending publisher*, enter:

   | Field | Value |
   | --- | --- |
   | PyPI project name | `slopguard` |
   | Owner | `patsypppe` |
   | Repository name | `slopguard` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

3. Repeat on <https://test.pypi.org/manage/account/publishing/> with environment name `testpypi`.

**2. Create the two GitHub environments.** In the repository: Settings, Environments, New environment,
named exactly `pypi` and `testpypi`. For `pypi`, add yourself under *Required reviewers* so a release
needs your approval, and restrict it to tags matching `v*`.

**3. Dry run on TestPyPI.** Actions, Release, Run workflow, branch `main`. When it finishes:

```bash
python -m venv /tmp/try && . /tmp/try/bin/activate
pip install --pre --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ slopguard
slopguard --version
slopguard scan --help
```

If that works, you know the packaging, the publisher setup and the workflow are all correct.

## Each release

1. Update `__version__` in `src/slopguard/__init__.py` and move the changelog entry from
   "unreleased" to the version and date.
2. Run the checks in [CONTRIBUTING.md](../CONTRIBUTING.md) (`make check`).
3. Regenerate the generated docs if rules or commands changed: `make docs`.
4. Commit, then tag and push the tag:

   ```bash
   git tag v1.0.0rc1 && git push origin v1.0.0rc1
   ```

5. Approve the `pypi` environment when GitHub asks. After publishing, the README badges for PyPI
   start working and `pipx install --pre slopguard` works.

## Before dropping the `rc` suffix

Do not publish `1.0.0` until these are true. They are listed in the changelog as known limitations.

- [ ] `scan --spec --llm`, `gen-tests` and `fix` have been run against a live provider on a real project.
- [ ] The Docker sandbox backend has been run once on a machine with a Docker daemon.
- [ ] The CI run on the release tag is green on Python 3.10 to 3.13.

## If something goes wrong

- *"invalid-publisher" or "trusted publishing exchange failure"*: the five values in step 1 must
  match the workflow exactly, including the environment name.
- *"File already exists"*: PyPI never lets you re-upload a version. Bump the version (`1.0.0rc2`).
- *Wrong release*: you cannot delete and reuse a version. Yank it on PyPI and publish the next one.
