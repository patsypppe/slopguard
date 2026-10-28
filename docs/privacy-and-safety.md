# Privacy and safety

## What slopguard does with your code

| Activity | Runs your code? | Sends anything off your machine? |
| --- | --- | --- |
| `scan` and all rules | **No.** Code is only parsed with Python's `ast`; it is never imported or executed | Package **names** to `pypi.org` for HAL-01 and HAL-02. Off with `--no-network` |
| `regress` | No | No |
| `regress --run-tests` | **Yes: your own test suite**, at the base ref and now, with your Python and no sandbox. This is what your CI already does | No |
| `scan --spec` without `--llm` | No | No |
| `scan --spec --llm` | No | The requirement text and up to four matching functions (about 8,000 characters) to your configured model provider |
| `gen-tests` | No | The requirements and the **signatures** of your public functions (up to about 9,000 characters) to your provider |
| `gen-tests --run` | **Yes: model-written tests**, in a sandbox (below) | No |
| `fix` | No | Each file that has serious findings, plus the findings, to your provider |

There is **no telemetry**. Nothing is sent anywhere unless the table says so. Before any model call
slopguard prints which provider and what kind of data, to standard error.

Model features are off until you configure `[llm]`. The scan never needs a model.

## Credentials

- Matched secrets are masked in all output (`sk-p…(51 chars)`), including SARIF and JSON.
- `fix` **refuses to send a file that contains a hardcoded credential** to a model. Remove it and
  rotate it first.
- API keys for model providers come from environment variables, never from the config file.

## The sandbox for generated tests

Model-written tests are untrusted code, so `gen-tests --run` runs them in a sandbox. First, slopguard
rejects generated files that do not parse, contain no tests, or import `subprocess`, `socket` or common
network libraries, but that is only a first filter.

| Backend | Isolation | Notes |
| --- | --- | --- |
| `docker` | No network, 512 MB memory, 1 CPU, 256 processes, throwaway container | The image must contain pytest. **Not yet run against a live Docker daemon by the maintainers** |
| `unshare` | New user and network namespace (no network), CPU, memory and file-size limits, minimal environment, temp copy of the project | Linux only; some systems restrict unprivileged user namespaces |
| `local` | A temp copy, a stripped environment and resource limits. **No network isolation** | Only when you ask for it by name |

`auto` picks Docker, then `unshare`, and **refuses to run** if neither works rather than run
unisolated. The project is copied (50 MB cap) so tests cannot modify your working tree.

## What slopguard cannot promise

- A clean scan is not a proof of safety. The flow rules follow values inside one function only; see
  [how it works](how-it-works.md#what-it-cannot-see).
- `fix` proposals are re-checked by slopguard's own rules, which catch what the rules know about. Review
  every diff. The default is a dry run.
- Generated tests can be wrong. A failing one lowers a verdict to "partial"; it does not prove the code
  is wrong.

Scan only code you own or are authorised to test.
