# Configuration

slopguard reads, in this order, the first it finds:

1. the file given with `--config`;
2. `slopguard.toml` in the project root;
3. the `[tool.slopguard]` table in `pyproject.toml`, with the same keys as below
   (for example `[tool.slopguard.scan]`).

The project root is the nearest folder above the scanned path that contains `.git`,
`slopguard.toml` or `pyproject.toml`. Run `slopguard init` for a commented starter file.

Every setting is optional. Unknown module names, bad types and unknown providers are errors
(exit code 2) so typos do not silently do nothing.

## `[scan]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `exclude` | list of globs | `[]` | Paths to skip, matched against the path relative to the project root. `*` also matches `/`, so `tests/fixtures/**` works. Add more on the command line with `--exclude`. |
| `fail_on` | string | `"high"` | Exit code 1 at this severity or above: `critical`, `high`, `medium`, `low`, `info`, or `none`. `--fail-on` overrides it. |

Always skipped: `.git`, `.hg`, `.venv`, `venv`, `env`, `node_modules`, `__pycache__`, `.tox`, `.nox`,
`.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `site-packages`, `dist`, `build`, `.next`, `.nuxt`,
`.output`, `target`, `vendor`, `.eggs`, every other folder starting with `.`, lock files, and files
over 1 MB.

## `[modules]`

Switch groups of rules on or off. A command-line `--module` replaces this for that run.

| Key | Default | Rules |
| --- | --- | --- |
| `hal` | `true` | HAL-01 to HAL-04: hallucinated, new, typosquatted and undeclared packages |
| `inc` | `true` | INC-01 to INC-08: stubs, placeholders, swallowed errors, chat residue |
| `sec` | `true` | SEC-01: hardcoded secrets |
| `llm` | `true` | LLM-01 to LLM-12: prompt injection, unsafe model output, agent tools |
| `drf` | **`false`** | DRF-01 to DRF-03: style drift (opt in) |
| `spc` | `true` | SPC-02, only active with `scan --spec` |
| `reg` | `true` | REG-01, REG-02, only active with `regress` |

## `[rules."RULE-ID"]`

Per-rule settings. Quote the ID because it contains a dash.

| Key | Applies to | Meaning |
| --- | --- | --- |
| `enabled` | any rule | `false` turns the rule off |
| `ignore` | any rule | Globs of paths where the rule does not run |
| `threshold` | `INC-06` | Number of TODO/FIXME/HACK markers in one file that triggers it (default 5) |
| `days` | `HAL-02` | A package first published fewer than this many days ago is "new" (default 30) |

```toml
[rules."INC-06"]
threshold = 10

[rules."INC-02"]
ignore = ["src/plugins/**"]

[rules."LLM-12"]
enabled = false
```

## `[network]`

| Key | Default | Meaning |
| --- | --- | --- |
| `registry_lookups` | `true` | Ask PyPI whether imported packages exist (HAL-01, HAL-02). `--no-network` overrides it for one run. |
| `cache_ttl_hours` | `24` | How long answers are cached. The cache lives in `$SLOPGUARD_CACHE_DIR`, or `$XDG_CACHE_HOME/slopguard`, or `~/.cache/slopguard`. |

Only package names are sent to PyPI, never your code.

## `[packages]`

| Key | Default | Meaning |
| --- | --- | --- |
| `private` | `[]` | Import names that come from a private index or are generated. All HAL rules skip them. |

```toml
[packages]
private = ["acme_internal", "acme_proto"]
```

## `[taint.sources]`, `[taint.sinks]`, `[taint.sanitizers]`

Teach the flow rules about your own helpers. Each takes `extra`, a list of dotted names matched
by suffix (`myapp.llm.ask` matches `client.myapp.llm.ask`).

| Table | Effect |
| --- | --- |
| `sources` | Calls that return **model output**, as if they were `client.messages.create` |
| `sinks` | Calls treated like a shell, so model output reaching them is reported as LLM-03 |
| `sanitizers` | Calls that make a value safe: the flow is dropped when a value passes through one |

```toml
[taint.sources]
extra = ["myapp.llm.ask"]

[taint.sinks]
extra = ["myapp.runner.run_command"]

[taint.sanitizers]
extra = ["myapp.safety.validate_command"]
```

Built in as sanitizers: `ast.literal_eval`, `shlex.quote`, `int`, `float`, `bool`, `len`.

## `[llm]`

Used only by `scan --spec --llm`, `gen-tests` and `fix`.

| Key | Default | Meaning |
| --- | --- | --- |
| `provider` | `"none"` | `anthropic`, `openai`, `ollama`, or `none` |
| `model` | none | Model ID. **No default**, because names change. `SLOPGUARD_LLM_MODEL` also works. |
| `base_url` | provider default | Use a proxy, a gateway, or another host. Ollama defaults to `http://localhost:11434`. |

Keys are read from the environment, never from this file: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`.

## `[sandbox]`

Where generated tests run (`gen-tests --run`).

| Key | Default | Meaning |
| --- | --- | --- |
| `backend` | `"auto"` | `auto` (Docker, then a Linux namespace, otherwise refuse), `docker`, `unshare`, or `local` (no isolation, your risk) |
| `image` | `"python:3.12-slim"` | Docker image. It must contain pytest, so build or pick one that does. |
| `timeout` | `120` | Seconds before the run is killed |

## Environment variables

| Variable | Used for |
| --- | --- |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | Model provider keys |
| `SLOPGUARD_LLM_MODEL` | Model ID when `[llm] model` is not set |
| `SLOPGUARD_CACHE_DIR` | Where PyPI answers are cached |
| `NO_COLOR` | Turns off colour in terminal output |
