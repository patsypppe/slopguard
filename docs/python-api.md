# Python API

Use slopguard from your own code: a CI script, an editor integration, or an AI agent that wants to
check what it is about to write.

```python
import slopguard

result = slopguard.scan(["src"], network=False)
for finding in result.findings:
    print(finding.severity.label, finding.rule_id, f"{finding.path}:{finding.line}", finding.message)
```

`import slopguard` is cheap; the API loads on first use. The package ships a `py.typed` marker.

## `slopguard.scan(paths=(".",), *, config=None, config_path=None, modules=(), rules=(), network=True)`

Scans files or folders and returns a `ScanResult`.

| Argument | Meaning |
| --- | --- |
| `paths` | Files or folders. A missing path raises `FileNotFoundError` |
| `config` | A `Config` object. It wins over `config_path` |
| `config_path` | A `slopguard.toml`. With neither, the project's own file is read |
| `modules` | Run only these modules, for example `["llm", "sec"]` |
| `rules` | Run only these rule IDs, for example `["LLM-02"]` |
| `network` | `False` skips PyPI lookups |

Unknown modules or rule IDs raise `ValueError`; a bad configuration raises
`slopguard.config.ConfigError`.

`ScanResult` has `findings` (a sorted list), `files_scanned` and `errors` (rules that crashed on a
file, which never stop the scan).

## `slopguard.scan_source(source, filename="snippet.py", *, config=None, modules=(), rules=())`

Scans a string and returns a list of findings. It is offline and never writes anything, so it suits
checking an assistant's answer **before** saving it:

```python
code = assistant_answer()
blockers = [f for f in slopguard.scan_source(code) if f.severity >= slopguard.Severity.HIGH]
if blockers:
    ask_assistant_to_fix(blockers)
```

PyPI lookups (HAL-01, HAL-02) are skipped because they need the network. Checks that read the project
(undeclared dependencies, local modules) use the current working directory.

## `Finding`

| Field | Type | Meaning |
| --- | --- | --- |
| `rule_id` | `str` | For example `"LLM-02"` |
| `severity` | `Severity` | `INFO < LOW < MEDIUM < HIGH < CRITICAL`; compare with `>=` |
| `confidence` | `float` | 0 to 1. Flow rules use lower values for guesses such as a parameter that merely looks like model output |
| `message`, `explanation`, `fix` | `str` | What, why, and what to do |
| `path`, `line`, `end_line` | `str`, `int`, `int` | Where. `path` is relative to the project root |
| `excerpt` | `str` | The offending line (credentials are masked) |
| `trace` | `tuple[str, ...]` | For flows, the steps from source to sink |
| `cwe`, `owasp` | `tuple[str, ...]` | References |

`finding.to_dict()` gives the same structure the JSON output uses, and `finding.fingerprint()` the
stable identifier baselines use.

## `Config`

```python
from slopguard import Config

config = Config()
config.modules["drf"] = True            # opt in to style drift
config.rules["INC-06"] = {"threshold": 10}
config.private_packages = ["acme_internal"]
slopguard.scan(["src"], config=config)
```

`Config.load(root)` reads the project's file, and `Config.from_mapping(dict)` builds one from a dict
shaped like the TOML.
