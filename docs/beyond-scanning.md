# Beyond scanning

Scanning is the core of slopguard and needs nothing but the code. These commands go further: they check code against what you asked for, compare it with the rest of the repo and its tests, and can propose repairs. Anything that uses a model is opt-in and says what it will send first.

| You want to know | Use |
| --- | --- |
| Does the code do what the spec asks? | [`scan --spec`](#checking-code-against-a-spec) |
| Can a model write tests for the spec? | [`gen-tests`](#generated-tests) |
| Does new code look like the rest of the repo? | [`scan -m drf`](#style-drift) |
| Did this change delete or weaken tests? | [`regress`](#regression-guard) |
| Can the findings be fixed automatically? | [`fix`](#repair-loop) |

## Checking code against a spec

```bash
slopguard scan src --spec SPEC.md            # offline: name matching only
slopguard scan src --spec SPEC.md --llm      # a model judges the best-matching code
```

Each bullet (or sentence with "must", "should", "shall") in the spec becomes a requirement.
Backticked names such as `` `parse_invoice()` `` or `` `--json` `` are looked up in the code: missing
means missing, defined-but-empty means partial. Other requirements are matched by their key
words against identifiers, strings and docstrings. **Without `--llm` this can show that code
exists, not that it behaves correctly**, and the output says so. With `--llm`, only the matching
functions and the requirement text are sent to your provider, and slopguard tells you before it does.
Requirements under "Non-goals" or "Out of scope" headings are skipped.

## Generated tests

```bash
slopguard gen-tests --spec SPEC.md src --run
```

The model writes pytest tests named `test_r<N>_...` (one group per requirement); slopguard rejects
files that do not parse, have no tests, or import `subprocess`, `socket` or network libraries, writes
the file for you to review, and with `--run` executes it in a sandbox and reports per requirement.
A failing generated test lowers the verdict to partial: the test may be wrong, not only the code.

**Sandbox.** `backend = "auto"` uses Docker (`--network none`, memory, CPU and process caps; the image
must contain pytest) and otherwise a Linux user and network namespace (no network, CPU, memory and
file-size limits). If neither is available it refuses to run. `backend = "local"` runs with only a
temp copy, a stripped environment and resource limits, and is for when you accept the risk.

## Style drift

```bash
slopguard scan --staged -m drf               # compare changed files with the rest of the repo
```

Off by default. It mines naming, library choices and idioms from the files outside the change and
flags deviations. It says nothing for repos with fewer than three other Python files.

## Regression guard

```bash
slopguard regress --base main                # deleted, skipped or weakened tests
slopguard regress --base main --run-tests    # also run the suite at the base and now
```

Run it in CI on pull requests. `--run-tests` checks out the base into a temporary worktree and puts
it first on `PYTHONPATH`; a package installed in editable mode may still import the working copy.

## Repair loop

```bash
slopguard fix src                            # dry run: shows a diff
slopguard fix src --apply                    # asks before writing; --yes skips the prompt
```

Scans, sends each file with serious findings to your model, re-scans the proposal, and keeps it only
if the file still parses, is not suspiciously shorter, has fewer serious findings, and has no new
ones. Stops at `--max-rounds`, when nothing is left, or when a round makes no progress. Opening pull
requests is not implemented.

## LLM configuration

See [configuration](configuration.md#llm) and [privacy and safety](privacy-and-safety.md).
