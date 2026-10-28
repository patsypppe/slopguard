# Suppressing findings

A finding you have judged and accepted should not keep failing your build. There are four ways to
say so, from narrowest to broadest.

## 1. On the line

```python
result = eval(expression)  # slopguard: ignore[LLM-02] expression is validated upstream
```

- The comment can sit on the line of the finding, or alone on the line directly above it.
- List several rules with commas: `# slopguard: ignore[LLM-02, SEC-01]`.
- `# slopguard: ignore` with no brackets suppresses every rule on that line. Prefer naming the rule.
- Write a reason. Your reviewers, and you in six months, need it.

## 2. In the configuration

Turn a rule off for some paths, or everywhere:

```toml
[rules."INC-02"]
ignore = ["src/plugins/**"]   # not in these paths

[rules."LLM-12"]
enabled = false               # not at all
```

Skip whole paths for every rule with `[scan] exclude`. See [configuration](configuration.md).

## 3. A baseline, for existing code

A baseline records today's findings so that only **new** ones fail:

```bash
slopguard scan . --write-baseline .slopguard-baseline.json    # once; commit the file
slopguard scan . --baseline .slopguard-baseline.json          # in CI
```

A baseline entry is identified by the rule, the file and the text of the offending line, not its
line number, so moving code around does not resurrect old findings. Changing the offending line
does, which is what you want. Delete entries by regenerating the file as you fix things.

## 4. Raise the bar

If a severity is just too noisy for you, fail only on what matters:

```bash
slopguard scan . --fail-on critical     # exit 1 only for critical findings
slopguard scan . --severity high        # also hide anything below high from the output
```

Note that `--severity` filters before the exit code is decided.

## What not to do

Do not suppress `SEC-01` on a real credential. Rotate the credential and read it from the
environment instead. A key in git history stays there even after you delete the line.
