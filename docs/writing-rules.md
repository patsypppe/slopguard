# Writing a rule

A rule is a class with metadata and a `check` method. Read [CONTRIBUTING](../CONTRIBUTING.md) first, in
particular the [clean-room rule](clean-room.md): write your own implementation from public references.

## Anatomy

```python
# src/slopguard/rules/example.py
from __future__ import annotations

import ast
from collections.abc import Iterable

from slopguard.context import FileContext
from slopguard.models import Finding, Rule, RuleMeta, Severity
from slopguard.rules import register


@register
class TodoReturn(Rule):
    meta = RuleMeta(
        id="INC-99",                      # prefix = module: HAL, INC, SEC, LLM, DRF, SPC, REG
        title="Function returns a TODO string",
        module="inc",                     # decides which [modules] switch controls it
        severity=Severity.MEDIUM,
        explanation="Returning a placeholder string makes a stub look like working code.",
        fix="Implement the function or raise NotImplementedError.",
        cwe=(),                           # references where they genuinely apply
        status="experimental",            # new rules start here
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        if ctx.tree is None:              # the file did not parse
            return
        for node in ast.walk(ctx.tree):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str) and "TODO" in node.value.value:
                    yield ctx.make_finding(self.meta, node.lineno, "Function returns a TODO string",
                                           confidence=0.8)
```

Register the module by adding it to the import list at the bottom of
`src/slopguard/rules/__init__.py`.

### What `FileContext` gives you

| Attribute | Meaning |
| --- | --- |
| `ctx.tree` | The parsed `ast.Module`, or `None` if the file did not parse |
| `ctx.source`, `ctx.lines` | Raw text and its lines |
| `ctx.rel`, `ctx.path` | Path relative to the project root, and the absolute path |
| `ctx.options("INC-99")` | The user's `[rules."INC-99"]` settings |
| `ctx.project` | Declared dependencies, local modules, the PyPI client, mined repo conventions |
| `ctx.cache` | A dict shared by rules for this file (the flow rules compute their flows once here) |
| `ctx.make_finding(meta, line, message, ...)` | Builds a finding. Optional: `end_line`, `confidence`, `excerpt`, `trace`, `severity` (to override the rule's default for one finding) |

## Choosing severity and confidence

- **Severity** is the harm if the finding is right. `critical`: code execution or a leaked credential.
  `high`: a vulnerability that needs one more condition. `medium`: a defect or likely bug. `low`: style
  or hygiene. The default `--fail-on high` makes `high` and `critical` block a build, so be conservative.
- **Confidence** (0 to 1) is how likely it is right. Use a lower value for a guess, and a lower
  *severity* for the weaker cases of the same rule. Real code taught us this: hollow methods are usually
  hooks (low), hollow free functions are usually stubs (medium).
- If a human wrote a comment or docstring that explains the pattern, assume it is intentional.

## Tests

Use the `scan` fixture from `tests/conftest.py`. It writes files into a temporary project and returns
findings.

```python
def test_todo_string_is_flagged(scan):
    findings = scan({"a.py": "def f():\n    return 'TODO'\n"}, rule_ids=("INC-99",))
    assert [f.rule_id for f in findings] == ["INC-99"]

def test_ordinary_strings_are_clean(scan):
    assert scan({"a.py": "def f():\n    return 'done'\n"}, rule_ids=("INC-99",)) == []
```

Write the **negative** tests first. For every ordinary code pattern you can think of that should *not*
trigger the rule, add one.

## The benchmark corpus

Add a vulnerable and a safe example to `benchmarks/corpus/vulnerable/` and `.../safe/`. The first
line is the label:

```python
# expect: INC-99
```

or `# expect: none` for safe files. `slopguard bench --min-precision 0.85` must still pass. If your rule
has a known blind spot, add a file named `gap_<what>.py` that labels the correct answer, so the miss is
measured instead of hidden.

## Check it on real code

```bash
python benchmarks/realworld.py --no-network
```

Read every new finding it produces on well-reviewed packages. If you cannot explain why a finding is
right, the rule is not ready: tighten it or lower its severity. [`docs/real-world-check.md`](real-world-check.md)
shows what happened to the first rules.

## Finish

```bash
make docs      # regenerate docs/rules.md and docs/cli.md (a test fails if they are stale)
make check     # lint, tests, self-scan, benchmark gate
```

Add a line to the "unreleased" section of [CHANGELOG.md](../CHANGELOG.md).
