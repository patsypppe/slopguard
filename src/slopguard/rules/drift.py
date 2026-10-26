"""DRF rules: new code that does not look like the rest of the repository.

These rules are opt-in (``--module drf`` or ``drf = true``). They compare each file with
conventions mined from the rest of the repo, so they need at least three other Python files
to say anything.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from slopguard.context import FileContext
from slopguard.drift import (
    JOBS,
    PASCAL,
    SNAKE,
    imported_modules,
    is_script,
    is_test_path,
    print_calls,
    public_functions,
)
from slopguard.models import Finding, Rule, RuleMeta, Severity
from slopguard.rules import register

DOMINANT = 0.8
MIN_SAMPLE = 10


class _DriftRule(Rule):
    def applies(self, ctx: FileContext) -> bool:
        if ctx.tree is None or is_test_path(ctx.rel):
            return False
        changed = ctx.project.changed
        if changed is not None and ctx.path.resolve() not in changed:
            return False
        return ctx.project.conventions().usable


@register
class NamingDrift(_DriftRule):
    meta = RuleMeta(
        id="DRF-01",
        title="Naming style differs from the rest of the repo",
        module="drf",
        severity=Severity.LOW,
        explanation=(
            "Assistants default to their own naming habits. Code that names things differently "
            "from its neighbours is harder to read and search."
        ),
        fix="Rename to match the repository's convention.",
        status="experimental",
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        if not self.applies(ctx):
            return
        conv = ctx.project.conventions()
        reported = 0
        if conv.functions >= MIN_SAMPLE and conv.snake_ratio() >= DOMINANT:
            for func in public_functions(ctx.tree):
                if not SNAKE.match(func.name) and reported < 3:
                    reported += 1
                    yield ctx.make_finding(
                        self.meta,
                        func.lineno,
                        f"`{func.name}` is not snake_case; {conv.snake_ratio():.0%} of this "
                        "repo's functions are",
                        confidence=0.7,
                    )
        if conv.classes >= MIN_SAMPLE // 2 and conv.pascal_ratio() >= DOMINANT:
            for node in ast.walk(ctx.tree):
                if isinstance(node, ast.ClassDef) and not PASCAL.match(node.name) and reported < 3:
                    reported += 1
                    yield ctx.make_finding(
                        self.meta,
                        node.lineno,
                        f"class `{node.name}` is not PascalCase; {conv.pascal_ratio():.0%} of "
                        "this repo's classes are",
                        confidence=0.7,
                    )


@register
class DuplicateLibrary(_DriftRule):
    meta = RuleMeta(
        id="DRF-02",
        title="New library for a job the repo already covers",
        module="drf",
        severity=Severity.MEDIUM,
        explanation=(
            "The repo already uses one library for this job. A second one adds a dependency "
            "and two ways of doing the same thing."
        ),
        fix="Use the library the repo already uses, or agree on a migration in a separate change.",
        status="experimental",
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        if not self.applies(ctx):
            return
        conv = ctx.project.conventions()
        modules = imported_modules(ctx.tree)
        for job, members in JOBS.items():
            chosen = conv.job_choice(job)
            if chosen is None:
                continue
            for module in members:
                if module != chosen and module in modules and conv.imports[module] < 2:
                    yield ctx.make_finding(
                        self.meta,
                        modules[module],
                        f"uses `{module}` for {job}, but the repo uses `{chosen}`",
                        confidence=0.65,
                    )


@register
class IdiomDrift(_DriftRule):
    meta = RuleMeta(
        id="DRF-03",
        title="Idiom differs from the rest of the repo",
        module="drf",
        severity=Severity.LOW,
        explanation=(
            "Examples: print() in a codebase that logs, or missing type hints where nearly "
            "every function has them. These are common signs of pasted, unadapted output."
        ),
        fix="Follow the repo's pattern: use its logger, add the type hints.",
        status="experimental",
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        if not self.applies(ctx):
            return
        conv = ctx.project.conventions()
        if not is_script(ctx.rel) and conv.imports["logging"] >= 3 and conv.print_files / conv.files <= 0.2:
            calls = print_calls(ctx.tree)
            if calls:
                yield ctx.make_finding(
                    self.meta,
                    calls[0],
                    f"print() used here, but the repo logs with logging ({len(calls)} call(s) in this file)",
                    confidence=0.6,
                )
        if conv.functions >= MIN_SAMPLE and conv.annotated_ratio() >= DOMINANT:
            bare = [f for f in public_functions(ctx.tree) if f.returns is None]
            if bare:
                yield ctx.make_finding(
                    self.meta,
                    bare[0].lineno,
                    f"{len(bare)} public function(s) lack return type hints; "
                    f"{conv.annotated_ratio():.0%} of the repo's have them",
                    confidence=0.6,
                )
