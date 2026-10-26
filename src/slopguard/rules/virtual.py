"""Rules that need more than one file or an external run.

They appear in ``slopguard rules`` and in SARIF output so their findings carry full
metadata, but their ``check`` does nothing during a normal scan. They are produced by
``scan --spec`` (SPC-02) and ``regress`` (REG-01, REG-02).
"""

from __future__ import annotations

from collections.abc import Iterable

from slopguard.context import FileContext
from slopguard.models import Finding, Rule, RuleMeta, Severity
from slopguard.rules import register


class _External(Rule):
    def check(self, ctx: FileContext) -> Iterable[Finding]:
        return ()


@register
class SpecConformance(_External):
    meta = RuleMeta(
        id="SPC-02",
        title="Requirement not met by the code",
        module="spc",
        severity=Severity.HIGH,
        explanation=(
            "A requirement in the spec has no matching implementation, or only a partial or "
            "empty one. AI assistants often skip or only half-build part of a request."
        ),
        fix="Implement the missing behaviour, or remove the requirement from the spec if it "
        "was dropped on purpose.",
        status="experimental",
    )


@register
class RegressedTest(_External):
    meta = RuleMeta(
        id="REG-01",
        title="Test that passed before now fails or is missing",
        module="reg",
        severity=Severity.HIGH,
        explanation="The change broke behaviour the existing test suite protected.",
        fix="Fix the code, not the test. If the behaviour changed on purpose, update the test "
        "and say so in the review.",
    )


@register
class WeakenedTests(_External):
    meta = RuleMeta(
        id="REG-02",
        title="Tests deleted, skipped or weakened",
        module="reg",
        severity=Severity.HIGH,
        explanation=(
            "Assistants sometimes make a failing test pass by deleting it, skipping it or "
            "removing assertions, which hides the bug instead of fixing it."
        ),
        fix="Restore the test or assertion and fix the code. If a test is truly obsolete, "
        "remove it in a separate, explained change.",
    )
