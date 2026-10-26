"""LLM-02 and LLM-03: model output reaching code or shell execution."""

from __future__ import annotations

from collections.abc import Iterable

from slopguard.context import FileContext
from slopguard.models import Finding, Rule, RuleMeta, Severity
from slopguard.rules import register
from slopguard.taint import Flow, find_flows

OWASP_OUTPUT_HANDLING = "LLM05:2025 Improper Output Handling"


def _flows(ctx: FileContext) -> list[Flow]:
    if "flows" not in ctx.cache:
        ctx.cache["flows"] = find_flows(ctx.tree, ctx.config) if ctx.tree is not None else []
    return ctx.cache["flows"]


class _FlowRule(Rule):
    def check(self, ctx: FileContext) -> Iterable[Finding]:
        for flow in _flows(ctx):
            if flow.rule_id != self.meta.id:
                continue
            yield ctx.make_finding(
                self.meta,
                flow.line,
                f"Model output reaches {flow.sink}() without validation",
                end_line=flow.end_line,
                confidence=0.9 if flow.certain else 0.55,
                trace=flow.trace,
            )


@register
class ModelOutputToEval(_FlowRule):
    meta = RuleMeta(
        id="LLM-02",
        title="Model output passed to eval, exec or compile",
        module="llm",
        severity=Severity.CRITICAL,
        explanation=(
            "Whatever the model returns can be steered by prompt injection. Executing it as "
            "code gives an attacker code execution in your process."
        ),
        fix="Never execute model output. Ask for structured data (JSON), parse it with "
        "json.loads or ast.literal_eval, and validate it against a schema.",
        cwe=("CWE-95", "CWE-94"),
        owasp=(OWASP_OUTPUT_HANDLING,),
    )


@register
class ModelOutputToShell(_FlowRule):
    meta = RuleMeta(
        id="LLM-03",
        title="Model output passed to a shell or subprocess",
        module="llm",
        severity=Severity.CRITICAL,
        explanation=(
            "Model output used in a command line lets prompt injection run arbitrary commands "
            "on the host."
        ),
        fix="Choose from an allow-list of fixed commands, pass arguments as a list with "
        "shell=False, and validate every value the model supplies.",
        cwe=("CWE-78",),
        owasp=(OWASP_OUTPUT_HANDLING,),
    )
