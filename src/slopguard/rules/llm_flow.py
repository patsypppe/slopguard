"""LLM-01 to LLM-06: taint flows into and out of language-model calls."""

from __future__ import annotations

from collections.abc import Iterable

from slopguard.context import FileContext
from slopguard.models import Finding, Rule, RuleMeta, Severity
from slopguard.rules import register
from slopguard.taint import Flow, find_flows

OWASP_OUTPUT_HANDLING = "LLM05:2025 Improper Output Handling"
OWASP_PROMPT_INJECTION = "LLM01:2025 Prompt Injection"


def flows_for(ctx: FileContext) -> list[Flow]:
    """All taint flows in the file, computed once and shared by every flow-based rule."""
    if "flows" not in ctx.cache:
        ctx.cache["flows"] = find_flows(ctx.tree, ctx.config) if ctx.tree is not None else []
    return ctx.cache["flows"]


class _FlowRule(Rule):
    def describe(self, flow: Flow) -> str:
        return f"Model output reaches {flow.sink}() without validation"

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        for flow in flows_for(ctx):
            if flow.rule_id != self.meta.id:
                continue
            yield ctx.make_finding(
                self.meta,
                flow.line,
                self.describe(flow),
                end_line=flow.end_line,
                confidence=flow.confidence,
                trace=flow.trace,
            )


@register
class UntrustedInputToPrompt(_FlowRule):
    meta = RuleMeta(
        id="LLM-01",
        title="Untrusted input reaches the prompt of a model call",
        module="llm",
        severity=Severity.HIGH,
        explanation=(
            "Text from users, web pages or the command line was placed where the model treats "
            "it as instructions (the system prompt) or glued into a prompt string. An attacker "
            "can override your instructions (prompt injection)."
        ),
        fix="Keep instructions constant. Send untrusted text only as a user message or inside "
        "clearly delimited data, and validate or limit what the model's answer can trigger.",
        cwe=("CWE-77",),
        owasp=(OWASP_PROMPT_INJECTION,),
    )

    def describe(self, flow: Flow) -> str:
        return f"Untrusted input reaches the {flow.label} of {flow.sink}()"


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


@register
class ModelOutputToSql(_FlowRule):
    meta = RuleMeta(
        id="LLM-04",
        title="Model output used to build a SQL query",
        module="llm",
        severity=Severity.HIGH,
        explanation=(
            "A query built from model output can be steered into reading or destroying data it "
            "was never meant to touch."
        ),
        fix="Use parameterised queries with fixed SQL, or map the model's answer to a fixed "
        "set of allowed queries. Run the model's database user with read-only rights.",
        cwe=("CWE-89",),
        owasp=(OWASP_OUTPUT_HANDLING,),
    )

    def describe(self, flow: Flow) -> str:
        return f"Model output is used as the SQL text in {flow.sink}()"


@register
class ModelOutputToPath(_FlowRule):
    meta = RuleMeta(
        id="LLM-05",
        title="Model output used as a file path",
        module="llm",
        severity=Severity.HIGH,
        explanation=(
            "A path chosen by the model can point anywhere on disk, including secrets or system "
            "files, and can overwrite or delete them."
        ),
        fix="Resolve the path against a fixed base directory, reject anything that escapes it, "
        "and prefer an allow-list of file names.",
        cwe=("CWE-22",),
        owasp=(OWASP_OUTPUT_HANDLING,),
    )

    def describe(self, flow: Flow) -> str:
        return f"Model output is used as a file path in {flow.sink}()"


@register
class ModelOutputToUrl(_FlowRule):
    meta = RuleMeta(
        id="LLM-06",
        title="Model output used as a request URL",
        module="llm",
        severity=Severity.HIGH,
        explanation=(
            "A URL chosen by the model can target internal services or cloud metadata "
            "endpoints (server-side request forgery)."
        ),
        fix="Allow-list hosts, block private and link-local addresses, and fetch through a "
        "proxy with no access to internal networks.",
        cwe=("CWE-918",),
        owasp=(OWASP_OUTPUT_HANDLING,),
    )

    def describe(self, flow: Flow) -> str:
        return f"Model output is used as the URL in {flow.sink}()"
