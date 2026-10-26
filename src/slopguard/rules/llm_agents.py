"""LLM-08, LLM-09 and LLM-12: agent tools and unbounded model calls."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from slopguard.context import FileContext
from slopguard.models import Finding, Rule, RuleMeta, Severity
from slopguard.rules import register
from slopguard.rules.llm_flow import flows_for
from slopguard.taint import collect_tool_names, dotted_name, is_tool_function

OWASP_EXCESSIVE_AGENCY = "LLM06:2025 Excessive Agency"
OWASP_UNBOUNDED = "LLM10:2025 Unbounded Consumption"

DANGEROUS_TOOL_CLASSES = {
    "PythonREPLTool": "Python code execution",
    "PythonAstREPLTool": "Python code execution",
    "PythonREPL": "Python code execution",
    "ShellTool": "shell access",
    "BashProcess": "shell access",
    "TerminalTool": "shell access",
}
DANGEROUS_TOOL_NAMES = {
    "terminal": "shell access",
    "python_repl": "Python code execution",
    "python_repl_ast": "Python code execution",
    "requests_all": "unrestricted HTTP requests",
}
DANGEROUS_FLAGS = ("allow_dangerous_code", "allow_dangerous_requests", "allow_dangerous_tools")

DESTRUCTIVE_CALLS = frozenset(
    {"remove", "unlink", "rmdir", "rmtree", "delete", "drop_table", "truncate", "drop"}
)
DESTRUCTIVE_SQL = re.compile(r"\b(DROP|DELETE|TRUNCATE)\b")
CONFIRM_NAME = re.compile(r"(confirm|approv|ask_user|human|dry_run|input)", re.IGNORECASE)

OPENAI_STYLE = ("chat.completions.create", "chat.completions.parse", "completions.create",
                "responses.create")
TOKEN_CAPS = frozenset({"max_tokens", "max_completion_tokens", "max_output_tokens"})


@register
class ExcessiveAgency(Rule):
    meta = RuleMeta(
        id="LLM-08",
        title="Agent tool gives the model unrestricted capabilities",
        module="llm",
        severity=Severity.HIGH,
        explanation=(
            "The model chooses tool arguments, and a prompt-injected model chooses hostile ones. "
            "A tool that runs commands or code, or passes arguments to files, SQL or the network "
            "unchecked, hands that control to whoever can influence the prompt."
        ),
        fix="Give each tool one narrow job with a fixed allow-list of actions, validate every "
        "argument against a schema, and run tools with least privilege in a sandbox.",
        cwe=("CWE-269",),
        owasp=(OWASP_EXCESSIVE_AGENCY,),
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        if ctx.tree is None:
            return
        for flow in flows_for(ctx):
            if flow.rule_id != "LLM-08":
                continue
            yield ctx.make_finding(
                self.meta,
                flow.line,
                f"Tool `{flow.owner}` passes a model-chosen argument to {flow.sink}() ({flow.label})",
                end_line=flow.end_line,
                confidence=flow.confidence,
                trace=flow.trace,
            )
        yield from self._dangerous_toolkits(ctx)

    def _dangerous_toolkits(self, ctx: FileContext) -> Iterable[Finding]:
        for node in ast.walk(ctx.tree):
            if not isinstance(node, ast.Call):
                continue
            name = (dotted_name(node.func) or "").rsplit(".", 1)[-1]
            if name in DANGEROUS_TOOL_CLASSES:
                yield ctx.make_finding(
                    self.meta,
                    node.lineno,
                    f"{name}() gives the agent unrestricted {DANGEROUS_TOOL_CLASSES[name]}",
                    confidence=0.9,
                )
                continue
            flagged = [
                kw.arg
                for kw in node.keywords
                if kw.arg in DANGEROUS_FLAGS
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ]
            if flagged:
                yield ctx.make_finding(
                    self.meta,
                    node.lineno,
                    f"{name or 'call'}() opts in to dangerous agent behaviour ({flagged[0]}=True)",
                    confidence=0.9,
                )
                continue
            if name == "load_tools" and node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                for item in node.args[0].elts:
                    if isinstance(item, ast.Constant) and item.value in DANGEROUS_TOOL_NAMES:
                        yield ctx.make_finding(
                            self.meta,
                            node.lineno,
                            f"load_tools() enables {DANGEROUS_TOOL_NAMES[item.value]} ({item.value!r})",
                            confidence=0.85,
                        )


@register
class DestructiveToolWithoutConfirmation(Rule):
    meta = RuleMeta(
        id="LLM-09",
        title="Destructive agent tool with no confirmation step",
        module="llm",
        severity=Severity.MEDIUM,
        explanation=(
            "The tool deletes or drops data, and nothing asks a person to approve the action "
            "first. One bad model decision is then irreversible."
        ),
        fix="Require human approval before destructive actions, or add a dry-run mode that "
        "the model must call first.",
        cwe=("CWE-862",),
        owasp=(OWASP_EXCESSIVE_AGENCY,),
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        if ctx.tree is None:
            return
        tool_names = collect_tool_names(ctx.tree)
        for node in ast.walk(ctx.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not is_tool_function(node, tool_names):
                continue
            action = self._destructive_action(node)
            if action is None or self._has_confirmation(node):
                continue
            yield ctx.make_finding(
                self.meta,
                node.lineno,
                f"Tool `{node.name}` performs a destructive action ({action}) with no confirmation",
                confidence=0.7,
            )

    @staticmethod
    def _destructive_action(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                last = (dotted_name(node.func) or "").rsplit(".", 1)[-1]
                if last in DESTRUCTIVE_CALLS:
                    return f"{last}()"
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                match = DESTRUCTIVE_SQL.search(node.value) if len(node.value) < 400 else None
                if match:
                    return f"SQL {match.group(0)}"
        return None

    @staticmethod
    def _has_confirmation(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        params = [a.arg for a in [*func.args.args, *func.args.kwonlyargs]]
        if any(CONFIRM_NAME.search(p) for p in params):
            return True
        for dec in func.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if CONFIRM_NAME.search(dotted_name(target) or ""):
                return True
        for node in ast.walk(func):
            if isinstance(node, ast.Call) and CONFIRM_NAME.search(
                (dotted_name(node.func) or "").rsplit(".", 1)[-1]
            ):
                return True
        return False


@register
class UnboundedModelCall(Rule):
    meta = RuleMeta(
        id="LLM-12",
        title="Model call with no output token limit",
        module="llm",
        severity=Severity.LOW,
        explanation=(
            "Without a cap on output tokens, one long or looping answer can run up cost and "
            "latency, and an attacker can trigger it on purpose."
        ),
        fix="Set max_tokens (or max_completion_tokens / max_output_tokens), plus a request "
        "timeout and a per-user rate limit.",
        cwe=("CWE-400",),
        owasp=(OWASP_UNBOUNDED,),
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        if ctx.tree is None:
            return
        for node in ast.walk(ctx.tree):
            if not isinstance(node, ast.Call):
                continue
            name = dotted_name(node.func) or ""
            if not any(name.endswith(s) for s in OPENAI_STYLE):
                continue
            if any(kw.arg is None for kw in node.keywords):  # **kwargs may carry the cap
                continue
            if any(kw.arg in TOKEN_CAPS for kw in node.keywords):
                continue
            yield ctx.make_finding(
                self.meta,
                node.lineno,
                f"{name}() has no max_tokens limit",
                confidence=0.6,
            )

