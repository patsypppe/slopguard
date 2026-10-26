"""Turn requirements into pytest tests, and test results back into verdicts."""

from __future__ import annotations

import ast
import re

from slopguard.llm import LLMError, Provider, extract_code_block
from slopguard.sandbox import TestRun
from slopguard.spec import Evidence, Requirement, Verdict

MAX_CONTEXT_CHARS = 9000
FORBIDDEN_IMPORTS = frozenset({"socket", "subprocess", "requests", "urllib", "httpx", "shutil"})

SYSTEM = (
    "You write pytest tests that check requirements against existing Python code.\n"
    "Rules:\n"
    "- Import from the modules shown. The project root and `src/` are on sys.path, so import "
    "a file `src/pkg/mod.py` as `pkg.mod`.\n"
    "- Name each test `test_<id>_<short_slug>` using the requirement id in lowercase, "
    "for example `test_r2_rounds_totals`.\n"
    "- No network, no subprocess, no writes outside the `tmp_path` fixture. Do not modify the "
    "code under test. Use only its public behaviour.\n"
    "- If a requirement cannot be tested without guessing an interface, write no test for it.\n"
    "Return exactly one ```python block and nothing else."
)


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    returns = f" -> {ast.unparse(node.returns)}" if node.returns else ""
    return f"{prefix} {node.name}({ast.unparse(node.args)}){returns}"


def interface_summary(files: list[tuple[str, str]]) -> str:
    """Public functions and classes per file: signatures and first docstring line only."""
    lines: list[str] = []
    for rel, source in files:
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            continue
        entries = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                entries.append(_signature(node) + _doc(node))
            elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                entries.append(f"class {node.name}" + _doc(node))
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and not item.name.startswith("_"):
                        entries.append("    " + _signature(item) + _doc(item))
        if entries:
            lines.append(f"# {rel}")
            lines.extend(entries)
    return "\n".join(lines)


def _doc(node: ast.AST) -> str:
    doc = ast.get_docstring(node)  # type: ignore[arg-type]
    return f"  # {doc.splitlines()[0]}" if doc else ""


def validate_test_code(code: str) -> None:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise LLMError(f"generated tests do not parse: {exc.msg}") from exc
    if not any(isinstance(n, ast.FunctionDef) and n.name.startswith("test") for n in ast.walk(tree)):
        raise LLMError("generated file contains no test functions")
    for node in ast.walk(tree):
        roots = []
        if isinstance(node, ast.Import):
            roots = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots = [node.module.split(".")[0]]
        banned = FORBIDDEN_IMPORTS.intersection(roots)
        if banned:
            raise LLMError(f"generated tests import {sorted(banned)[0]}, which is not allowed")


def generate_tests(
    requirements: list[Requirement], files: list[tuple[str, str]], provider: Provider
) -> str:
    listing = "\n".join(f"{r.id}: {r.text}" for r in requirements)
    context = interface_summary(files)[:MAX_CONTEXT_CHARS]
    prompt = f"Requirements:\n{listing}\n\nCode interfaces:\n{context}"
    answer = provider.complete(SYSTEM, prompt, 3000)
    code = extract_code_block(answer)
    if code is None:
        raise LLMError("the model's answer contained no Python code block")
    validate_test_code(code)
    return code


def apply_test_results(verdicts: list[Verdict], run: TestRun) -> list[Verdict]:
    """Fold generated-test outcomes into the spec verdicts."""
    if not run.results:
        return verdicts
    updated = []
    for verdict in verdicts:
        rid = verdict.requirement.id.lower()
        pattern = re.compile(rf"::test_{rid}(_|$)")
        mine = {k: v for k, v in run.results.items() if pattern.search(k)}
        if not mine:
            updated.append(verdict)
            continue
        failed = sorted(k.split("::")[-1] for k, v in mine.items() if v == "failed")
        evidence = verdict.evidence + [Evidence("", 0, f"generated test {k.split('::')[-1]}: {v}")
                                       for k, v in sorted(mine.items())]
        if failed:
            status = "partial" if verdict.status == "met" else verdict.status
            reason = f"generated test failed: {', '.join(failed)} (the test itself may be wrong)"
            updated.append(Verdict(verdict.requirement, status, reason, 0.55, "tests", evidence))
        else:
            reason = f"{len(mine)} generated test(s) pass in a {run.backend} sandbox"
            updated.append(Verdict(verdict.requirement, "met", reason, 0.85, "tests", evidence))
    return updated

