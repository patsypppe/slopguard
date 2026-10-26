"""Verify-and-repair loop: scan, ask a model for a fix, re-scan, keep only real improvement.

The model proposes a whole corrected file. slopguard accepts it only if the file still
parses, does not shrink suspiciously, has fewer serious findings than before, and introduces
no new serious finding. Nothing touches disk unless the caller applies the result.
"""

from __future__ import annotations

import ast
import difflib
from dataclasses import dataclass, field
from pathlib import Path

from slopguard.context import ProjectContext
from slopguard.engine import scan_text
from slopguard.llm import LLMError, Provider, extract_code_block
from slopguard.models import Finding, Rule, Severity

SYSTEM = (
    "You repair security and completeness problems in one Python file. Return the complete "
    "corrected file in a single ```python block and nothing else. Keep behaviour, public "
    "names and unrelated code unchanged. Never execute model output; never invent packages; "
    "do not leave placeholders, stubs or TODOs. If a finding cannot be fixed safely, leave that "
    "code as it is."
)
MAX_FILE_CHARS = 30000
MIN_SIZE_RATIO = 0.4


@dataclass
class Attempt:
    path: str
    accepted: bool
    note: str
    before: int
    after: int | None = None


@dataclass
class RepairRound:
    number: int
    attempts: list[Attempt] = field(default_factory=list)

    @property
    def accepted(self) -> int:
        return sum(a.accepted for a in self.attempts)


@dataclass
class RepairResult:
    original: dict[str, str]
    current: dict[str, str]
    rounds: list[RepairRound]
    remaining: list[Finding]
    stopped: str

    def changed_files(self) -> list[str]:
        return [p for p in self.current if self.current[p] != self.original[p]]

    def diff(self) -> str:
        chunks = []
        for rel in self.changed_files():
            chunks.extend(
                difflib.unified_diff(
                    self.original[rel].splitlines(keepends=True),
                    self.current[rel].splitlines(keepends=True),
                    f"a/{rel}", f"b/{rel}",
                )
            )
        return "".join(chunks)


def _serious(findings: list[Finding], minimum: Severity) -> list[Finding]:
    return [f for f in findings if f.severity >= minimum]


def _describe(findings: list[Finding]) -> str:
    lines = []
    for f in findings:
        lines.append(f"- line {f.line}: {f.rule_id} {f.message}. Fix: {f.fix}")
        lines.extend(f"    {step}" for step in f.trace)
    return "\n".join(lines)


def _prompt(rel: str, source: str, findings: list[Finding]) -> str:
    return f"File: {rel}\n\nFindings to fix:\n{_describe(findings)}\n\n```python\n{source}\n```"


def judge_candidate(
    rel: str,
    old: str,
    new: str,
    before: list[Finding],
    rules: list[Rule],
    project: ProjectContext,
    minimum: Severity,
) -> tuple[bool, str, list[Finding]]:
    """Decide whether a proposed file is a safe improvement."""
    if new.strip() == old.strip():
        return False, "model returned the file unchanged", before
    try:
        ast.parse(new)
    except (SyntaxError, ValueError) as exc:
        return False, f"proposal does not parse ({getattr(exc, 'msg', exc)})", before
    if len(new) < len(old) * MIN_SIZE_RATIO:
        return False, "proposal is much shorter than the original; looks truncated", before
    after = scan_text(rel, new, rules, project)
    old_serious, new_serious = _serious(before, minimum), _serious(after, minimum)
    known = {f.fingerprint() for f in before}
    fresh = [f for f in new_serious if f.fingerprint() not in known]
    if fresh:
        return False, f"proposal introduces {fresh[0].rule_id} at line {fresh[0].line}", before
    if len(new_serious) >= len(old_serious):
        return False, "proposal does not reduce the serious findings", before
    return True, f"serious findings {len(old_serious)} -> {len(new_serious)}", after


def repair(
    sources: dict[str, str],
    rules: list[Rule],
    project: ProjectContext,
    provider: Provider,
    *,
    max_rounds: int = 3,
    minimum: Severity = Severity.HIGH,
    max_files: int = 5,
) -> RepairResult:
    original = dict(sources)
    current = dict(sources)
    rounds: list[RepairRound] = []
    stopped = "round limit reached"
    findings = {rel: scan_text(rel, src, rules, project) for rel, src in current.items()}
    for number in range(1, max_rounds + 1):
        targets = [rel for rel, found in findings.items() if _serious(found, minimum)]
        if not targets:
            stopped = "no serious findings left"
            break
        round_ = RepairRound(number)
        for rel in targets[:max_files]:
            before = findings[rel]
            attempt = _attempt(rel, current[rel], before, rules, project, provider, minimum)
            round_.attempts.append(attempt[0])
            if attempt[0].accepted:
                current[rel] = attempt[1]
                findings[rel] = attempt[2]
        rounds.append(round_)
        if round_.accepted == 0:
            stopped = "no progress in the last round"
            break
    else:
        if not any(_serious(f, minimum) for f in findings.values()):
            stopped = "no serious findings left"
    remaining = [f for found in findings.values() for f in found]
    return RepairResult(original, current, rounds, remaining, stopped)


def _attempt(rel, source, before, rules, project, provider, minimum):
    serious = _serious(before, minimum)
    if len(source) > MAX_FILE_CHARS:
        return Attempt(rel, False, "file too large to send", len(serious)), source, before
    try:
        answer = provider.complete(SYSTEM, _prompt(rel, source, serious), 8000)
    except LLMError as exc:
        return Attempt(rel, False, f"model call failed: {exc}", len(serious)), source, before
    code = extract_code_block(answer)
    if code is None:
        return Attempt(rel, False, "answer had no Python code block", len(serious)), source, before
    ok, note, after = judge_candidate(rel, source, code, before, rules, project, minimum)
    attempt = Attempt(rel, ok, note, len(serious), len(_serious(after, minimum)) if ok else None)
    return attempt, (code if ok else source), after


def read_sources(paths: list[Path], root: Path) -> dict[str, str]:
    sources = {}
    for path in paths:
        rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
        sources[rel] = path.read_text(errors="replace")
    return sources
