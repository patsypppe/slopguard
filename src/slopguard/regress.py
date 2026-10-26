"""Regression checks: did a change delete, skip or weaken tests, or break passing ones?"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from slopguard.drift import is_test_path
from slopguard.models import Finding, Severity, finding_from_meta
from slopguard.rules import get_rule

TEST_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(test\w*)\s*\(")
ASSERT_LINE = re.compile(r"^\s*assert\b|\bself\.assert\w+\(|\bpytest\.raises\(|\bassertRaises\(")
SKIP_MARK = re.compile(
    r"pytest\.mark\.(?:skip|xfail)\b|pytest\.skip\(|pytest\.xfail\(|@unittest\.skip|@skip\b"
)
MAX_REPORTED = 20


class RegressionError(Exception):
    """The comparison could not be made (not a git repo, bad ref, tests would not run)."""


def _git(root: Path, *args: str) -> str:
    try:
        done = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise RegressionError(f"git {' '.join(args[:2])} failed: {detail.strip()[:200]}") from exc
    return done.stdout


@dataclass
class _FileDiff:
    path: str
    deleted: bool = False
    removed_tests: list[str] = field(default_factory=list)
    added_tests: list[str] = field(default_factory=list)
    removed_asserts: int = 0
    added_asserts: int = 0
    added_skips: list[str] = field(default_factory=list)


def _parse_diff(diff: str) -> list[_FileDiff]:
    files: list[_FileDiff] = []
    current: _FileDiff | None = None
    old_path = ""
    in_header = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            in_header, current, old_path = True, None, ""
        elif in_header and line.startswith("--- "):
            old_path = line[4:].strip().removeprefix("a/")
        elif in_header and line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                current = _FileDiff(old_path, deleted=True)
            else:
                current = _FileDiff(target.removeprefix("b/"))
            files.append(current)
        elif line.startswith("@@"):
            in_header = False
        elif current is not None and not in_header and line[:1] in ("+", "-"):
            _count_line(current, line[0], line[1:])
    return files


def _count_line(item: _FileDiff, sign: str, body: str) -> None:
    if sign == "-":
        if (m := TEST_DEF.match(body)):
            item.removed_tests.append(m.group(1))
        if ASSERT_LINE.search(body):
            item.removed_asserts += 1
        return
    if (m := TEST_DEF.match(body)):
        item.added_tests.append(m.group(1))
    if ASSERT_LINE.search(body):
        item.added_asserts += 1
    if SKIP_MARK.search(body):
        item.added_skips.append(body.strip())


def weakened_test_findings(root: Path, base: str) -> list[Finding]:
    """REG-02: compare the working tree with ``base`` for deleted, skipped or weakened tests."""
    meta = get_rule("REG-02").meta  # type: ignore[union-attr]
    diff = _git(root, "diff", "--no-color", "--unified=0", base, "--", "*.py")
    findings: list[Finding] = []
    for item in _parse_diff(diff):
        if not is_test_path(item.path):
            continue
        gone = [t for t in item.removed_tests if t not in item.added_tests]
        if item.deleted:
            findings.append(finding_from_meta(
                meta, item.path, 1, f"test file deleted ({len(item.removed_tests)} test(s))",
                confidence=0.9))
        elif gone:
            names = ", ".join(gone[:5]) + ("…" if len(gone) > 5 else "")
            findings.append(finding_from_meta(
                meta, item.path, 1, f"{len(gone)} test(s) removed: {names}", confidence=0.9))
        for skip in item.added_skips:
            findings.append(finding_from_meta(
                meta, item.path, 1, f"skip or xfail added: {skip[:80]}", confidence=0.85,
                excerpt=skip))
        lost = item.removed_asserts - item.added_asserts
        if lost > 0 and not item.deleted and not gone:
            findings.append(finding_from_meta(
                meta, item.path, 1, f"{lost} fewer assertion(s) than before", confidence=0.6,
                severity=Severity.MEDIUM))
    return findings


# -- running the suite before and after ------------------------------------------------------


def run_suite(directory: Path, timeout: int = 300) -> dict[str, str]:
    """Run pytest in ``directory`` and return ``{test id: passed | failed | skipped}``."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.xml"
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [str(directory / "src"), str(directory), env.get("PYTHONPATH", "")]
        )
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        cmd = [sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider",
               f"--junitxml={report}"]
        try:
            subprocess.run(cmd, cwd=directory, env=env, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise RegressionError(f"test run in {directory} timed out after {timeout}s") from exc
        except OSError as exc:
            raise RegressionError(f"could not run pytest: {exc}") from exc
        if not report.exists():
            raise RegressionError(f"pytest produced no report in {directory}")
        return _read_junit(report)


def _read_junit(report: Path) -> dict[str, str]:
    results: dict[str, str] = {}
    for case in ET.parse(report).getroot().iter("testcase"):
        test_id = f"{case.get('classname', '')}::{case.get('name', '')}"
        if case.find("failure") is not None or case.find("error") is not None:
            results[test_id] = "failed"
        elif case.find("skipped") is not None:
            results[test_id] = "skipped"
        else:
            results[test_id] = "passed"
    return results


def regressed_test_findings(root: Path, base: str, timeout: int = 300) -> list[Finding]:
    """REG-01: tests that passed at ``base`` and now fail or have vanished."""
    meta = get_rule("REG-01").meta  # type: ignore[union-attr]
    _git(root, "rev-parse", "--verify", f"{base}^{{commit}}")
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "base"
        _git(root, "worktree", "add", "--detach", str(tree), base)
        try:
            before = run_suite(tree, timeout)
        finally:
            subprocess.run(["git", "-C", str(root), "worktree", "remove", "--force", str(tree)],
                           capture_output=True)
    after = run_suite(root, timeout)
    findings = []
    for test_id, outcome in sorted(before.items()):
        if outcome != "passed":
            continue
        now = after.get(test_id)
        if now == "passed":
            continue
        module, _, name = test_id.partition("::")
        path = module.replace(".", "/") + ".py"
        state = "now fails" if now == "failed" else "is no longer reported" if now is None else f"is now {now}"
        findings.append(finding_from_meta(
            meta, path, 1, f"`{name}` passed at {base} and {state}", confidence=0.9))
    return findings[:MAX_REPORTED]


def regress(root: Path, base: str, run_tests: bool, timeout: int = 300) -> list[Finding]:
    findings = weakened_test_findings(root, base)
    if run_tests:
        findings += regressed_test_findings(root, base, timeout)
    return findings
