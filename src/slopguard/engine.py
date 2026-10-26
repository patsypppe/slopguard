"""File discovery, rule execution, suppressions and baselines."""

from __future__ import annotations

import ast
import fnmatch
import json
import os
import re
import subprocess
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from slopguard.config import DEFAULT_EXCLUDE_DIRS, Config
from slopguard.context import FileContext, ProjectContext
from slopguard.models import Finding, Rule

SUPPRESSION = re.compile(r"#\s*slopguard:\s*ignore(?:\[([^\]]*)\])?")
LOCK_FILES = frozenset(
    {"package-lock.json", "yarn.lock", "poetry.lock", "uv.lock", "Pipfile.lock", "pnpm-lock.yaml"}
)
MAX_BYTES = 1_000_000


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)


def find_root(paths: list[Path]) -> Path:
    """Project root: nearest ancestor with a project marker, else the first path's folder."""
    start = paths[0].resolve() if paths else Path.cwd()
    folder = start if start.is_dir() else start.parent
    for candidate in (folder, *folder.parents):
        if any((candidate / m).exists() for m in (".git", "slopguard.toml", "pyproject.toml")):
            return candidate
    return folder


def _wanted(name: str, suffixes: set[str]) -> bool:
    if name in LOCK_FILES:
        return False
    if name == ".env" or name.startswith(".env."):
        return ".env" in suffixes
    return Path(name).suffix in suffixes


def discover(paths: list[Path], root: Path, config: Config, suffixes: set[str]) -> list[Path]:
    found: list[Path] = []
    for entry in paths:
        entry = entry.resolve()
        if entry.is_file():
            found.append(entry)
            continue
        for current, dirs, files in os.walk(entry):
            dirs[:] = sorted(d for d in dirs if d not in DEFAULT_EXCLUDE_DIRS and not d.startswith("."))
            for name in sorted(files):
                if _wanted(name, suffixes):
                    found.append(Path(current) / name)
    unique = sorted(dict.fromkeys(found))
    return [p for p in unique if not _excluded(_rel(p, root), config.exclude)]


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _excluded(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) for p in patterns)


def changed_files(root: Path, ref: str | None, staged: bool) -> set[Path]:
    """Files touched in a diff against ``ref``, or staged for commit."""
    args = ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMR"]
    args += ["--cached"] if staged else [ref or "HEAD"]
    try:
        out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"could not read git diff: {exc}") from exc
    return {(root / line).resolve() for line in out.splitlines() if line.strip()}


def _parse(source: str) -> tuple[ast.Module | None, SyntaxError | None]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(source), None
    except SyntaxError as exc:
        return None, exc
    except ValueError as exc:
        return None, SyntaxError(str(exc))
    except (RecursionError, MemoryError):
        return None, None


def _suppressed(finding: Finding, lines: list[str]) -> bool:
    for number in (finding.line, finding.line - 1):
        if not 1 <= number <= len(lines):
            continue
        text = lines[number - 1]
        if number != finding.line and not text.lstrip().startswith("#"):
            continue
        match = SUPPRESSION.search(text)
        if not match:
            continue
        if match.group(1) is None:
            return True
        ids = {part.strip() for part in match.group(1).split(",")}
        if finding.rule_id in ids:
            return True
    return False


def run_scan(
    files: list[Path],
    rules: list[Rule],
    project: ProjectContext,
) -> ScanResult:
    result = ScanResult()
    for path in files:
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
            raw = path.read_bytes()
        except OSError as exc:
            result.errors.append(f"{path}: cannot read: {exc}")
            continue
        if b"\0" in raw[:8000]:
            continue
        source = raw.decode("utf-8", errors="replace")
        rel = _rel(path, project.root)
        tree, error = _parse(source) if path.suffix == ".py" else (None, None)
        ctx = FileContext(path, rel, source, project, tree, error)
        result.files_scanned += 1
        result.findings.extend(_check_file(ctx, rules, result.errors))
    result.findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
    return result


def _check_file(ctx: FileContext, rules: list[Rule], errors: list[str]) -> list[Finding]:
    config = ctx.project.config
    found: list[Finding] = []
    for rule in rules:
        if not _applies(rule, ctx.path):
            continue
        if _excluded(ctx.rel, list(config.rule_options(rule.meta.id).get("ignore", []))):
            continue
        try:
            produced = list(rule.check(ctx))
        except Exception as exc:  # noqa: BLE001  a crashing rule must not stop the scan
            errors.append(f"{rule.meta.id} crashed on {ctx.rel}: {exc!r}")
            continue
        found.extend(f for f in produced if not _suppressed(f, ctx.lines))
    return found


def scan_text(rel: str, source: str, rules: list[Rule], project: ProjectContext) -> list[Finding]:
    """Scan source held in memory as if it lived at ``rel`` inside the project."""
    path = project.root / rel
    tree, error = _parse(source) if path.suffix == ".py" else (None, None)
    ctx = FileContext(path, rel, source, project, tree, error)
    findings = _check_file(ctx, rules, [])
    findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
    return findings


def _applies(rule: Rule, path: Path) -> bool:
    if path.name == ".env" or path.name.startswith(".env."):
        return ".env" in rule.file_types
    return path.suffix in rule.file_types


def load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"cannot read baseline {path}: {exc}") from exc
    return set(data.get("fingerprints", []))


def write_baseline(path: Path, findings: list[Finding]) -> None:
    payload = {"version": 1, "fingerprints": sorted({f.fingerprint() for f in findings})}
    path.write_text(json.dumps(payload, indent=1) + "\n")
