#!/usr/bin/env python3
"""False-positive check on mature, human-written packages.

Downloads wheels from PyPI into a temporary folder, unpacks them, and scans the Python source
with slopguard's default rules. The code is only parsed, never imported or run. These packages
are well reviewed, so serious findings on them are mostly false positives; every one should be
read by a person, which is the point of this script.

    python benchmarks/realworld.py --write docs/real-world-check.md
    python benchmarks/realworld.py --packages requests flask --no-network
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter
from datetime import date
from pathlib import Path

from slopguard import __version__
from slopguard.config import Config
from slopguard.context import build_project
from slopguard.engine import discover, run_scan
from slopguard.rules import all_rules

DEFAULT_PACKAGES = [
    "requests", "flask", "click", "jinja2", "httpx", "rich", "werkzeug", "typer",
    "openai", "anthropic", "langchain-core", "litellm",
]
SEVERITIES = ["critical", "high", "medium", "low"]


def download(package: str, folder: Path) -> Path | None:
    done = subprocess.run(
        [sys.executable, "-m", "pip", "download", "--no-deps", "--only-binary", ":all:", "-q",
         "-d", str(folder), package],
        capture_output=True, text=True,
    )
    wheels = sorted(folder.glob("*.whl"), key=lambda p: p.stat().st_mtime)
    return wheels[-1] if done.returncode == 0 and wheels else None


def count_lines(root: Path) -> int:
    total = 0
    for path in root.rglob("*.py"):
        with path.open(errors="replace") as handle:
            total += sum(1 for _ in handle)
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--packages", nargs="+", default=DEFAULT_PACKAGES)
    parser.add_argument("--no-network", action="store_true", help="skip PyPI lookups (HAL rules)")
    parser.add_argument("--write", type=Path)
    args = parser.parse_args()

    rows, by_rule, total_lines, serious = [], Counter(), 0, 0
    rules = [r for r in all_rules() if r.meta.module != "drf"]
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="slopguard-real-") as tmp:
        for package in args.packages:
            work = Path(tmp) / package
            work.mkdir()
            wheel = download(package, work)
            if wheel is None:
                rows.append((package, "download failed", 0, Counter()))
                continue
            target = work / "src"
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(target)
            lines = count_lines(target)
            config = Config()
            project = build_project(target, config, network=not args.no_network)
            files = discover([target], target, config, {s for r in rules for s in r.file_types})
            result = run_scan(files, rules, project)
            if project.registry is not None:
                project.registry.save()
            counts = Counter(f.severity.label for f in result.findings)
            for f in result.findings:
                by_rule[(f.rule_id, f.severity.label)] += 1
            serious += counts["critical"] + counts["high"]
            total_lines += lines
            rows.append((wheel.stem, f"{len(files)} files", lines, counts))
    seconds = time.time() - started

    out = [
        "# Real-world check: mature packages as a false-positive control",
        "",
        f"Generated {date.today().isoformat()} by `benchmarks/realworld.py` with slopguard "
        f"{__version__} ({'offline' if args.no_network else 'with PyPI lookups'}). Do not edit by hand.",
        "",
        "These are well-reviewed, human-written packages, so a serious finding here is almost "
        "certainly a false positive. The code was parsed, never imported or run. They are not "
        "AI-generated, so this measures noise, not detection.",
        "",
        "| Package (wheel) | Scanned | Lines | Critical | High | Medium | Low |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, scanned, lines, counts in rows:
        out.append(f"| {name} | {scanned} | {lines:,} | " + " | ".join(str(counts[s]) for s in SEVERITIES) + " |")
    out += [
        "",
        f"**{total_lines:,} lines scanned in {seconds:.0f}s (includes downloads). "
        f"Critical + high findings: {serious}** "
        f"({serious / max(total_lines, 1) * 1000:.3f} per 1,000 lines; the project target is below 1).",
        "",
        "## Findings by rule",
        "",
        "| Rule | Severity | Count |",
        "| --- | --- | ---: |",
    ]
    for (rule, severity), count in sorted(by_rule.items()):
        out.append(f"| {rule} | {severity} | {count} |")
    out += [
        "",
        "Medium findings are hollow module-level functions and the occasional placeholder comment, "
        "which a person should judge. Low findings are hook methods with empty bodies, silent "
        "`except Exception: pass` blocks with no comment, and files with many TODOs.",
        "",
    ]
    text = "\n".join(out)
    if args.write:
        args.write.write_text(text)
        print(f"wrote {args.write}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
