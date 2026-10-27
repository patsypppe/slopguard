#!/usr/bin/env python3
"""Compare slopguard with other scanners on the labelled corpus.

Every other tool is run as an external program and only its JSON report is read. Nothing from
those tools is imported, vendored or copied.

    python benchmarks/compare.py \\
        --bandit /path/to/bandit \\
        --semgrep /path/to/semgrep --semgrep-set "Semgrep (python rules)=rules/python,rules/generic/secrets" \\
        --semgrep-set "Semgrep (ai rules)=rules/ai" \\
        --vibechck "node /path/to/vibechck/dist/cli/index.js" \\
        --write docs/benchmarks.md

A tool counts as *flagging* a file when it reports at least one finding at or above the chosen
severity (low, medium or high, mapped from each tool's own scale). Rule taxonomies differ too
much for per-rule scoring, so this answers a coarser question: does the tool notice the file at
all, and does it stay quiet on the safe files?
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from slopguard import __version__
from slopguard.bench import parse_expected
from slopguard.config import Config
from slopguard.context import build_project
from slopguard.engine import discover, run_scan
from slopguard.rules import all_rules

LEVELS = {"low": 1, "medium": 2, "high": 3}
CATEGORIES = {
    "LLM": "LLM-app security",
    "SEC": "Hardcoded secrets",
    "INC": "Incomplete code",
    "HAL": "Hallucinated packages",
}
TIMEOUT = 600


@dataclass
class ToolRun:
    name: str
    version: str
    seconds: float
    findings: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # file -> [(rule, sev)]
    note: str = ""

    def flags(self, rel: str, minimum: str) -> bool:
        return bool(self.rules_at(rel, minimum))

    def rules_at(self, rel: str, minimum: str) -> list[str]:
        floor = LEVELS[minimum]
        found = [rule for rule, sev in self.findings.get(rel, []) if LEVELS[sev] >= floor]
        return list(dict.fromkeys(found))


def run(cmd: list[str], cwd: Path | None = None) -> tuple[str, float]:
    started = time.time()
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, cwd=cwd)
    return done.stdout, time.time() - started  # these tools exit non-zero when they find things


def rel_path(raw: str, corpus: Path) -> str:
    path = Path(raw)
    try:
        return (path if path.is_absolute() else Path.cwd() / path).resolve().relative_to(corpus).as_posix()
    except ValueError:
        return raw


def run_slopguard(corpus: Path) -> ToolRun:
    started = time.time()
    config = Config()
    project = build_project(corpus, config, network=False)
    rules = [r for r in all_rules() if r.meta.module != "drf"]
    files = discover([corpus], corpus, config, {s for r in rules for s in r.file_types})
    result = run_scan(files, rules, project)
    sev = {"info": "low", "low": "low", "medium": "medium", "high": "high", "critical": "high"}
    findings: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for f in result.findings:
        findings[f.path].append((f.rule_id, sev[f.severity.label]))
    return ToolRun("slopguard", __version__, time.time() - started, dict(findings))


def run_bandit(exe: str, corpus: Path) -> ToolRun:
    version = run([exe, "--version"])[0].splitlines()[0].strip()
    out, secs = run([exe, "-r", str(corpus), "-f", "json", "-q"])
    data = json.loads(out)
    findings: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for item in data.get("results", []):
        findings[rel_path(item["filename"], corpus)].append(
            (item["test_id"], item["issue_severity"].lower())
        )
    note = f"{len(data.get('errors', []))} file(s) it could not parse"
    return ToolRun("Bandit", version.replace("bandit ", ""), secs, dict(findings), note)


def run_semgrep(exe: str, label: str, configs: list[str], corpus: Path, rules_rev: str) -> ToolRun:
    version = run([exe, "--version"])[0].strip().splitlines()[-1]
    cmd = [exe, "scan", "--metrics=off", "--json", "--quiet", "--disable-version-check", "--no-git-ignore"]
    for config in configs:
        cmd += ["--config", config]
    out, secs = run(cmd + [str(corpus)])
    data = json.loads(out)
    sev = {"INFO": "low", "WARNING": "medium", "ERROR": "high"}
    findings: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for item in data.get("results", []):
        findings[rel_path(item["path"], corpus)].append(
            (item["check_id"].split(".")[-1], sev.get(item["extra"]["severity"], "low"))
        )
    return ToolRun(label, version, secs, dict(findings), f"public semgrep-rules @ {rules_rev}")


def run_vibechck(command: str, corpus: Path) -> ToolRun:
    out, secs = run([*shlex.split(command), "--json", str(corpus)])
    data = json.loads(out[out.index("{") :])
    sev = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "high"}
    findings: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for alert in data.get("alerts", []):
        if alert.get("file"):
            findings[rel_path(alert["file"], corpus)].append(
                (alert.get("rule", "?"), sev.get(alert["severity"], "low"))
            )
    return ToolRun("vibechck", "0.2.9 (npm)", secs, dict(findings), "AGPL-3.0; run as a black box")


def label_files(corpus: Path) -> tuple[dict[str, set[str]], list[str]]:
    vulnerable: dict[str, set[str]] = {}
    safe: list[str] = []
    for path in sorted(corpus.rglob("*.py")):
        expected = parse_expected(path.read_text(errors="replace"))
        rel = path.relative_to(corpus).as_posix()
        if expected is None:
            continue
        if expected:
            vulnerable[rel] = expected
        else:
            safe.append(rel)
    return vulnerable, safe


def category(expected: set[str]) -> str:
    return CATEGORIES[sorted(expected)[0].split("-")[0]]


def summarise(tools: list[ToolRun], vulnerable: dict[str, set[str]], safe: list[str], minimum: str):
    by_cat: dict[str, list[str]] = defaultdict(list)
    for rel, expected in vulnerable.items():
        by_cat[category(expected)].append(rel)
    rows = []
    for tool in tools:
        row = {"tool": tool.name}
        for cat in CATEGORIES.values():
            files = by_cat.get(cat, [])
            row[cat] = f"{sum(tool.flags(f, minimum) for f in files)}/{len(files)}"
        row["safe"] = f"{sum(tool.flags(f, minimum) for f in safe)}/{len(safe)}"
        rows.append(row)
    return rows


def markdown(tools, vulnerable, safe, rules_rev: str) -> str:
    lines = [
        "# Benchmark: slopguard against other scanners",
        "",
        f"Generated {date.today().isoformat()} by `benchmarks/compare.py`. Do not edit by hand.",
        "",
        "## What this measures, and what it does not",
        "",
        f"- **Corpus:** {len(vulnerable)} files with known problems and {len(safe)} safe files in "
        "`benchmarks/corpus/`. The maintainers wrote it, and it is built around the problems "
        "slopguard targets. It is a *coverage* check on LLM-era problems, **not** a general quality "
        "ranking: Bandit and Semgrep are broader tools that were not built for these cases.",
        "- **Method:** each tool runs as an external program and only its JSON report is read. "
        "A tool *flags* a file if it reports at least one finding at or above the severity shown "
        "(its own scale mapped to low / medium / high). Per-rule scoring is not possible because "
        "the rule sets differ.",
        "- **Semgrep** ran with the public community rules of `semgrep-rules` at "
        f"`{rules_rev}`, not its commercial packs. The `ai/` folder holds SDK best-practice lints "
        "(missing user id, missing system prompt, no error handling), so it is reported as its own "
        "row instead of being mixed with the security rules. The rules are used locally for this "
        "comparison only and are not redistributed.",
        "- **vibechck** is AGPL-3.0. It is run as a black box and none of its code is used by slopguard.",
        "- slopguard's own rules were tuned against this corpus, so its numbers here are optimistic. "
        "The two files labelled `gap_*` are known misses and count against it.",
        "",
    ]
    for minimum, title in (("low", "Any severity"), ("medium", "Medium severity or higher")):
        rows = summarise(tools, vulnerable, safe, minimum)
        cats = list(CATEGORIES.values())
        lines += [f"## Files flagged: {title}", "",
                  "| Tool | " + " | ".join(cats) + " | False alarms on safe files |",
                  "| --- |" + " --- |" * (len(cats) + 1)]
        for row in rows:
            lines.append(f"| {row['tool']} | " + " | ".join(row[c] for c in cats) + f" | {row['safe']} |")
        lines.append("")
    lines += ["## Tools and timing", "", "| Tool | Version | Time on corpus | Note |", "| --- | --- | --- | --- |"]
    for tool in tools:
        lines.append(f"| {tool.name} | {tool.version} | {tool.seconds:.1f}s | {tool.note} |")
    lines += ["", "## Per file: rule IDs reported at medium severity or higher", "",
              "A tool can flag a file for an unrelated reason, so read the rule IDs, not only the marks.", "",
              "<details><summary>Show every file</summary>", "",
              "| File | Expected | " + " | ".join(t.name for t in tools) + " |",
              "| --- | --- |" + " --- |" * len(tools)]
    for rel in [*vulnerable, *safe]:
        expected = ", ".join(sorted(vulnerable.get(rel, set()))) or "none"
        marks = " | ".join(_cell(t.rules_at(rel, "medium")) for t in tools)
        lines.append(f"| `{rel}` | {expected} | {marks} |")
    lines += ["", "</details>", ""]
    return "\n".join(lines)


def _cell(rules: list[str]) -> str:
    if not rules:
        return "-"
    shown = ", ".join(f"`{r}`" for r in rules[:3])
    return shown + (f" +{len(rules) - 3}" if len(rules) > 3 else "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=Path("benchmarks/corpus"))
    parser.add_argument("--bandit")
    parser.add_argument("--semgrep")
    parser.add_argument("--semgrep-set", action="append", default=[],
                        help='"Label=path1,path2": one Semgrep run per set of rule folders')
    parser.add_argument("--semgrep-rules-rev", default="unknown")
    parser.add_argument("--vibechck", help='command that runs vibechck, e.g. "node path/to/cli/index.js"')
    parser.add_argument("--write", type=Path, help="write the Markdown report here")
    args = parser.parse_args()

    corpus = args.corpus.resolve()
    vulnerable, safe = label_files(corpus)
    tools = [run_slopguard(corpus)]
    if args.bandit:
        tools.append(run_bandit(args.bandit, corpus))
    for spec in args.semgrep_set if args.semgrep else []:
        label, _, folders = spec.partition("=")
        tools.append(run_semgrep(args.semgrep, label, folders.split(","), corpus, args.semgrep_rules_rev))
    if args.vibechck:
        tools.append(run_vibechck(args.vibechck, corpus))
    report = markdown(tools, vulnerable, safe, args.semgrep_rules_rev)
    if args.write:
        args.write.write_text(report)
        print(f"wrote {args.write}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
