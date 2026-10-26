"""Output formats: terminal, JSON, Markdown and SARIF 2.1.0."""

from __future__ import annotations

import json
from collections import Counter
from itertools import groupby

from rich.console import Console
from rich.text import Text

from slopguard import __version__
from slopguard.models import Finding, Rule, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.label for f in findings)
    return {s.label: counts.get(s.label, 0) for s in sorted(Severity, reverse=True)}


def render_terminal(
    findings: list[Finding], console: Console, files_scanned: int, errors: list[str]
) -> None:
    for path, group in groupby(findings, key=lambda f: f.path):
        console.print(Text(path, style="bold underline"))
        for finding in group:
            line = Text("  ")
            line.append(f"{finding.line}", style="dim")
            line.append("  ")
            line.append(f" {finding.severity.label.upper()} ", style=SEVERITY_STYLE[finding.severity])
            line.append(f"  {finding.rule_id}  ", style="bold")
            line.append(finding.message)
            console.print(line)
            if finding.excerpt:
                console.print(Text(f"        {finding.excerpt[:120]}", style="dim"))
            for step in finding.trace:
                console.print(Text(f"        ↳ {step}", style="dim"))
            console.print(Text(f"        fix: {finding.fix}", style="green"))
        console.print()
    for error in errors:
        console.print(Text(f"warning: {error}", style="yellow"))
    counts = summarize(findings)
    parts = [f"{n} {name}" for name, n in counts.items() if n]
    summary = ", ".join(parts) if parts else "no findings"
    console.print(Text(f"{files_scanned} files scanned: {summary}", style="bold"))


def to_json(findings: list[Finding], files_scanned: int, errors: list[str]) -> str:
    payload = {
        "version": 1,
        "tool": {"name": "slopguard", "version": __version__},
        "summary": {"files_scanned": files_scanned, "by_severity": summarize(findings)},
        "findings": [f.to_dict() for f in findings],
        "errors": errors,
    }
    return json.dumps(payload, indent=2)


def to_markdown(findings: list[Finding], files_scanned: int) -> str:
    counts = summarize(findings)
    lines = ["# slopguard report", "", f"{files_scanned} files scanned."]
    lines.append("")
    lines.append("| " + " | ".join(counts) + " |")
    lines.append("|" + "---|" * len(counts))
    lines.append("| " + " | ".join(str(n) for n in counts.values()) + " |")
    lines.append("")
    if not findings:
        lines.append("No findings.")
    for finding in findings:
        lines.append(
            f"- **{finding.severity.label}** `{finding.rule_id}` "
            f"`{finding.path}:{finding.line}`: {finding.message}"
        )
        lines.append(f"  - Fix: {finding.fix}")
        for step in finding.trace:
            lines.append(f"  - {step}")
    return "\n".join(lines) + "\n"


def to_sarif(findings: list[Finding], rules: list[Rule]) -> dict:
    driver_rules = []
    for rule in rules:
        meta = rule.meta
        tags = [*meta.cwe, *meta.owasp]
        driver_rules.append(
            {
                "id": meta.id,
                "name": meta.title.title().replace(" ", "").replace(",", ""),
                "shortDescription": {"text": meta.title},
                "fullDescription": {"text": meta.explanation},
                "help": {"text": meta.fix},
                "defaultConfiguration": {"level": SARIF_LEVEL[meta.severity]},
                "properties": {"tags": tags, "module": meta.module},
            }
        )
    index = {r["id"]: i for i, r in enumerate(driver_rules)}
    results = []
    for f in findings:
        result = {
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path},
                        "region": {"startLine": f.line, "endLine": max(f.line, f.end_line)},
                    }
                }
            ],
            "partialFingerprints": {"slopguard/v1": f.fingerprint()},
            "properties": {"confidence": round(f.confidence, 2), "trace": list(f.trace)},
        }
        if f.rule_id in index:
            result["ruleIndex"] = index[f.rule_id]
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "slopguard",
                        "version": __version__,
                        "rules": driver_rules,
                    }
                },
                "results": results,
            }
        ],
    }
