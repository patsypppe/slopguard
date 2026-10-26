"""Command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from slopguard import __version__
from slopguard.config import MODULES, STARTER_CONFIG, Config, ConfigError
from slopguard.context import build_project
from slopguard.engine import (
    changed_files,
    discover,
    find_root,
    load_baseline,
    run_scan,
    write_baseline,
)
from slopguard.models import Rule, Severity
from slopguard.reporters import render_terminal, to_json, to_markdown, to_sarif
from slopguard.rules import all_rules, get_rule

app = typer.Typer(
    name="slopguard",
    help="Verify AI-generated code: LLM-app security, hallucinated packages, stubs and drift.",
    no_args_is_help=True,
    add_completion=False,
)

FORMATS = ("terminal", "json", "markdown", "sarif")
EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_INTERNAL = 0, 1, 2, 3


def _fail(message: str, code: int = EXIT_USAGE) -> typer.Exit:
    Console(stderr=True).print(f"error: {message}", markup=False)
    return typer.Exit(code)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"slopguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(  # slopguard: ignore[INC-02] Typer callback, body is intentionally empty
    version: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Show the version and exit."
    ),
) -> None:
    """slopguard command-line interface."""


def _select_rules(config: Config, modules: list[str], rule_ids: list[str]) -> list[Rule]:
    for name in modules:
        if name not in MODULES:
            raise _fail(f"unknown module {name!r}; expected one of: {', '.join(MODULES)}")
    chosen = []
    wanted = {r.upper() for r in rule_ids}
    for rule in all_rules():
        meta = rule.meta
        if wanted and meta.id not in wanted:
            continue
        if modules:
            if meta.module not in modules:
                continue
        elif not config.modules.get(meta.module, True):
            continue
        if config.rule_enabled(meta.id):
            chosen.append(rule)
    unknown = wanted - {r.meta.id for r in all_rules()}
    if unknown:
        raise _fail(f"unknown rule(s): {', '.join(sorted(unknown))}")
    return chosen


@app.command()
def scan(
    paths: list[Path] | None = typer.Argument(None, help="Files or folders to scan."),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal, json, markdown or sarif."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write the report here."),
    severity: str | None = typer.Option(None, "--severity", help="Minimum severity to report."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit 1 at this severity or above, or 'none'."),
    module: list[str] | None = typer.Option(None, "--module", "-m", help="Run only these modules."),
    rule: list[str] | None = typer.Option(None, "--rule", "-r", help="Run only these rule IDs."),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="Glob to skip (repeatable)."),
    diff: str | None = typer.Option(None, "--diff", help="Scan only files changed against this git ref."),
    staged: bool = typer.Option(False, "--staged", help="Scan only files staged for commit."),
    baseline: Path | None = typer.Option(None, "--baseline", help="Ignore findings recorded in this file."),
    write_baseline_to: Path | None = typer.Option(None, "--write-baseline", help="Record current findings as a baseline."),
    no_network: bool = typer.Option(False, "--no-network", help="Skip PyPI lookups."),
    config_path: Path | None = typer.Option(None, "--config", help="Path to a slopguard.toml."),
) -> None:
    """Scan code for LLM-app vulnerabilities, hallucinated imports and unfinished code."""
    try:
        exit_code = _scan(
            paths or [Path(".")], fmt, output, severity, fail_on, module or [], rule or [],
            exclude or [], diff, staged, baseline, write_baseline_to, no_network, config_path,
        )
    except typer.Exit:
        raise
    except Exception as exc:  # last resort so users get exit code 3, not a traceback
        raise _fail(f"internal error: {exc!r}", EXIT_INTERNAL) from exc
    raise typer.Exit(exit_code)


def _scan(paths, fmt, output, severity, fail_on, modules, rule_ids, exclude, diff, staged,
          baseline, write_baseline_to, no_network, config_path) -> int:
    if fmt not in FORMATS:
        raise _fail(f"unknown format {fmt!r}; expected one of: {', '.join(FORMATS)}")
    missing = [p for p in paths if not p.exists()]
    if missing:
        raise _fail(f"path not found: {missing[0]}")
    try:
        minimum = Severity.parse(severity) if severity else None
        root = find_root(paths)
        config = Config.load(root, config_path)
        config.exclude.extend(exclude)
        if fail_on:
            config.fail_on = fail_on.lower()
        threshold = config.fail_threshold()
    except (ConfigError, ValueError) as exc:
        raise _fail(str(exc)) from exc

    rules = _select_rules(config, modules, rule_ids)
    suffixes = {suffix for r in rules for suffix in r.file_types}
    files = discover(paths, root, config, suffixes)
    if diff or staged:
        try:
            changed = changed_files(root, diff, staged)
        except RuntimeError as exc:
            raise _fail(str(exc)) from exc
        files = [f for f in files if f in changed]

    project = build_project(root, config, network=not no_network)
    result = run_scan(files, rules, project)
    if project.registry is not None:
        project.registry.save()

    findings = result.findings
    if write_baseline_to:
        write_baseline(write_baseline_to, findings)
        Console(stderr=True).print(f"baseline written to {write_baseline_to}", markup=False)
    if baseline:
        try:
            known = load_baseline(baseline)
        except RuntimeError as exc:
            raise _fail(str(exc)) from exc
        findings = [f for f in findings if f.fingerprint() not in known]
    if minimum is not None:
        findings = [f for f in findings if f.severity >= minimum]

    _emit(fmt, output, findings, rules, result.files_scanned, result.errors)
    if threshold is not None and any(f.severity >= threshold for f in findings):
        return EXIT_FINDINGS
    return EXIT_OK


def _emit(fmt, output, findings, rules, files_scanned, errors) -> None:
    if fmt == "terminal" and output is None:
        render_terminal(findings, Console(), files_scanned, errors)
        return
    if fmt == "json":
        text = to_json(findings, files_scanned, errors)
    elif fmt == "markdown":
        text = to_markdown(findings, files_scanned)
    elif fmt == "sarif":
        text = json.dumps(to_sarif(findings, rules), indent=2)
    else:
        with Path(output).open("w") as handle:
            console = Console(file=handle, width=100, color_system=None)
            render_terminal(findings, console, files_scanned, errors)
        return
    if output:
        Path(output).write_text(text if text.endswith("\n") else text + "\n")
    else:
        typer.echo(text)


@app.command("rules")
def list_rules() -> None:
    """List every rule with its severity and module."""
    table = Table(show_header=True, header_style="bold")
    for column in ("ID", "Severity", "Module", "Status", "Title"):
        table.add_column(column)
    for rule in all_rules():
        meta = rule.meta
        table.add_row(meta.id, meta.severity.label, meta.module, meta.status, meta.title)
    Console().print(table)


@app.command()
def explain(rule_id: str = typer.Argument(..., help="Rule ID, for example LLM-02.")) -> None:
    """Explain a rule: why it matters and how to fix it."""
    rule = get_rule(rule_id)
    if rule is None:
        raise _fail(f"unknown rule {rule_id!r}; run `slopguard rules` to list them")
    meta = rule.meta
    console = Console()
    console.print(f"{meta.id}  {meta.title}", style="bold", markup=False)
    console.print(f"severity: {meta.severity.label}   module: {meta.module}   status: {meta.status}", markup=False)
    if meta.cwe or meta.owasp:
        console.print("references: " + ", ".join([*meta.cwe, *meta.owasp]), markup=False)
    console.print(f"\nWhy it matters\n  {meta.explanation}", markup=False)
    console.print(f"\nHow to fix\n  {meta.fix}", markup=False)


@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite an existing slopguard.toml."),
) -> None:
    """Write a starter slopguard.toml in the current folder."""
    target = Path("slopguard.toml")
    if target.exists() and not force:
        raise _fail(f"{target} already exists; use --force to overwrite")
    target.write_text(STARTER_CONFIG)
    typer.echo(f"wrote {target}")
