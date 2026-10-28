"""Command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from slopguard import __version__
from slopguard.api import select_rules
from slopguard.bench import run_benchmark
from slopguard.config import STARTER_CONFIG, Config, ConfigError
from slopguard.context import build_project
from slopguard.engine import (
    changed_files,
    discover,
    find_root,
    load_baseline,
    run_scan,
    write_baseline,
)
from slopguard.llm import LLMError, get_provider
from slopguard.models import Rule, Severity
from slopguard.regress import RegressionError, regress
from slopguard.repair import read_sources, repair
from slopguard.reporters import render_terminal, to_json, to_markdown, to_sarif
from slopguard.rules import all_rules, get_rule
from slopguard.sandbox import SandboxError, run_tests
from slopguard.spec import parse_spec, verdict_findings, verify_spec

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
    try:
        return select_rules(config, modules, rule_ids)
    except ValueError as exc:
        raise _fail(str(exc)) from exc


@app.command()
def scan(
    paths: list[Path] | None = typer.Argument(None, help="Files or folders to scan."),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal, json, markdown or sarif."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write the report here."),
    severity: str | None = typer.Option(None, "--severity", help="Minimum severity to report."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit 1 at this severity or above, or 'none' (default: high)."),
    module: list[str] | None = typer.Option(None, "--module", "-m", help="Run only these modules."),
    rule: list[str] | None = typer.Option(None, "--rule", "-r", help="Run only these rule IDs."),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="Glob to skip (repeatable)."),
    diff: str | None = typer.Option(None, "--diff", help="Scan only files changed against this git ref."),
    staged: bool = typer.Option(False, "--staged", help="Scan only files staged for commit."),
    baseline: Path | None = typer.Option(None, "--baseline", help="Ignore findings recorded in this file."),
    write_baseline_to: Path | None = typer.Option(None, "--write-baseline", help="Record current findings as a baseline."),
    no_network: bool = typer.Option(False, "--no-network", help="Skip PyPI lookups."),
    config_path: Path | None = typer.Option(None, "--config", help="Path to a slopguard.toml."),
    spec: Path | None = typer.Option(None, "--spec", help="Check the code against this spec file."),
    use_llm: bool = typer.Option(False, "--llm", help="Let the configured model judge --spec requirements."),
) -> None:
    """Scan code for LLM-app vulnerabilities, hallucinated imports and unfinished code."""
    try:
        exit_code = _scan(
            paths or [Path(".")], fmt, output, severity, fail_on, module or [], rule or [],
            exclude or [], diff, staged, baseline, write_baseline_to, no_network, config_path,
            spec, use_llm,
        )
    except typer.Exit:
        raise
    except Exception as exc:  # last resort so users get exit code 3, not a traceback
        raise _fail(f"internal error: {exc!r}", EXIT_INTERNAL) from exc
    raise typer.Exit(exit_code)


def _scan(paths, fmt, output, severity, fail_on, modules, rule_ids, exclude, diff, staged,
          baseline, write_baseline_to, no_network, config_path, spec=None, use_llm=False) -> int:
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
    changed = None
    if diff or staged:
        try:
            changed = changed_files(root, diff, staged)
        except RuntimeError as exc:
            raise _fail(str(exc)) from exc
        files = [f for f in files if f in changed]

    project = build_project(root, config, network=not no_network, changed=changed)
    result = run_scan(files, rules, project)
    if project.registry is not None:
        project.registry.save()

    findings = result.findings
    if spec is not None:
        findings = sorted(
            findings + _spec_findings(spec, paths, root, config, use_llm),
            key=lambda f: (f.path, f.line, f.rule_id),
        )
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


def _provider(config: Config, what: str):
    try:
        provider = get_provider(config)
    except LLMError as exc:
        raise _fail(str(exc)) from exc
    Console(stderr=True).print(
        f"sending {what} to {provider.name} ({provider.model}); source stays local otherwise",
        markup=False,
    )
    return provider


def _read_py_files(paths, root: Path, config: Config) -> list[tuple[str, str]]:
    files = discover(paths, root, config, {".py"})
    return [(_rel_to(p, root), p.read_text(errors="replace")) for p in files]


def _rel_to(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()


def _spec_findings(spec: Path, paths, root: Path, config: Config, use_llm: bool):
    if not spec.is_file():
        raise _fail(f"spec file not found: {spec}")
    text = spec.read_text(errors="replace")
    provider = _provider(config, "requirement text and the best-matching code") if use_llm else None
    try:
        verdicts = verify_spec(text, _read_py_files(paths, root, config), provider)
    except LLMError as exc:
        raise _fail(f"spec check failed: {exc}") from exc
    if not verdicts:
        raise _fail("no requirements found in the spec; use bullet points, or pass --llm to extract them")
    counts = {s: sum(v.status == s for v in verdicts) for s in ("met", "partial", "missing")}
    Console(stderr=True).print(
        f"spec: {counts['met']} met, {counts['partial']} partial, {counts['missing']} missing "
        f"({'model-judged' if provider else 'name matching only; behaviour not verified'})",
        markup=False,
    )
    return verdict_findings(_rel_to(spec.resolve(), root), verdicts)


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


@app.command("regress")
def regress_cmd(
    base: str = typer.Option("HEAD", "--base", help="Git ref to compare against."),
    run_tests_flag: bool = typer.Option(False, "--run-tests", help="Also run the suite at the base and now."),
    timeout: int = typer.Option(300, "--timeout", help="Seconds allowed per test run."),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal, json, markdown or sarif."),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """Find deleted, skipped or weakened tests, and tests that passed before and now fail."""
    if fmt not in FORMATS:
        raise _fail(f"unknown format {fmt!r}; expected one of: {', '.join(FORMATS)}")
    root = find_root([Path(".")])
    try:
        Config.load(root, config_path)
        findings = regress(root, base, run_tests_flag, timeout)
    except (ConfigError, RegressionError) as exc:
        raise _fail(str(exc)) from exc
    rules = [r for r in all_rules() if r.meta.module == "reg"]
    _emit(fmt, None, findings, rules, 0, [])
    raise typer.Exit(EXIT_FINDINGS if any(f.severity >= Severity.HIGH for f in findings) else EXIT_OK)



@app.command("gen-tests")
def gen_tests(
    spec: Path = typer.Option(..., "--spec", help="Spec file with the requirements."),
    paths: list[Path] | None = typer.Argument(None, help="Code to test (default: current folder)."),
    out: Path = typer.Option(Path("tests/generated/test_spec_requirements.py"), "--out", help="Where to write the tests."),
    run: bool = typer.Option(False, "--run", help="Run the tests in the sandbox and report per requirement."),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """Ask the configured model for pytest tests that check each requirement."""
    from slopguard.gentests import apply_test_results, generate_tests
    from slopguard.spec import build_index, judge_heuristic

    paths = paths or [Path(".")]
    root = find_root(paths)
    try:
        config = Config.load(root, config_path)
    except ConfigError as exc:
        raise _fail(str(exc)) from exc
    if not spec.is_file():
        raise _fail(f"spec file not found: {spec}")
    requirements = parse_spec(spec.read_text(errors="replace"))
    if not requirements:
        raise _fail("no requirements found in the spec; use bullet points")
    files = _read_py_files(paths, root, config)
    provider = _provider(config, "requirement text and public function signatures")
    try:
        code = generate_tests(requirements, files, provider)
    except LLMError as exc:
        raise _fail(f"test generation failed: {exc}") from exc
    target = out if out.is_absolute() else root / out
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code)
    typer.echo(f"wrote {target}")
    if not run:
        typer.echo("review the file, then run it, or re-run with --run to use the sandbox")
        return
    index = build_index(files)
    verdicts = [judge_heuristic(r, index) for r in requirements]
    try:
        outcome = run_tests(root, {_rel_to(target, root): code}, backend=config.sandbox_backend,
                            image=config.sandbox_image, timeout=config.sandbox_timeout)
    except SandboxError as exc:
        raise _fail(str(exc)) from exc
    verdicts = apply_test_results(verdicts, outcome)
    table = Table(show_header=True, header_style="bold")
    for column in ("Req", "Status", "Source", "Reason"):
        table.add_column(column)
    for v in verdicts:
        table.add_row(v.requirement.id, v.status, v.source, v.reason)
    Console().print(table)
    typer.echo(f"sandbox: {outcome.backend}; exit {outcome.returncode}"
               + ("; timed out" if outcome.timed_out else ""))
    raise typer.Exit(EXIT_OK if outcome.passed else EXIT_FINDINGS)


@app.command()
def fix(
    paths: list[Path] | None = typer.Argument(None, help="Files or folders to repair."),
    max_rounds: int = typer.Option(3, "--max-rounds", help="Stop after this many rounds."),
    min_severity: str = typer.Option("high", "--min-severity", help="Only repair findings at or above this."),
    apply: bool = typer.Option(False, "--apply", help="Write accepted changes to disk."),
    yes: bool = typer.Option(False, "--yes", help="Do not ask before writing with --apply."),
    no_network: bool = typer.Option(False, "--no-network"),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """Scan, ask the configured model for fixes, re-scan, and keep only real improvements.

    By default this only prints a diff. Use --apply to write the files.
    """
    paths = paths or [Path(".")]
    for path in paths:
        if not path.exists():
            raise _fail(f"path not found: {path}")
    try:
        minimum = Severity.parse(min_severity)
        root = find_root(paths)
        config = Config.load(root, config_path)
    except (ConfigError, ValueError) as exc:
        raise _fail(str(exc)) from exc
    rules = _select_rules(config, [], [])
    suffixes = {".py"}
    files = discover(paths, root, config, suffixes)
    if not files:
        raise _fail("no Python files to repair")
    provider = _provider(config, "each file that has serious findings, plus the findings")
    project = build_project(root, config, network=not no_network)
    result = repair(read_sources(files, root), rules, project, provider,
                    max_rounds=max_rounds, minimum=minimum)
    console = Console()
    for round_ in result.rounds:
        for attempt in round_.attempts:
            mark = "accepted" if attempt.accepted else "rejected"
            console.print(f"round {round_.number}: {attempt.path}: {mark} ({attempt.note})", markup=False)
    console.print(f"stopped: {result.stopped}", markup=False)
    serious = [f for f in result.remaining if f.severity >= minimum]
    console.print(f"{len(serious)} serious finding(s) remain", markup=False)
    diff = result.diff()
    if not diff:
        raise typer.Exit(EXIT_FINDINGS if serious else EXIT_OK)
    typer.echo(diff)
    if apply and (yes or typer.confirm("Write these changes to disk?")):
        for rel in result.changed_files():
            (root / rel).write_text(result.current[rel])
        console.print(f"wrote {len(result.changed_files())} file(s)", markup=False)
    elif apply:
        console.print("nothing written", markup=False)
    else:
        console.print("dry run: re-run with --apply to write these changes", markup=False)
    raise typer.Exit(EXIT_FINDINGS if serious else EXIT_OK)


def rules_markdown() -> str:
    lines = ["# Rules reference", "",
             "Generated by `slopguard rules --markdown`. Do not edit by hand.", "",
             "| ID | Severity | Module | Status | Title |", "| --- | --- | --- | --- | --- |"]
    rules = all_rules()
    for rule in rules:
        m = rule.meta
        lines.append(f"| [{m.id}](#{m.id.lower()}) | {m.severity.label} | {m.module} | {m.status} | {m.title} |")
    for rule in rules:
        m = rule.meta
        lines += ["", f"## {m.id}", "", f"**{m.title}**", "",
                  f"Severity: {m.severity.label}. Module: `{m.module}`. Status: {m.status}.", "",
                  f"**Why it matters.** {m.explanation}", "", f"**How to fix.** {m.fix}"]
        if m.cwe or m.owasp:
            lines += ["", "References: " + ", ".join([*m.cwe, *m.owasp])]
    return "\n".join(lines) + "\n"


@app.command("rules")
def list_rules(
    markdown: bool = typer.Option(False, "--markdown", help="Print the full reference as Markdown."),
) -> None:
    """List every rule with its severity and module."""
    if markdown:
        typer.echo(rules_markdown(), nl=False)
        return
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


@app.command()
def bench(
    corpus: Path = typer.Argument(Path("benchmarks/corpus"), help="Folder of labelled files."),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal or json."),
    min_precision: float = typer.Option(0.0, "--min-precision", help="Exit 1 if any rule is below."),
    min_recall: float = typer.Option(0.0, "--min-recall", help="Exit 1 if any rule is below."),
) -> None:
    """Score slopguard against a labelled corpus (precision, recall and F1 per rule)."""
    if not corpus.is_dir():
        raise _fail(f"corpus folder not found: {corpus}")
    if fmt not in ("terminal", "json"):
        raise _fail("format must be terminal or json")
    report = run_benchmark(corpus)
    if fmt == "json":
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        _print_bench(report)
    problems = report.failing(min_precision, min_recall)
    for problem in problems:
        Console(stderr=True).print(f"below threshold: {problem}", markup=False)
    raise typer.Exit(EXIT_FINDINGS if problems else EXIT_OK)


def _print_bench(report) -> None:
    def cell(value: float | None) -> str:
        return "-" if value is None else f"{value:.2f}"

    table = Table(show_header=True, header_style="bold")
    for column in ("Rule", "TP", "FP", "FN", "Precision", "Recall", "F1"):
        table.add_column(column, justify="left" if column == "Rule" else "right")
    for rule_id, score in sorted(report.scores.items()):
        table.add_row(rule_id, str(score.tp), str(score.fp), str(score.fn),
                      cell(score.precision), cell(score.recall), cell(score.f1))
    total = report.overall()
    table.add_section()
    table.add_row("overall", str(total.tp), str(total.fp), str(total.fn),
                  cell(total.precision), cell(total.recall), cell(total.f1))
    console = Console()
    console.print(table)
    console.print(f"{report.files} labelled files", markup=False)
    for line in report.mismatches:
        console.print(line, markup=False, style="yellow")
    for rel in report.unlabelled:
        console.print(f"unlabelled (skipped): {rel}", markup=False, style="dim")
