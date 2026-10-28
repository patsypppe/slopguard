"""The supported Python API.

Everything importable from ``slopguard`` directly (``slopguard.scan``, ``Finding``,
``Severity``, ``Config``) comes from here. The CLI is a thin layer over the same functions.

    import slopguard

    result = slopguard.scan(["src"], network=False)
    for finding in result.findings:
        print(finding.rule_id, finding.path, finding.line, finding.message)
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from slopguard.config import MODULES, Config
from slopguard.context import build_project
from slopguard.engine import ScanResult, discover, find_root, run_scan, scan_text
from slopguard.models import Finding, Rule, Severity
from slopguard.rules import all_rules

__all__ = ["Config", "Finding", "ScanResult", "Severity", "scan", "scan_source", "select_rules"]


def select_rules(
    config: Config, modules: Iterable[str] = (), rule_ids: Iterable[str] = ()
) -> list[Rule]:
    """Rules to run: those in ``modules`` (or enabled in ``config``), narrowed to ``rule_ids``.

    Raises ``ValueError`` for an unknown module or rule ID.
    """
    modules, wanted = list(modules), {r.upper() for r in rule_ids}
    for name in modules:
        if name not in MODULES:
            raise ValueError(f"unknown module {name!r}; expected one of: {', '.join(MODULES)}")
    unknown = wanted - {r.meta.id for r in all_rules()}
    if unknown:
        raise ValueError(f"unknown rule(s): {', '.join(sorted(unknown))}")
    chosen = []
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
    return chosen


def scan(
    paths: Iterable[str | Path] = (".",),
    *,
    config: Config | None = None,
    config_path: str | Path | None = None,
    modules: Iterable[str] = (),
    rules: Iterable[str] = (),
    network: bool = True,
) -> ScanResult:
    """Scan files or folders and return the findings.

    ``config`` wins over ``config_path``; with neither, ``slopguard.toml`` or
    ``[tool.slopguard]`` is read from the project root. ``network=False`` skips PyPI lookups.
    Raises ``slopguard.config.ConfigError`` for a bad configuration and ``FileNotFoundError``
    for a path that does not exist.
    """
    targets = [Path(p) for p in paths]
    for target in targets:
        if not target.exists():
            raise FileNotFoundError(target)
    root = find_root(targets)
    if config is None:
        config = Config.load(root, Path(config_path) if config_path else None)
    selected = select_rules(config, modules, rules)
    files = discover(targets, root, config, {s for r in selected for s in r.file_types})
    project = build_project(root, config, network=network)
    result = run_scan(files, selected, project)
    if project.registry is not None:
        project.registry.save()
    return result


def scan_source(
    source: str,
    filename: str = "snippet.py",
    *,
    config: Config | None = None,
    modules: Iterable[str] = (),
    rules: Iterable[str] = (),
) -> list[Finding]:
    """Scan a string of source code, for example an assistant's answer before it is saved.

    Offline and file-system free: package lookups and manifest checks are skipped.
    """
    config = config or Config()
    selected = select_rules(config, modules, rules)
    project = build_project(Path.cwd(), config, network=False)
    return scan_text(filename, source, selected, project)
