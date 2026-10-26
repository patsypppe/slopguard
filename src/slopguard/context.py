"""Per-project and per-file context handed to rules."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any

from slopguard.config import Config
from slopguard.manifest import declared_dependencies
from slopguard.models import Finding, RuleMeta
from slopguard.registry import RegistryClient


@dataclass
class ProjectContext:
    root: Path
    config: Config
    registry: RegistryClient | None
    declared: set[str] | None
    local_modules: set[str]
    installed: dict[str, list[str]]
    changed: set[Path] | None = None
    _conventions: Any = None

    def conventions(self) -> Any:
        """Style conventions mined from files outside the change (computed once)."""
        if self._conventions is None:
            from slopguard.drift import mine_conventions

            self._conventions = mine_conventions(self.root, self.config, self.changed or set())
        return self._conventions

    def is_local(self, name: str, file_path: Path) -> bool:
        if name in self.local_modules:
            return True
        folder = file_path.parent
        return (folder / f"{name}.py").exists() or (folder / name).is_dir()


@dataclass
class FileContext:
    path: Path
    rel: str
    source: str
    project: ProjectContext
    tree: ast.Module | None = None
    syntax_error: SyntaxError | None = None
    cache: dict[str, Any] = field(default_factory=dict)
    lines: list[str] = field(init=False)

    def __post_init__(self) -> None:
        self.lines = self.source.splitlines()

    @property
    def config(self) -> Config:
        return self.project.config

    def options(self, rule_id: str) -> dict[str, Any]:
        return self.config.rule_options(rule_id)

    def line_text(self, line: int) -> str:
        return self.lines[line - 1] if 1 <= line <= len(self.lines) else ""

    def make_finding(
        self,
        meta: RuleMeta,
        line: int,
        message: str,
        *,
        end_line: int | None = None,
        confidence: float = 0.9,
        excerpt: str | None = None,
        trace: tuple[str, ...] = (),
    ) -> Finding:
        return Finding(
            rule_id=meta.id,
            severity=meta.severity,
            message=message,
            path=self.rel,
            line=line,
            end_line=end_line or line,
            confidence=confidence,
            explanation=meta.explanation,
            fix=meta.fix,
            cwe=meta.cwe,
            owasp=meta.owasp,
            excerpt=self.line_text(line).strip() if excerpt is None else excerpt,
            trace=trace,
        )


def _local_module_names(root: Path) -> set[str]:
    names: set[str] = set()
    for base in (root, root / "src"):
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            if entry.name.startswith((".", "_")) and entry.name != "__init__.py":
                continue
            if entry.is_dir():
                names.add(entry.name)
            elif entry.suffix == ".py":
                names.add(entry.stem)
    return names


def build_project(
    root: Path,
    config: Config,
    *,
    network: bool = True,
    registry: RegistryClient | None = None,
    changed: set[Path] | None = None,
) -> ProjectContext:
    if registry is None and network and config.registry_lookups:
        registry = RegistryClient(ttl_hours=config.cache_ttl_hours)
    try:
        installed = {k: list(v) for k, v in metadata.packages_distributions().items()}
    except Exception:  # noqa: BLE001  # pragma: no cover - broken metadata must not stop a scan
        installed = {}
    return ProjectContext(
        root=root,
        config=config,
        registry=registry,
        declared=declared_dependencies(root),
        local_modules=_local_module_names(root),
        installed=installed,
        changed=changed,
    )
