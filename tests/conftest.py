from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from slopguard.config import Config
from slopguard.context import build_project
from slopguard.engine import discover, run_scan
from slopguard.registry import RegistryClient
from slopguard.rules import all_rules


@pytest.fixture
def scan(tmp_path: Path) -> Callable[..., list]:
    """Write files into a temp project, scan them and return the findings."""

    def _scan(
        files: dict[str, str],
        *,
        rule_ids: tuple[str, ...] = (),
        known_packages: frozenset[str] = frozenset(),
        config: Config | None = None,
        network: bool = False,
    ) -> list:
        for name, content in files.items():
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        config = config or Config()
        registry = None
        if network:
            registry = RegistryClient(
                cache_path=tmp_path / ".cache.json",
                fetcher=lambda name: 200 if name in known_packages else 404,
                json_fetcher=lambda name: None,
            )
        project = build_project(tmp_path, config, network=False, registry=registry)
        rules = [r for r in all_rules() if not rule_ids or r.meta.id in rule_ids]
        suffixes = {s for r in rules for s in r.file_types}
        found = discover([tmp_path], tmp_path, config, suffixes)
        return run_scan(found, rules, project).findings

    return _scan


def ids(findings: list) -> list[str]:
    return [f.rule_id for f in findings]
