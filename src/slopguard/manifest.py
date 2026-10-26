"""Read declared dependencies from requirements files and pyproject.toml."""

from __future__ import annotations

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

from slopguard.registry import normalize

_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def requirement_name(spec: str) -> str | None:
    match = _REQUIREMENT_NAME.match(spec)
    return normalize(match.group(1)) if match else None


def _from_requirements_file(path: Path) -> set[str]:
    names: set[str] = set()
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://", ".")):
            continue
        name = requirement_name(line)
        if name:
            names.add(name)
    return names


def _from_pyproject(path: Path) -> set[str]:
    try:
        data = tomllib.loads(path.read_text(errors="replace"))
    except tomllib.TOMLDecodeError:
        return set()
    specs: list[str] = []
    project = data.get("project", {})
    specs += [s for s in project.get("dependencies", []) if isinstance(s, str)]
    for group in project.get("optional-dependencies", {}).values():
        specs += [s for s in group if isinstance(s, str)]
    for group in data.get("dependency-groups", {}).values():
        specs += [s for s in group if isinstance(s, str)]
    names = {n for n in map(requirement_name, specs) if n}
    poetry = data.get("tool", {}).get("poetry", {})
    tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    tables += [g.get("dependencies", {}) for g in poetry.get("group", {}).values()]
    for table in tables:
        names |= {normalize(k) for k in table if k.lower() != "python"}
    return names


def declared_dependencies(root: Path) -> set[str] | None:
    """Return normalised declared dependency names, or None when no manifest exists."""
    found = False
    names: set[str] = set()
    for path in sorted(root.glob("requirements*.txt")) + sorted(root.glob("requirements/*.txt")):
        found = True
        names |= _from_requirements_file(path)
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        found = True
        names |= _from_pyproject(pyproject)
    return names if found else None
