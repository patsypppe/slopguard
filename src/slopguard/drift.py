"""Mine a repository's own conventions so new code can be compared against them."""

from __future__ import annotations

import ast
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from slopguard.config import Config
from slopguard.engine import discover

TEST_PATH = re.compile(r"(^|/)(tests?/|test_[^/]*\.py$|[^/]*_test\.py$|conftest\.py$)")
SNAKE = re.compile(r"^_*[a-z][a-z0-9_]*$")
PASCAL = re.compile(r"^_*[A-Z][A-Za-z0-9]*$")
SCRIPT_NAMES = frozenset({"cli.py", "__main__.py", "main.py", "manage.py", "setup.py"})

# libraries that do the same job; a repo normally picks one of them
JOBS: dict[str, tuple[str, ...]] = {
    "HTTP client": ("requests", "httpx", "aiohttp", "urllib3"),
    "JSON": ("json", "orjson", "ujson", "simplejson"),
    "command line": ("argparse", "click", "typer", "fire"),
    "data frames": ("pandas", "polars"),
    "logging": ("logging", "loguru", "structlog"),
    "validation": ("pydantic", "marshmallow", "attrs"),
}
MIN_FILES = 3


@dataclass
class Conventions:
    files: int = 0
    functions: int = 0
    snake_functions: int = 0
    classes: int = 0
    pascal_classes: int = 0
    annotated_functions: int = 0
    imports: Counter[str] = field(default_factory=Counter)  # module -> number of files using it
    print_files: int = 0

    @property
    def usable(self) -> bool:
        return self.files >= MIN_FILES

    def snake_ratio(self) -> float:
        return self.snake_functions / self.functions if self.functions else 0.0

    def pascal_ratio(self) -> float:
        return self.pascal_classes / self.classes if self.classes else 0.0

    def annotated_ratio(self) -> float:
        return self.annotated_functions / self.functions if self.functions else 0.0

    def job_choice(self, job: str) -> str | None:
        """The library this repo uses for ``job`` (used in at least two files), if any."""
        counts = {m: self.imports[m] for m in JOBS[job] if self.imports[m] >= 2}
        return max(counts, key=lambda m: counts[m]) if counts else None


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH.search(rel))


def is_script(rel: str) -> bool:
    return Path(rel).name in SCRIPT_NAMES or rel.startswith(("scripts/", "script/"))


def public_functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
    ]


def imported_modules(tree: ast.AST) -> dict[str, int]:
    """Top-level module -> first line, for absolute imports."""
    found: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.setdefault(alias.name.split(".")[0], node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.setdefault(node.module.split(".")[0], node.lineno)
    return found


def main_guard_lines(tree: ast.Module) -> set[int]:
    """Line numbers inside ``if __name__ == "__main__":`` blocks."""
    lines: set[int] = set()
    for node in tree.body:
        if isinstance(node, ast.If) and "__main__" in ast.dump(node.test):
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            lines.update(range(node.lineno, end + 1))
    return lines


def print_calls(tree: ast.Module) -> list[int]:
    guarded = main_guard_lines(tree)
    return sorted(
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "print"
        and node.lineno not in guarded
    )


def mine_conventions(root: Path, config: Config, exclude: set[Path]) -> Conventions:
    conv = Conventions()
    for path in discover([root], root, config, {".py"}):
        if path.resolve() in exclude:
            continue
        rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
        if is_test_path(rel):
            continue
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (SyntaxError, ValueError, OSError):
            continue
        conv.files += 1
        for module in imported_modules(tree):
            conv.imports[module] += 1
        for func in public_functions(tree):
            conv.functions += 1
            conv.snake_functions += bool(SNAKE.match(func.name))
            conv.annotated_functions += func.returns is not None
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                conv.classes += 1
                conv.pascal_classes += bool(PASCAL.match(node.name))
        if not is_script(rel) and print_calls(tree):
            conv.print_files += 1
    return conv
