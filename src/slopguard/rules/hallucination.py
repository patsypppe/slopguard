"""HAL rules: imports of packages that do not exist or are not declared."""

from __future__ import annotations

import ast
import sys
from collections.abc import Iterable, Iterator

from slopguard.context import FileContext
from slopguard.models import Finding, Rule, RuleMeta, Severity
from slopguard.registry import normalize
from slopguard.rules import register

# import name -> PyPI distribution names, where they differ
ALIASES: dict[str, list[str]] = {
    "yaml": ["pyyaml"],
    "PIL": ["pillow"],
    "cv2": ["opencv-python", "opencv-python-headless"],
    "sklearn": ["scikit-learn"],
    "skimage": ["scikit-image"],
    "bs4": ["beautifulsoup4"],
    "dotenv": ["python-dotenv"],
    "jwt": ["pyjwt"],
    "attr": ["attrs"],
    "dateutil": ["python-dateutil"],
    "git": ["gitpython"],
    "serial": ["pyserial"],
    "OpenSSL": ["pyopenssl"],
    "Crypto": ["pycryptodome", "pycryptodomex"],
    "magic": ["python-magic"],
    "docx": ["python-docx"],
    "pptx": ["python-pptx"],
    "fitz": ["pymupdf"],
    "mpl_toolkits": ["matplotlib"],
    "tomli_w": ["tomli-w"],
}
SKIP_ROOTS = frozenset({"google", "azure", "__main__", "conftest", "_typeshed"})


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    items = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    names = {i.id for i in items if isinstance(i, ast.Name)}
    return bool(names & {"ImportError", "ModuleNotFoundError", "Exception"})


def iter_imports(tree: ast.Module) -> Iterator[tuple[str, int, bool]]:
    """Yield ``(top-level name, line, guarded)`` once per imported root name."""
    guarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and any(_catches_import_error(h) for h in node.handlers):
            for stmt in node.body:
                guarded.update(id(sub) for sub in ast.walk(stmt))
    seen: set[str] = set()
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module.split(".")[0]]
        for name in names:
            if name not in seen:
                seen.add(name)
                yield name, node.lineno, id(node) in guarded


def third_party_candidates(ctx: FileContext, root: str) -> list[str] | None:
    """Distribution names an import could come from, or None for stdlib and local modules."""
    if root in sys.stdlib_module_names or root == "__future__":
        return None
    if root in SKIP_ROOTS or root.startswith("_"):
        return None
    if ctx.project.is_local(root, ctx.path):
        return None
    return ALIASES.get(root, [root])


@register
class NonexistentPackage(Rule):
    meta = RuleMeta(
        id="HAL-01",
        title="Imported package does not exist on PyPI",
        module="hal",
        severity=Severity.HIGH,
        explanation=(
            "AI assistants invent plausible package names. Installing a name that does not "
            "exist fails, and an attacker can register it and ship malware (slopsquatting)."
        ),
        fix="Check the import. Use the real package name, or remove the dependency.",
        cwe=("CWE-829",),
        owasp=("LLM03:2025 Supply Chain",),
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        registry = ctx.project.registry
        if ctx.tree is None or registry is None:
            return
        for root, line, _guarded in iter_imports(ctx.tree):
            candidates = third_party_candidates(ctx, root)
            if candidates is None or root in ctx.project.installed:
                continue
            answers = [registry.exists(name) for name in candidates]
            if any(a is True or a is None for a in answers):
                continue  # exists, or we could not tell
            yield ctx.make_finding(
                self.meta,
                line,
                f"`{root}` is not on PyPI and is not a local or installed module",
                confidence=0.85,
            )


@register
class UndeclaredDependency(Rule):
    meta = RuleMeta(
        id="HAL-04",
        title="Import not declared in the project's dependencies",
        module="hal",
        severity=Severity.MEDIUM,
        explanation=(
            "The code imports a third-party package that no requirements file or pyproject "
            "dependency list mentions, so a clean install will fail."
        ),
        fix="Add the package to your dependency manifest, or remove the import.",
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        declared = ctx.project.declared
        if ctx.tree is None or declared is None:
            return
        for root, line, guarded in iter_imports(ctx.tree):
            candidates = third_party_candidates(ctx, root)
            if candidates is None or guarded:
                continue
            known = {normalize(c) for c in candidates}
            known |= {normalize(d) for d in ctx.project.installed.get(root, [])}
            if known & declared:
                continue
            yield ctx.make_finding(
                self.meta,
                line,
                f"`{root}` is imported but not declared as a dependency",
                confidence=0.6,
            )
