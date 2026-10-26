"""INC rules: stubs, placeholders, swallowed errors and unparseable files."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections.abc import Iterable, Iterator

from slopguard.context import FileContext
from slopguard.models import Finding, Rule, RuleMeta, Severity
from slopguard.rules import register

PLACEHOLDER_COMMENT = re.compile(
    r"""(?ix)
    \b(rest|remainder|remaining)\s+of\s+(the\s+)?(code|file|function|method|class|implementation|logic)\b
    | \.\.\.\s*(existing|previous|other|same|more)\b
    | \b(existing|previous|original)\s+(code|implementation|logic)\s+(here|remains|unchanged|goes)
    | \b(implementation|logic|code)\s+(goes\s+)?here\b
    | \b(add|insert|put|write)\s+(your\s+)?(code|logic|implementation)\s+here\b
    | \bsame\s+as\s+(before|above)\b
    """
)
CHAT_RESIDUE = re.compile(
    r"^\s*#?\s*(Sure|Certainly|Of course|Here'?s|Here is|I'?ve (?:updated|modified|added|fixed)|"
    r"As an AI)\b"
)
FENCE = re.compile(r"^\s*```")
TODO_MARKER = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")
BENIGN_EXCEPTIONS = frozenset(
    {
        "ImportError",
        "ModuleNotFoundError",
        "KeyboardInterrupt",
        "StopIteration",
        "StopAsyncIteration",
        "CancelledError",
        "asyncio.CancelledError",
    }
)
TRUNCATION_HINTS = ("was never closed", "unexpected eof", "expected an indented block", "unterminated")


def comments_and_string_lines(ctx: FileContext) -> tuple[list[tuple[int, str]], set[int]]:
    """Return ``(comments, lines inside string literals)``, cached per file."""
    cached = ctx.cache.get("tokens")
    if cached is not None:
        return cached
    comments: list[tuple[int, str]] = []
    string_lines: set[int] = set()
    fstring_starts: list[int] = []
    fstring_start = getattr(tokenize, "FSTRING_START", None)
    fstring_end = getattr(tokenize, "FSTRING_END", None)
    try:
        for token in tokenize.generate_tokens(io.StringIO(ctx.source).readline):
            if token.type == tokenize.COMMENT:
                comments.append((token.start[0], token.string))
            elif token.type == tokenize.STRING:
                string_lines.update(range(token.start[0], token.end[0] + 1))
            elif fstring_start is not None and token.type == fstring_start:
                fstring_starts.append(token.start[0])
            elif fstring_end is not None and token.type == fstring_end and fstring_starts:
                string_lines.update(range(fstring_starts.pop(), token.end[0] + 1))
    except (tokenize.TokenError, IndentationError, SyntaxError):  # slopguard: ignore[INC-04] partial tokens are fine
        pass
    ctx.cache["tokens"] = (comments, string_lines)
    return comments, string_lines


def _is_docstring(node: ast.stmt) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _is_ellipsis(node: ast.stmt) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and node.value.value is Ellipsis
    )


def _decorator_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names = set()
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute):
            names.add(target.attr)
        elif isinstance(target, ast.Name):
            names.add(target.id)
    return names


def _base_names(cls: ast.ClassDef) -> set[str]:
    names = set()
    for base in cls.bases:
        node = base.value if isinstance(base, ast.Subscript) else base
        if isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Name):
            names.add(node.id)
    return names


def _functions(tree: ast.Module) -> Iterator[tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.ClassDef | None]]:
    def visit(node: ast.AST, cls: ast.ClassDef | None):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                yield from visit(child, child)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield child, cls
                yield from visit(child, None)
            else:
                yield from visit(child, cls)

    yield from visit(tree, None)


@register
class PlaceholderComment(Rule):
    meta = RuleMeta(
        id="INC-01",
        title="Placeholder comment left by an AI assistant",
        module="inc",
        severity=Severity.MEDIUM,
        explanation=(
            "Comments such as 'rest of code here' mark code an assistant skipped. "
            "The surrounding function is usually incomplete."
        ),
        fix="Write the missing implementation, or delete the comment if nothing is missing.",
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        comments, _ = comments_and_string_lines(ctx)
        for line, text in comments:
            if PLACEHOLDER_COMMENT.search(text.lstrip("# ")):
                yield ctx.make_finding(self.meta, line, "Placeholder comment suggests missing code")


@register
class HollowFunction(Rule):
    meta = RuleMeta(
        id="INC-02",
        title="Hollow function body",
        module="inc",
        severity=Severity.MEDIUM,
        explanation=(
            "A function whose body is only `pass`, `...` or `raise NotImplementedError` does "
            "nothing. AI-generated code often leaves these behind as stubs."
        ),
        fix="Implement the function, or mark it as an abstract method or protocol member.",
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        if ctx.tree is None:
            return
        for func, cls in _functions(ctx.tree):
            if func.name.startswith("__") and func.name.endswith("__"):
                continue
            if _decorator_names(func) & {"abstractmethod", "overload", "abstractproperty"}:
                continue
            if cls is not None and _base_names(cls) & {"ABC", "Protocol", "ABCMeta"}:
                continue
            body = [s for s in func.body if not _is_docstring(s)]
            kind = self._hollow_kind(body)
            if kind is None:
                continue
            soft = kind == "docstring only" or (kind == "NotImplementedError" and cls is not None)
            confidence = 0.5 if soft else 0.85
            yield ctx.make_finding(
                self.meta,
                func.lineno,
                f"`{func.name}` has no implementation ({kind})",
                end_line=getattr(func, "end_lineno", None),
                confidence=confidence,
            )

    @staticmethod
    def _hollow_kind(body: list[ast.stmt]) -> str | None:
        if not body:
            return "docstring only"
        if all(isinstance(s, ast.Pass) for s in body):
            return "pass"
        if all(_is_ellipsis(s) for s in body):
            return "ellipsis"
        if len(body) == 1 and isinstance(body[0], ast.Raise) and body[0].exc is not None:
            exc = body[0].exc
            target = exc.func if isinstance(exc, ast.Call) else exc
            if isinstance(target, ast.Name) and target.id == "NotImplementedError":
                return "NotImplementedError"
        return None


@register
class SwallowedException(Rule):
    meta = RuleMeta(
        id="INC-04",
        title="Swallowed exception",
        module="inc",
        severity=Severity.MEDIUM,
        explanation=(
            "An except block that only passes hides failures, so bugs surface later and far "
            "from their cause."
        ),
        fix="Log the error, re-raise it, or handle it explicitly; catch the narrowest type.",
        cwe=("CWE-390",),
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        if ctx.tree is None:
            return
        for node in ast.walk(ctx.tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            body = [s for s in node.body if not _is_docstring(s)]
            if not body or not all(isinstance(s, ast.Pass) or _is_ellipsis(s) for s in body):
                continue
            names = self._exception_names(node.type)
            if names and names <= BENIGN_EXCEPTIONS:
                continue
            broad = not names or bool(names & {"Exception", "BaseException"})
            label = "bare except" if node.type is None else f"except {', '.join(sorted(names))}"
            yield ctx.make_finding(
                self.meta,
                node.lineno,
                f"Exception silently ignored ({label})",
                end_line=getattr(node, "end_lineno", None),
                confidence=0.9 if broad else 0.6,
            )

    @staticmethod
    def _exception_names(node: ast.expr | None) -> set[str]:
        if node is None:
            return set()
        items = node.elts if isinstance(node, ast.Tuple) else [node]
        names = set()
        for item in items:
            if isinstance(item, ast.Name):
                names.add(item.id)
            elif isinstance(item, ast.Attribute):
                base = item.value.id if isinstance(item.value, ast.Name) else ""
                names.add(f"{base}.{item.attr}" if base else item.attr)
        return names


@register
class ChatResidue(Rule):
    meta = RuleMeta(
        id="INC-05",
        title="Assistant chat text inside source",
        module="inc",
        severity=Severity.HIGH,
        explanation=(
            "Markdown fences or sentences like 'Here is the updated function' were copied from "
            "a chat window into the file."
        ),
        fix="Delete the conversational text so only code remains.",
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        _, string_lines = comments_and_string_lines(ctx)
        for number, text in enumerate(ctx.lines, start=1):
            if number in string_lines:
                continue
            if FENCE.match(text):
                yield ctx.make_finding(self.meta, number, "Markdown code fence in source file")
            elif CHAT_RESIDUE.match(text):
                yield ctx.make_finding(
                    self.meta, number, "Conversational text left in source", confidence=0.7
                )


@register
class TodoDensity(Rule):
    meta = RuleMeta(
        id="INC-06",
        title="High TODO or FIXME density",
        module="inc",
        severity=Severity.LOW,
        explanation="Many TODO, FIXME or HACK markers in one file point to unfinished work.",
        fix="Finish or ticket the open items, then remove the markers.",
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        threshold = int(ctx.options(self.meta.id).get("threshold", 5))
        comments, _ = comments_and_string_lines(ctx)
        marked = [line for line, text in comments if TODO_MARKER.search(text)]
        if len(marked) >= threshold:
            yield ctx.make_finding(
                self.meta,
                marked[0],
                f"{len(marked)} TODO/FIXME/HACK markers in this file (threshold {threshold})",
                confidence=0.8,
            )


@register
class UnparseableFile(Rule):
    meta = RuleMeta(
        id="INC-08",
        title="File does not parse",
        module="inc",
        severity=Severity.HIGH,
        explanation=(
            "The file has a syntax error. Truncated AI output often ends mid-function or with "
            "an unclosed bracket or string."
        ),
        fix="Restore the missing part of the file, or regenerate it in full.",
    )

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        error = ctx.syntax_error
        if error is None:
            return
        message = (error.msg or "invalid syntax").strip()
        truncated = any(hint in message.lower() for hint in TRUNCATION_HINTS)
        yield ctx.make_finding(
            self.meta,
            error.lineno or 1,
            f"File does not parse: {message}" + (" (looks truncated)" if truncated else ""),
            confidence=0.95 if truncated else 0.8,
        )
