"""Small intra-procedural taint tracker for model-output flows.

Sources are LLM SDK calls; sinks are code and shell execution. Each function body
(and the module body) is analysed on its own: values flow through assignments,
attribute access, subscripts, f-strings and string operations. Cross-function flow
is not tracked yet, so results are a lower bound.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from slopguard.config import Config

SOURCE_SUFFIXES = (
    "messages.create",
    "chat.completions.create",
    "chat.completions.parse",
    "completions.create",
    "responses.create",
    "generate_content",
    "ollama.chat",
    "ollama.generate",
)
LLM_RECEIVER = re.compile(r"(llm|chain|model|agent|chat)", re.IGNORECASE)
LLM_METHODS = frozenset({"invoke", "ainvoke", "predict", "apredict"})
PARAM_NAME = re.compile(
    r"^(llm|model|ai|completion|generated)_?(output|response|text|code|answer|reply)$"
    r"|^(completion|generated_code|llm_response|model_output)$"
)
SANITIZERS = frozenset({"ast.literal_eval", "shlex.quote", "int", "float", "bool", "len"})
PASSTHROUGH_CALLS = frozenset({"str", "repr", "bytes", "list", "tuple", "dedent", "textwrap.dedent"})

CODE_SINKS = frozenset({"eval", "exec", "compile", "builtins.eval", "builtins.exec"})
SHELL_SINKS = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_output",
        "subprocess.check_call",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
    }
)

MAX_TRACE = 6


@dataclass(frozen=True)
class Taint:
    trace: tuple[str, ...]
    certain: bool

    def step(self, text: str) -> Taint:
        return Taint((self.trace + (text,))[-MAX_TRACE:], self.certain)


@dataclass(frozen=True)
class Flow:
    rule_id: str
    line: int
    end_line: int
    sink: str
    trace: tuple[str, ...]
    certain: bool


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _matches(name: str | None, names: frozenset[str] | set[str] | list[str]) -> bool:
    if not name:
        return False
    return any(name == n or name.endswith("." + n) for n in names)


class _Scope:
    def __init__(self, cfg: Config, env: dict[str, Taint]) -> None:
        self.cfg = cfg
        self.env = env
        self.flows: list[Flow] = []
        self.defs: list[ast.AST] = []
        self.sources = list(SOURCE_SUFFIXES) + cfg.taint_sources
        self.sanitizers = set(SANITIZERS) | set(cfg.taint_sanitizers)
        self.shell_sinks = set(SHELL_SINKS) | set(cfg.taint_sinks)

    # -- expressions -------------------------------------------------------
    def taint_of(self, node: ast.AST | None) -> Taint | None:
        if node is None:
            return None
        if isinstance(node, ast.Await):
            return self.taint_of(node.value)
        if isinstance(node, ast.Name):
            return self.env.get(node.id)
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
            return self.taint_of(node.value)
        if isinstance(node, ast.Call):
            return self._call_taint(node)
        if isinstance(node, ast.JoinedStr):
            return self._first(v.value for v in node.values if isinstance(v, ast.FormattedValue))
        if isinstance(node, ast.BinOp):
            return self._first((node.left, node.right))
        if isinstance(node, ast.BoolOp):
            return self._first(node.values)
        if isinstance(node, ast.IfExp):
            return self._first((node.body, node.orelse))
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return self._first(node.elts)
        if isinstance(node, ast.Dict):
            return self._first(v for v in node.values if v is not None)
        if isinstance(node, ast.UnaryOp):
            return self.taint_of(node.operand)
        if isinstance(node, ast.NamedExpr):
            return self.taint_of(node.value)
        return None

    def _first(self, nodes) -> Taint | None:
        for item in nodes:
            taint = self.taint_of(item)
            if taint:
                return taint
        return None

    def _is_source(self, name: str | None, func: ast.AST) -> bool:
        if _matches(name, self.sources):
            return True
        if isinstance(func, ast.Attribute) and func.attr in LLM_METHODS:
            receiver = dotted_name(func.value) or ""
            return bool(LLM_RECEIVER.search(receiver))
        return False

    def _call_taint(self, node: ast.Call) -> Taint | None:
        name = dotted_name(node.func)
        if _matches(name, self.sanitizers):
            return None
        if self._is_source(name, node.func):
            label = name or "model call"
            return Taint((f"line {node.lineno}: model output from {label}()",), True)
        if isinstance(node.func, ast.Attribute):
            inherited = self.taint_of(node.func.value)
            if inherited:
                return inherited
        if _matches(name, PASSTHROUGH_CALLS):
            return self._first(node.args)
        return None

    # -- sinks -------------------------------------------------------------
    def check_sinks(self, root: ast.AST) -> None:
        for node in ast.walk(root):
            if not isinstance(node, ast.Call):
                continue
            name = dotted_name(node.func)
            if name in CODE_SINKS:
                args = node.args[:1]
                self._report("LLM-02", node, name, args)
            elif _matches(name, self.shell_sinks):
                args = list(node.args) + [k.value for k in node.keywords]
                self._report("LLM-03", node, name, args)

    def _report(self, rule_id: str, node: ast.Call, name: str | None, args) -> None:
        for arg in args:
            taint = self.taint_of(arg)
            if taint:
                sink = name or "call"
                trace = taint.step(f"line {node.lineno}: passed to {sink}()").trace
                end = getattr(node, "end_lineno", node.lineno) or node.lineno
                self.flows.append(Flow(rule_id, node.lineno, end, sink, trace, taint.certain))
                return

    # -- statements --------------------------------------------------------
    def run(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self.stmt(stmt)

    def stmt(self, node: ast.stmt) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.defs.append(node)
            return
        if isinstance(node, ast.ClassDef):
            self.run(node.body)
            return
        nested: list[ast.stmt] = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                nested.append(child)
            elif isinstance(child, (ast.ExceptHandler, ast.match_case)):
                nested.extend(child.body)
            else:
                self.check_sinks(child)
        self._bind_statement(node)
        self.run(nested)

    def _bind_statement(self, node: ast.stmt) -> None:
        if isinstance(node, ast.Assign):
            taint = self.taint_of(node.value)
            for target in node.targets:
                self._bind(target, taint, node.lineno)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            self._bind(node.target, self.taint_of(node.value), node.lineno)
        elif isinstance(node, ast.AugAssign):
            taint = self.taint_of(node.value) or self.taint_of(node.target)
            if taint:
                self._bind(node.target, taint, node.lineno)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._bind(node.target, self.taint_of(node.iter), node.lineno)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, self.taint_of(item.context_expr), node.lineno)

    def _bind(self, target: ast.AST, taint: Taint | None, line: int) -> None:
        if isinstance(target, ast.Name):
            if taint:
                self.env[target.id] = taint.step(f"line {line}: stored in `{target.id}`")
            else:
                self.env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind(element, taint, line)


def _param_env(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Taint]:
    env: dict[str, Taint] = {}
    args = func.args
    for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        if PARAM_NAME.match(arg.arg):
            note = f"line {func.lineno}: parameter `{arg.arg}` looks like model output"
            env[arg.arg] = Taint((note,), False)
    return env


def find_flows(tree: ast.Module, cfg: Config) -> list[Flow]:
    """Return every model-output-to-sink flow found in the module."""
    flows: list[Flow] = []
    queue: list[ast.AST] = [tree]
    while queue:
        node = queue.pop(0)
        if isinstance(node, ast.Module):
            scope = _Scope(cfg, {})
            body = node.body
        else:
            scope = _Scope(cfg, _param_env(node))  # type: ignore[arg-type]
            body = node.body  # type: ignore[attr-defined]
        scope.run(body)
        flows.extend(scope.flows)
        queue.extend(scope.defs)
    seen: set[tuple[str, int]] = set()
    unique = []
    for flow in sorted(flows, key=lambda f: (f.line, f.rule_id)):
        key = (flow.rule_id, flow.line)
        if key not in seen:
            seen.add(key)
            unique.append(flow)
    return unique
