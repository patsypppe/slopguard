"""Small intra-procedural taint tracker.

Three kinds of flow are tracked, each with its own sources and sinks:

* ``model``: output of an LLM SDK call reaching code, shell, SQL, file or URL sinks.
* ``untrusted``: user, web or CLI input reaching the system prompt of an LLM call.
* ``tool``: arguments of an agent tool function reaching the same dangerous sinks.

Each function body (and the module body) is analysed on its own: values flow through
assignments, attribute access, subscripts, f-strings and string operations. Flow across
functions is not tracked yet, so results are a lower bound.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from slopguard.config import Config

MODEL_SOURCE_SUFFIXES = (
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
MODEL_PARAM = re.compile(
    r"^(llm|model|ai|completion|generated)_?(output|response|text|code|answer|reply)$"
    r"|^(completion|generated_code|llm_response|model_output)$"
)
UNTRUSTED_PARAM = re.compile(
    r"^(user|untrusted|raw)_?(input|message|query|prompt|text|question|content)$"
)
UNTRUSTED_CALLS = frozenset(
    {
        "input",
        "sys.stdin.read",
        "sys.stdin.readline",
        "requests.get",
        "requests.post",
        "httpx.get",
        "httpx.post",
        "urllib.request.urlopen",
        "urlopen",
        "request.get_json",
        "request.get_data",
    }
)
UNTRUSTED_ATTRS = frozenset(
    {
        "request.args",
        "request.form",
        "request.json",
        "request.values",
        "request.data",
        "request.GET",
        "request.POST",
        "request.body",
        "request.query_params",
        "request.headers",
        "request.cookies",
        "sys.argv",
    }
)
SANITIZERS = frozenset({"ast.literal_eval", "shlex.quote", "int", "float", "bool", "len"})
PASSTHROUGH_CALLS = frozenset({"str", "repr", "bytes", "list", "tuple", "dedent", "textwrap.dedent"})
STRING_BUILDERS = frozenset({"format", "format_map", "join", "replace"})
SYSTEM_KWARGS = frozenset(
    {"system", "instructions", "system_prompt", "system_instruction", "preamble"}
)
PROMPT_KWARGS = frozenset({"prompt", "contents", "input", "query"})
TOOL_DECORATORS = frozenset({"tool", "function_tool", "call_tool"})
TOOL_FACTORIES = ("Tool", "StructuredTool", "from_function", "from_defaults")
NON_MODEL_PARAMS = frozenset({"self", "cls", "ctx", "context", "config", "run_manager", "callbacks"})

MAX_TRACE = 6


@dataclass(frozen=True)
class Sink:
    rule_id: str
    label: str
    exact: frozenset[str] = frozenset()
    suffix: frozenset[str] = frozenset()
    any_arg: bool = False
    base_confidence: float = 0.9


CODE_SINK = Sink(
    "LLM-02",
    "code execution",
    exact=frozenset({"eval", "exec", "compile", "builtins.eval", "builtins.exec"}),
)
SHELL_SINK = Sink(
    "LLM-03",
    "shell",
    suffix=frozenset(
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
    ),
    any_arg=True,
)
SQL_SINK = Sink(
    "LLM-04",
    "SQL",
    suffix=frozenset({"execute", "executemany", "executescript", "read_sql", "read_sql_query"}),
    base_confidence=0.85,
)
PATH_SINK = Sink(
    "LLM-05",
    "file path",
    exact=frozenset({"open", "Path", "pathlib.Path"}),
    suffix=frozenset(
        {
            "os.remove",
            "os.unlink",
            "os.rename",
            "os.makedirs",
            "os.rmdir",
            "shutil.rmtree",
            "shutil.move",
            "shutil.copy",
            "shutil.copyfile",
        }
    ),
    base_confidence=0.7,
)
URL_SINK = Sink(
    "LLM-06",
    "network request",
    suffix=frozenset(
        {
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "requests.head",
            "requests.patch",
            "httpx.get",
            "httpx.post",
            "httpx.put",
            "httpx.delete",
            "urllib.request.urlopen",
            "urlopen",
        }
    ),
    base_confidence=0.7,
)
MODEL_SINKS = (CODE_SINK, SHELL_SINK, SQL_SINK, PATH_SINK, URL_SINK)


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
    label: str
    owner: str
    trace: tuple[str, ...]
    confidence: float


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _matches(name: str | None, names: frozenset[str] | set[str] | list[str] | tuple[str, ...]) -> bool:
    if not name:
        return False
    return any(name == n or name.endswith("." + n) for n in names)


def _sink_matches(name: str | None, sink: Sink) -> bool:
    if not name:
        return False
    return name in sink.exact or _matches(name, sink.suffix)


class _Scope:
    def __init__(self, cfg: Config, env: dict[str, Taint], kind: str, owner: str) -> None:
        self.cfg = cfg
        self.env = env
        self.kind = kind
        self.owner = owner
        self.sysenv: dict[str, Taint] = {}
        self.flows: list[Flow] = []
        self.defs: list[ast.AST] = []
        self.model_sources = list(MODEL_SOURCE_SUFFIXES) + cfg.taint_sources
        self.sanitizers = set(SANITIZERS) | set(cfg.taint_sanitizers)
        self.extra_shell = frozenset(cfg.taint_sinks)

    # -- expressions -------------------------------------------------------
    def taint_of(self, node: ast.AST | None) -> Taint | None:
        if node is None:
            return None
        if isinstance(node, ast.Await):
            return self.taint_of(node.value)
        if isinstance(node, ast.Name):
            return self.env.get(node.id)
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
            if self.kind == "untrusted" and isinstance(node, ast.Attribute):
                name = dotted_name(node)
                if _matches(name, UNTRUSTED_ATTRS):
                    return Taint((f"line {node.lineno}: untrusted input {name}",), True)
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

    def is_model_call(self, name: str | None, func: ast.AST) -> bool:
        if _matches(name, self.model_sources):
            return True
        if isinstance(func, ast.Attribute) and func.attr in LLM_METHODS:
            return bool(LLM_RECEIVER.search(dotted_name(func.value) or ""))
        return False

    def _call_taint(self, node: ast.Call) -> Taint | None:
        name = dotted_name(node.func)
        if _matches(name, self.sanitizers):
            return None
        if self.kind == "model" and self.is_model_call(name, node.func):
            return Taint((f"line {node.lineno}: model output from {name or 'model call'}()",), True)
        if self.kind == "untrusted" and _matches(name, UNTRUSTED_CALLS):
            return Taint((f"line {node.lineno}: untrusted input from {name}()",), True)
        if isinstance(node.func, ast.Attribute):
            inherited = self.taint_of(node.func.value)
            if inherited:
                return inherited
        if _matches(name, PASSTHROUGH_CALLS):
            return self._first(node.args)
        if isinstance(node.func, ast.Attribute) and node.func.attr in STRING_BUILDERS:
            return self._first([*node.args, *[k.value for k in node.keywords]])
        return None

    # -- sinks -------------------------------------------------------------
    def check_sinks(self, root: ast.AST) -> None:
        for node in ast.walk(root):
            if not isinstance(node, ast.Call):
                continue
            name = dotted_name(node.func)
            if self.kind == "untrusted":
                self._check_prompt_call(node, name)
                continue
            for sink in MODEL_SINKS:
                extra = sink is SHELL_SINK and _matches(name, self.extra_shell)
                if _sink_matches(name, sink) or extra:
                    self._check_sink(node, name, sink)
                    break

    def _check_sink(self, node: ast.Call, name: str | None, sink: Sink) -> None:
        if sink.any_arg:
            args = list(node.args) + [k.value for k in node.keywords]
        else:
            args = node.args[:1]
            args += [k.value for k in node.keywords if k.arg in ("url", "path", "sql", "query")]
        for arg in args:
            taint = self.taint_of(arg)
            if not taint:
                continue
            call = name or "call"
            trace = taint.step(f"line {node.lineno}: passed to {call}()").trace
            confidence = sink.base_confidence if taint.certain else min(sink.base_confidence, 0.55)
            rule_id = "LLM-08" if self.kind == "tool" else sink.rule_id
            if self.kind == "tool" and sink.rule_id in ("LLM-02", "LLM-03"):
                confidence = 0.95
            self._add(rule_id, node, call, sink.label, trace, confidence)
            return

    def _check_prompt_call(self, node: ast.Call, name: str | None) -> None:
        if not self.is_model_call(name, node.func):
            return
        call = name or "model call"
        for kw in node.keywords:
            if kw.arg in SYSTEM_KWARGS:
                taint = self.taint_of(kw.value)
                if taint:
                    self._report_prompt(node, call, taint, "system prompt", 0.9)
                    return
        exprs = list(node.args) + [k.value for k in node.keywords]
        for expr in exprs:
            taint = self._system_taint(expr)
            if taint:
                self._report_prompt(node, call, taint, "system prompt", 0.9)
                return
        for kw in node.keywords:
            if kw.arg in PROMPT_KWARGS and isinstance(kw.value, (ast.JoinedStr, ast.BinOp)):
                taint = self.taint_of(kw.value)
                if taint:
                    self._report_prompt(node, call, taint, "prompt string", 0.5)
                    return

    def _report_prompt(self, node: ast.Call, call: str, taint: Taint, label: str, conf: float) -> None:
        trace = taint.step(f"line {node.lineno}: placed in the {label} of {call}()").trace
        self._add("LLM-01", node, call, label, trace, conf if taint.certain else min(conf, 0.5))

    def _system_taint(self, expr: ast.AST) -> Taint | None:
        if isinstance(expr, ast.Name):
            return self.sysenv.get(expr.id)
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Dict):
                pairs = {
                    k.value: v for k, v in zip(sub.keys, sub.values, strict=False) if isinstance(k, ast.Constant)
                }
                role, content = pairs.get("role"), pairs.get("content")
                if (
                    isinstance(role, ast.Constant)
                    and role.value in ("system", "developer")
                    and content is not None
                ):
                    taint = self.taint_of(content)
                    if taint:
                        return taint
            elif (
                isinstance(sub, ast.Tuple)
                and len(sub.elts) == 2
                and isinstance(sub.elts[0], ast.Constant)
                and sub.elts[0].value == "system"
            ):
                taint = self.taint_of(sub.elts[1])
                if taint:
                    return taint
            elif isinstance(sub, ast.Call) and (dotted_name(sub.func) or "").endswith("SystemMessage"):
                taint = self._first([*sub.args, *[k.value for k in sub.keywords]])
                if taint:
                    return taint
        return None

    def _add(self, rule_id: str, node: ast.Call, sink: str, label: str,
             trace: tuple[str, ...], confidence: float) -> None:
        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        self.flows.append(
            Flow(rule_id, node.lineno, end, sink, label, self.owner, trace, confidence)
        )

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
                self._bind_system(target, node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            self._bind(node.target, self.taint_of(node.value), node.lineno)
            self._bind_system(node.target, node.value)
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

    def _bind_system(self, target: ast.AST, value: ast.AST) -> None:
        if self.kind != "untrusted" or not isinstance(target, ast.Name):
            return
        taint = self._system_taint(value)
        if taint:
            self.sysenv[target.id] = taint
        else:
            self.sysenv.pop(target.id, None)

    def _bind(self, target: ast.AST, taint: Taint | None, line: int) -> None:
        if isinstance(target, ast.Name):
            if taint:
                self.env[target.id] = taint.step(f"line {line}: stored in `{target.id}`")
            else:
                self.env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind(element, taint, line)


def _decorator_last_name(dec: ast.expr) -> str:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return ""


def is_tool_function(func: ast.FunctionDef | ast.AsyncFunctionDef, tool_names: set[str]) -> bool:
    if func.name in tool_names:
        return True
    return any(_decorator_last_name(d) in TOOL_DECORATORS for d in func.decorator_list)


def collect_tool_names(tree: ast.Module) -> set[str]:
    """Names of functions registered as tools through factory calls like ``Tool(func=f)``."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func) or ""
        if not any(name == f or name.endswith(f) for f in TOOL_FACTORIES):
            continue
        for kw in node.keywords:
            if kw.arg in ("func", "coroutine", "fn") and isinstance(kw.value, ast.Name):
                names.add(kw.value.id)
        if node.args and isinstance(node.args[0], ast.Name) and name.endswith(("from_function", "from_defaults")):
            names.add(node.args[0].id)
    return names


def _initial_env(kind: str, func: ast.FunctionDef | ast.AsyncFunctionDef,
                 tool_names: set[str]) -> dict[str, Taint]:
    args = func.args
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    env: dict[str, Taint] = {}
    if kind == "tool":
        if not is_tool_function(func, tool_names):
            return env
        for arg in params:
            if arg.arg not in NON_MODEL_PARAMS:
                note = f"line {func.lineno}: tool argument `{arg.arg}` is chosen by the model"
                env[arg.arg] = Taint((note,), True)
        return env
    pattern = MODEL_PARAM if kind == "model" else UNTRUSTED_PARAM
    what = "model output" if kind == "model" else "untrusted input"
    for arg in params:
        if pattern.match(arg.arg):
            note = f"line {func.lineno}: parameter `{arg.arg}` looks like {what}"
            env[arg.arg] = Taint((note,), False)
    return env


def find_flows(tree: ast.Module, cfg: Config) -> list[Flow]:
    """Return every taint flow found in the module, across all three kinds."""
    tool_names = collect_tool_names(tree)
    flows: list[Flow] = []
    for kind in ("model", "untrusted", "tool"):
        queue: list[ast.AST] = [tree]
        while queue:
            node = queue.pop(0)
            if isinstance(node, ast.Module):
                scope = _Scope(cfg, {}, kind, "<module>")
            else:
                scope = _Scope(cfg, _initial_env(kind, node, tool_names), kind, node.name)  # type: ignore[arg-type,attr-defined]
            scope.run(node.body)  # type: ignore[attr-defined]
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
