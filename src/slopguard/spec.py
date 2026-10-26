"""Check code against a written spec: requirements in, met/partial/missing out.

Two layers. The heuristic layer works offline: it reads the spec's bullet points, looks for
backticked names in the code, and matches the remaining words against identifiers, strings
and docstrings. It can say a name exists and has a body; it cannot say the behaviour is
right. The optional LLM layer reads the best-matching code and gives a reasoned verdict.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from slopguard.llm import LLMError, Provider, extract_json
from slopguard.models import Finding, Severity, finding_from_meta
from slopguard.rules.incomplete import HollowFunction, _is_docstring

BULLET = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+(?:\[[ xX]\]\s+)?(.*\S)\s*$")
MODAL = re.compile(r"\b(must|shall|should|needs? to|required to|has to)\b", re.IGNORECASE)
IDENT = re.compile(r"`(-{0,2}[A-Za-z_][\w.-]*)(?:\(\))?`")
SKIP_HEADING = re.compile(r"non-?goals?|out of scope|not in scope|future work|later", re.IGNORECASE)
TEST_PATH = re.compile(r"(^|/)(tests?/|test_[^/]*\.py$|[^/]*_test\.py$)")
STOPWORDS = frozenset(
    ["the", "and", "for", "with", "that", "this", "from", "into", "when", "then", "than", "have", "has", "are", "was", "were", "will", "shall", "must", "should", "can", "not", "any", "all", "each", "every", "its", "their", "there", "which", "while", "where", "what", "who", "whom", "been", "being", "also", "only", "more", "most", "some", "such", "use", "used", "using", "able", "allow", "allows", "via", "per", "without", "within"]
)
MAX_SNIPPET_LINES = 80
MAX_PROMPT_CHARS = 8000


@dataclass(frozen=True)
class Requirement:
    id: str
    text: str
    line: int
    identifiers: tuple[str, ...] = ()


@dataclass(frozen=True)
class Evidence:
    path: str
    line: int
    note: str = ""


@dataclass
class Verdict:
    requirement: Requirement
    status: str  # met | partial | missing
    reason: str
    confidence: float
    source: str  # heuristic | llm
    evidence: list[Evidence] = field(default_factory=list)


# -- spec parsing ---------------------------------------------------------------------------


def parse_spec(text: str) -> list[Requirement]:
    requirements: list[Requirement] = []
    in_fence = False
    skipping = False

    def add(raw: str, number: int) -> None:
        raw = raw.strip()
        if len(raw) >= 12:
            ids = tuple(dict.fromkeys(m.group(1) for m in IDENT.finditer(raw)))
            requirements.append(Requirement(f"R{len(requirements) + 1}", raw, number, ids))

    for number, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.lstrip().startswith("#"):
            skipping = bool(SKIP_HEADING.search(line))
            continue
        if skipping:
            continue
        bullet = BULLET.match(line)
        if bullet:
            add(bullet.group(1), number)
        elif MODAL.search(line):
            for sentence in re.split(r"(?<=[.!?])\s+", line.strip()):
                if MODAL.search(sentence):
                    add(sentence, number)
    return requirements


def extract_requirements_with_llm(text: str, provider: Provider) -> list[Requirement]:
    """Ask the model to split a prose spec into short, testable requirements."""
    system = (
        "You turn a software request into atomic, testable requirements. Answer with JSON "
        'only: {"requirements": ["...", "..."]}. One behaviour per item, at most 25 items.'
    )
    data = extract_json(provider.complete(system, text[:MAX_PROMPT_CHARS], 1500))
    items = data.get("requirements", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise LLMError("requirement list was not a JSON array")
    found = [str(item).strip() for item in items if str(item).strip()]
    return [
        Requirement(
            f"R{i}", item, 1, tuple(dict.fromkeys(m.group(1) for m in IDENT.finditer(item)))
        )
        for i, item in enumerate(found[:25], start=1)
    ]


# -- code index -----------------------------------------------------------------------------


@dataclass
class Symbol:
    name: str
    kind: str
    path: str
    line: int
    hollow: bool
    text: str


def _stem(word: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            return word[: -len(suffix)]
    return word


def split_words(name: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [_stem(w.lower()) for w in re.split(r"[^A-Za-z0-9]+", spaced) if len(w) >= 3]


class CodeIndex:
    def __init__(self) -> None:
        self.symbols: list[Symbol] = []
        self.words: dict[str, list[tuple[str, int]]] = {}
        self.test_words: set[str] = set()

    def add_word(self, word: str, path: str, line: int) -> None:
        self.words.setdefault(word, []).append((path, line))

    def find(self, name: str) -> list[Symbol]:
        return [s for s in self.symbols if s.name == name]


def build_index(files: list[tuple[str, str]]) -> CodeIndex:
    index = CodeIndex()
    for rel, source in files:
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            continue
        is_test = bool(TEST_PATH.search(rel))
        lines = source.splitlines()
        for node in ast.walk(tree):
            words: list[tuple[str, int]] = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for w in split_words(node.name):
                    words.append((w, node.lineno))
                if not is_test:
                    hollow = False
                    kind = "class" if isinstance(node, ast.ClassDef) else "function"
                    if kind == "function":
                        body = [s for s in node.body if not _is_docstring(s)]
                        hollow = HollowFunction._hollow_kind(body) is not None
                    end = getattr(node, "end_lineno", node.lineno) or node.lineno
                    snippet = "\n".join(lines[node.lineno - 1 : min(end, node.lineno + MAX_SNIPPET_LINES)])
                    index.symbols.append(Symbol(node.name, kind, rel, node.lineno, hollow, snippet))
            elif isinstance(node, ast.Name):
                words = [(w, node.lineno) for w in split_words(node.id)]
            elif isinstance(node, ast.Attribute):
                words = [(w, node.lineno) for w in split_words(node.attr)]
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) <= 300:
                words = [(_stem(w.lower()), getattr(node, "lineno", 1))
                         for w in re.findall(r"[A-Za-z]{3,}", node.value)]
            for word, line in words:
                if is_test:
                    index.test_words.add(word)
                else:
                    index.add_word(word, rel, line)
    return index


# -- heuristic judging ----------------------------------------------------------------------


def _tokens(req: Requirement) -> list[str]:
    text = IDENT.sub(" ", req.text)
    out = []
    for raw in re.findall(r"[A-Za-z][A-Za-z0-9_]{2,}", text):
        word = _stem(raw.lower())
        if word not in STOPWORDS and len(word) >= 4:
            out.append(word)
    return list(dict.fromkeys(out))


def judge_heuristic(req: Requirement, index: CodeIndex) -> Verdict:
    if req.identifiers:
        return _judge_identifiers(req, index)
    tokens = _tokens(req)
    if len(tokens) < 2:
        return Verdict(req, "partial", "too few distinctive words to match against the code",
                       0.2, "heuristic")
    hits = [t for t in tokens if t in index.words]
    score = len(hits) / len(tokens)
    evidence = _best_locations(hits, index)
    tested = " Words from it appear in tests." if any(t in index.test_words for t in tokens) else ""
    if score >= 0.6:
        status, conf = "met", 0.45
    elif score >= 0.3:
        status, conf = "partial", 0.4
    else:
        status, conf = "missing", 0.4
    reason = f"{len(hits)} of {len(tokens)} key words appear in the code (name match only).{tested}"
    return Verdict(req, status, reason, conf, "heuristic", evidence)


def _judge_identifiers(req: Requirement, index: CodeIndex) -> Verdict:
    found, missing, hollow = [], [], []
    evidence: list[Evidence] = []
    for ident in req.identifiers:
        leaf = ident.lstrip("-").replace("-", "_").split(".")[-1]
        symbols = index.find(leaf)
        if not symbols:
            parts = split_words(leaf)
            if parts and all(w in index.words for w in parts):
                found.append(ident)  # a constant, flag or attribute rather than a def
                path, line = index.words[parts[0]][0]
                evidence.append(Evidence(path, line, "referenced"))
            else:
                missing.append(ident)
            continue
        symbol = symbols[0]
        evidence.append(Evidence(symbol.path, symbol.line, f"defines {symbol.kind} {symbol.name}"))
        (hollow if symbol.hollow else found).append(ident)
    if missing and not found and not hollow:
        names = ", ".join(f"`{m}`" for m in missing)
        return Verdict(req, "missing", f"{names} not found in the scanned code", 0.85, "heuristic")
    if missing or hollow:
        parts = []
        if missing:
            parts.append("not found: " + ", ".join(f"`{m}`" for m in missing))
        if hollow:
            parts.append("defined but empty: " + ", ".join(f"`{h}`" for h in hollow))
        return Verdict(req, "partial", "; ".join(parts), 0.8, "heuristic", evidence)
    return Verdict(req, "met", "named symbols exist and have bodies; behaviour not verified",
                   0.6, "heuristic", evidence)


def _best_locations(hits: list[str], index: CodeIndex, limit: int = 5) -> list[Evidence]:
    scored: dict[tuple[str, int], int] = {}
    for word in hits:
        for location in index.words.get(word, [])[:20]:
            scored[location] = scored.get(location, 0) + 1
    ranked = sorted(scored.items(), key=lambda item: (-item[1], item[0]))
    return [Evidence(path, line, "keyword match") for (path, line), _ in ranked[:limit]]


# -- LLM judging ----------------------------------------------------------------------------


def _candidate_symbols(req: Requirement, index: CodeIndex, limit: int = 4) -> list[Symbol]:
    wanted = set(_tokens(req)) | {w for i in req.identifiers for w in split_words(i.split(".")[-1])}
    scored = []
    for symbol in index.symbols:
        overlap = len(wanted & set(split_words(symbol.name)))
        explicit = symbol.name in {i.split(".")[-1] for i in req.identifiers}
        if overlap or explicit:
            scored.append((overlap + (5 if explicit else 0), symbol))
    scored.sort(key=lambda item: -item[0])
    return [s for _, s in scored[:limit]]


JUDGE_SYSTEM = (
    "You check whether code satisfies one requirement. Be strict: partial means some but not "
    "all of the behaviour is there. Answer with JSON only: "
    '{"status": "met" | "partial" | "missing", "reason": "<one sentence>", "lines": [<ints>]}.'
)


def judge_with_llm(req: Requirement, index: CodeIndex, provider: Provider, fallback: Verdict) -> Verdict:
    candidates = _candidate_symbols(req, index)
    if not candidates:
        return fallback
    blocks, used = [], 0
    for symbol in candidates:
        block = f"### {symbol.path}:{symbol.line} ({symbol.kind} {symbol.name})\n```python\n{symbol.text}\n```"
        if used + len(block) > MAX_PROMPT_CHARS:
            break
        blocks.append(block)
        used += len(block)
    prompt = f"Requirement: {req.text}\n\nCode:\n" + "\n\n".join(blocks)
    try:
        data = extract_json(provider.complete(JUDGE_SYSTEM, prompt, 400))
        status = str(data["status"]).lower()
        if status not in ("met", "partial", "missing"):
            raise LLMError(f"unknown status {status!r}")
        reason = str(data.get("reason", "")).strip() or "no reason given"
    except (LLMError, KeyError, TypeError, AttributeError) as exc:
        fallback.reason = f"LLM answer unusable ({exc}); {fallback.reason}"
        return fallback
    evidence = [Evidence(s.path, s.line, f"reviewed {s.name}") for s in candidates]
    return Verdict(req, status, reason, 0.8, "llm", evidence)


# -- entry points ---------------------------------------------------------------------------


def verify_spec(
    spec_text: str,
    files: list[tuple[str, str]],
    provider: Provider | None = None,
) -> list[Verdict]:
    requirements = parse_spec(spec_text)
    if not requirements and provider is not None:
        requirements = extract_requirements_with_llm(spec_text, provider)
    index = build_index(files)
    verdicts = []
    for req in requirements:
        verdict = judge_heuristic(req, index)
        if provider is not None:
            verdict = judge_with_llm(req, index, provider, verdict)
        verdicts.append(verdict)
    return verdicts


def verdict_findings(spec_path: str, verdicts: list[Verdict]) -> list[Finding]:
    from slopguard.rules import get_rule

    meta = get_rule("SPC-02").meta  # type: ignore[union-attr]
    findings = []
    for verdict in verdicts:
        if verdict.status == "met":
            continue
        severity = Severity.HIGH if verdict.status == "missing" else Severity.MEDIUM
        req = verdict.requirement
        trace = tuple(f"{e.path}:{e.line} {e.note}".strip() for e in verdict.evidence[:5])
        findings.append(
            finding_from_meta(
                meta,
                spec_path,
                req.line,
                f"{req.id} is {verdict.status}: {verdict.reason}",
                confidence=verdict.confidence,
                excerpt=req.text,
                trace=trace,
                severity=severity,
            )
        )
    return findings
