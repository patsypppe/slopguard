"""SEC-01: hardcoded secrets and API keys."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable

from slopguard.context import FileContext
from slopguard.models import Finding, Rule, RuleMeta, Severity
from slopguard.rules import register

PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}")),
    (
        "private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    ),
)

GENERIC_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b([\w.]*?(?:api[_-]?key|secret|token|passwd|password|auth[_-]?key|access[_-]?key)\w*)
    \s*[:=]\s*(["'])([^"'\s]{12,})\2
    """
)
PLACEHOLDER_HINTS = (
    "example", "placeholder", "changeme", "change-me", "your", "xxxx", "dummy", "sample",
    "fake", "redacted", "insert", "<", ">", "${", "{{", "...", "todo", "none", "null",
)
MIN_ENTROPY = 3.0
# A name like ANTHROPIC_API_KEY or "llm.token_count" is a label, not a credential.
NON_SECRET_NAME = re.compile(
    r"(?i)(_env|_env_var|_name|_header|_field|_prefix|_path|_url|_type|_file|_param|_attr|_label)$"
)
BASE64_BODY = re.compile(r"[A-Za-z0-9+/=]{40,}")
SYMBOLS = frozenset("!@#$%^&*()+=[]{}|;<>?~")


def _entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def _mask(value: str) -> str:
    return f"{value[:4]}…({len(value)} chars)"


def _looks_real(value: str, name: str = "") -> bool:
    """Heuristic: a credential has a digit or symbol; names, paths and env-var labels do not."""
    lowered = value.lower()
    if any(hint in lowered for hint in PLACEHOLDER_HINTS) or NON_SECRET_NAME.search(name):
        return False
    if value.startswith(("/", "http")) or "://" in value:
        return False  # an endpoint or URL
    if re.sub(r"[-_.]", "", lowered) == re.sub(r"[-_.]", "", name.lower().rsplit(".", 1)[-1]):
        return False  # the value just repeats the variable's name
    if not (any(c.isdigit() for c in value) or SYMBOLS & set(value)):
        return False
    return _entropy(value) >= MIN_ENTROPY


@register
class HardcodedSecret(Rule):
    meta = RuleMeta(
        id="SEC-01",
        title="Hardcoded secret or API key",
        module="sec",
        severity=Severity.CRITICAL,
        explanation=(
            "Credentials committed to source are copied into every clone, build and log. "
            "AI assistants often paste example keys that turn out to be real ones."
        ),
        fix="Remove the value, rotate the credential, and read it from an environment variable "
        "or a secrets manager.",
        cwe=("CWE-798",),
    )
    file_types = (".py", ".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".sh")

    def check(self, ctx: FileContext) -> Iterable[Finding]:
        for number, text in enumerate(ctx.lines, start=1):
            hit = self._match(text)
            if hit is None:
                continue
            label, secret = hit
            if label == "private key block" and not self._has_key_body(ctx.lines, number):
                continue
            masked = text.replace(secret, _mask(secret)).strip()
            yield ctx.make_finding(
                self.meta,
                number,
                f"Hardcoded {label} ({_mask(secret)})",
                excerpt=masked,
                confidence=0.95 if label != "credential assignment" else 0.7,
            )

    @staticmethod
    def _has_key_body(lines: list[str], number: int) -> bool:
        """A key block only counts when base64 key material follows the header."""
        window = lines[number - 1 : number + 3]
        header_end = window[0].find("PRIVATE KEY")
        window[0] = window[0][header_end:] if header_end != -1 else window[0]
        return any(BASE64_BODY.search(line) for line in window)

    @staticmethod
    def _match(text: str) -> tuple[str, str] | None:
        for label, pattern in PROVIDER_PATTERNS:
            found = pattern.search(text)
            if found and "example" not in found.group(0).lower():
                return label, found.group(0)
        generic = GENERIC_ASSIGNMENT.search(text)
        if generic and "example" not in text.lower() and _looks_real(generic.group(3), generic.group(1)):
            return "credential assignment", generic.group(3)
        return None
