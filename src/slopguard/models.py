"""Core data types: severities, findings and rule metadata."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from slopguard.context import FileContext


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    module: str
    severity: Severity
    explanation: str
    fix: str
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    status: str = "stable"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    path: str
    line: int
    end_line: int
    confidence: float
    explanation: str
    fix: str
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    excerpt: str = ""
    trace: tuple[str, ...] = field(default_factory=tuple)

    def fingerprint(self) -> str:
        """Stable identity used by baselines; independent of line numbers."""
        raw = f"{self.rule_id}\x1f{self.path}\x1f{self.excerpt.strip()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "confidence": round(self.confidence, 2),
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "end_line": self.end_line,
            "excerpt": self.excerpt,
            "explanation": self.explanation,
            "fix": self.fix,
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "trace": list(self.trace),
            "fingerprint": self.fingerprint(),
        }


def finding_from_meta(
    meta: RuleMeta,
    path: str,
    line: int,
    message: str,
    *,
    end_line: int | None = None,
    confidence: float = 0.9,
    excerpt: str = "",
    trace: tuple[str, ...] = (),
    severity: Severity | None = None,
) -> Finding:
    """Build a finding for rules that do not run inside a single parsed file."""
    return Finding(
        rule_id=meta.id,
        severity=meta.severity if severity is None else severity,
        message=message,
        path=path,
        line=line,
        end_line=end_line or line,
        confidence=confidence,
        explanation=meta.explanation,
        fix=meta.fix,
        cwe=meta.cwe,
        owasp=meta.owasp,
        excerpt=excerpt,
        trace=trace,
    )


class Rule(ABC):
    """Base class for rules. Subclasses set ``meta`` and implement ``check``."""

    meta: RuleMeta
    file_types: tuple[str, ...] = (".py",)

    @abstractmethod
    def check(self, ctx: FileContext) -> Iterable[Finding]:
        """Yield findings for one file."""
