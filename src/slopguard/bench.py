"""Benchmark runner: precision and recall per rule on a labelled corpus.

Every corpus file starts with a label line, ``# expect: RULE-ID[, RULE-ID]`` or
``# expect: none``. A rule counts as a true positive for a file when it is both expected
and reported, a false positive when reported but not expected, and a false negative when
expected but not reported. Scoring is per file, so line-level accuracy is not measured.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from slopguard.config import Config
from slopguard.context import build_project
from slopguard.engine import discover, run_scan
from slopguard.rules import all_rules

LABEL = re.compile(r"^#\s*expect:\s*(.+)$", re.MULTILINE)


@dataclass
class RuleScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        total = self.tp + self.fp
        return self.tp / total if total else None

    @property
    def recall(self) -> float | None:
        total = self.tp + self.fn
        return self.tp / total if total else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)


@dataclass
class BenchReport:
    files: int = 0
    scores: dict[str, RuleScore] = field(default_factory=dict)
    mismatches: list[str] = field(default_factory=list)
    unlabelled: list[str] = field(default_factory=list)

    def overall(self) -> RuleScore:
        total = RuleScore()
        for score in self.scores.values():
            total.tp += score.tp
            total.fp += score.fp
            total.fn += score.fn
        return total

    def failing(self, min_precision: float, min_recall: float) -> list[str]:
        bad = []
        for rule_id, score in sorted(self.scores.items()):
            if score.precision is not None and score.precision < min_precision:
                bad.append(f"{rule_id} precision {score.precision:.2f} < {min_precision:.2f}")
            if score.recall is not None and score.recall < min_recall:
                bad.append(f"{rule_id} recall {score.recall:.2f} < {min_recall:.2f}")
        return bad

    def to_dict(self) -> dict:
        def num(value: float | None) -> float | None:
            return None if value is None else round(value, 3)

        return {
            "files": self.files,
            "rules": {
                rule_id: {
                    "tp": s.tp, "fp": s.fp, "fn": s.fn,
                    "precision": num(s.precision), "recall": num(s.recall), "f1": num(s.f1),
                }
                for rule_id, s in sorted(self.scores.items())
            },
            "overall": {
                "precision": num(self.overall().precision),
                "recall": num(self.overall().recall),
                "f1": num(self.overall().f1),
            },
            "mismatches": self.mismatches,
            "unlabelled": self.unlabelled,
        }


def parse_expected(source: str) -> set[str] | None:
    """Return the labelled rule IDs, an empty set for ``none``, or None if unlabelled."""
    match = LABEL.search(source)
    if not match:
        return None
    ids = {part.strip().upper() for part in match.group(1).split(",") if part.strip()}
    return set() if ids <= {"NONE"} else ids


def run_benchmark(corpus: Path) -> BenchReport:
    corpus = corpus.resolve()
    config = Config()
    project = build_project(corpus, config, network=False)
    rules = all_rules()
    suffixes = {s for r in rules for s in r.file_types}
    files = discover([corpus], corpus, config, suffixes)
    result = run_scan(files, rules, project)

    found: dict[str, set[str]] = {}
    for finding in result.findings:
        found.setdefault(finding.path, set()).add(finding.rule_id)

    report = BenchReport()
    for path in files:
        rel = path.relative_to(corpus).as_posix()
        expected = parse_expected(path.read_text(errors="replace"))
        if expected is None:
            report.unlabelled.append(rel)
            continue
        report.files += 1
        reported = found.get(rel, set())
        for rule_id in expected | reported:
            score = report.scores.setdefault(rule_id, RuleScore())
            if rule_id in expected and rule_id in reported:
                score.tp += 1
            elif rule_id in reported:
                score.fp += 1
                report.mismatches.append(f"false positive  {rel}  {rule_id}")
            else:
                score.fn += 1
                report.mismatches.append(f"false negative  {rel}  {rule_id}")
    report.mismatches.sort()
    return report
