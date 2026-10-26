from pathlib import Path

from typer.testing import CliRunner

from slopguard.bench import RuleScore, parse_expected, run_benchmark
from slopguard.cli import app

CORPUS = Path(__file__).resolve().parent.parent / "benchmarks" / "corpus"


def test_parse_expected_labels():
    assert parse_expected("# expect: LLM-02, inc-04\nx = 1\n") == {"LLM-02", "INC-04"}
    assert parse_expected("# expect: none\n") == set()
    assert parse_expected("x = 1\n") is None


def test_rule_score_math():
    score = RuleScore(tp=3, fp=1, fn=2)
    assert score.precision == 0.75 and score.recall == 0.6
    assert round(score.f1, 3) == 0.667
    assert RuleScore().precision is None


def test_tiny_corpus_counts_true_and_false_positives(tmp_path):
    (tmp_path / "hit.py").write_text("# expect: INC-02\ndef f():\n    pass\n")
    (tmp_path / "miss.py").write_text("# expect: INC-04\nx = 1\n")
    (tmp_path / "noise.py").write_text("# expect: none\ndef g():\n    pass\n")
    (tmp_path / "skip.py").write_text("x = 1\n")
    report = run_benchmark(tmp_path)
    assert report.files == 3 and report.unlabelled == ["skip.py"]
    inc02, inc04 = report.scores["INC-02"], report.scores["INC-04"]
    assert (inc02.tp, inc02.fp, inc02.fn) == (1, 1, 0)
    assert (inc04.tp, inc04.fp, inc04.fn) == (0, 0, 1)
    assert any("false positive" in m and "noise.py" in m for m in report.mismatches)


def test_shipped_corpus_meets_the_phase_2_gate():
    """Gate 2: every rule scores at least 0.85 precision on the shipped corpus."""
    report = run_benchmark(CORPUS)
    assert report.files >= 30
    assert report.failing(min_precision=0.85, min_recall=0.0) == []
    llm_rules = {r for r in report.scores if r.startswith("LLM-")}
    assert {"LLM-01", "LLM-02", "LLM-03", "LLM-04", "LLM-05", "LLM-06"} <= llm_rules


def test_known_gaps_are_labelled_and_missed():
    report = run_benchmark(CORPUS)
    missed = {m.split()[-2] for m in report.mismatches if m.startswith("false negative")}
    assert {"vulnerable/gap_cross_function.py", "vulnerable/gap_instance_attribute.py"} <= missed


def test_bench_command_exit_codes_and_json(tmp_path):
    runner = CliRunner()
    ok = runner.invoke(app, ["bench", str(CORPUS), "--min-precision", "0.85"])
    assert ok.exit_code == 0 and "overall" in ok.stdout
    strict = runner.invoke(app, ["bench", str(CORPUS), "--min-recall", "1.0"])
    assert strict.exit_code == 1
    data = runner.invoke(app, ["bench", str(CORPUS), "--format", "json"]).stdout
    assert '"overall"' in data
    assert runner.invoke(app, ["bench", str(tmp_path / "missing")]).exit_code == 2
