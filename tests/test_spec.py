import json

from conftest import ScriptedProvider
from typer.testing import CliRunner

from slopguard.cli import app
from slopguard.spec import parse_spec, verdict_findings, verify_spec

SPEC = """# Invoice tool

## Requirements
- `parse_invoice()` reads an invoice file and returns the total
- The CLI must support a `--json` output flag
- Totals should be rounded to two decimals
- Send an email reminder when the invoice is overdue

## Non-goals
- Supporting scanned images
"""

CODE = '''
def parse_invoice(path):
    pass

def format_total(value):
    """Round totals to two decimals."""
    return round(value, 2)

def main(args):
    if args.json:
        print("{}")
'''


def test_parse_spec_bullets_and_skips():
    reqs = parse_spec(SPEC)
    assert [r.id for r in reqs] == ["R1", "R2", "R3", "R4"]
    assert reqs[0].identifiers == ("parse_invoice",) and reqs[1].identifiers == ("--json",)
    assert all("scanned" not in r.text for r in reqs)  # non-goals are skipped


def test_parse_spec_sentences_checkboxes_and_fences():
    text = "The service must log every request. It is fast.\n- [ ] Users can reset passwords\n```\n- not a requirement here\n```\n"
    reqs = parse_spec(text)
    assert [r.text for r in reqs] == ["The service must log every request.", "Users can reset passwords"]


def test_heuristic_verdicts():
    verdicts = {v.requirement.id: v for v in verify_spec(SPEC, [("inv.py", CODE)])}
    assert verdicts["R1"].status == "partial" and "empty" in verdicts["R1"].reason
    assert verdicts["R2"].status == "met"
    assert verdicts["R3"].status == "met" and verdicts["R3"].confidence < 0.6
    assert verdicts["R4"].status == "missing"
    assert all(v.source == "heuristic" for v in verdicts.values())


def test_missing_identifier_is_missing_with_high_confidence():
    (verdict,) = verify_spec("- `export_csv()` writes all rows to a CSV file", [("a.py", "x = 1\n")])
    assert verdict.status == "missing" and verdict.confidence >= 0.8


def test_tests_are_mentioned_but_do_not_count_as_code():
    files = [("a.py", "x = 1\n"), ("tests/test_a.py", "def test_overdue_reminder_email():\n    assert True\n")]
    (verdict,) = verify_spec("- Send an overdue reminder email to the customer", files)
    assert verdict.status == "missing" and "tests" in verdict.reason


def test_llm_judgement_replaces_heuristic():
    provider = ScriptedProvider('{"status": "partial", "reason": "returns None instead of a total", "lines": [2]}')
    spec = "- `parse_invoice()` reads an invoice file and returns the total\n"
    (verdict,) = verify_spec(spec, [("inv.py", CODE)], provider)
    assert verdict.source == "llm" and verdict.status == "partial"
    assert "returns None" in verdict.reason
    assert "def parse_invoice" in provider.calls[0][1]


def test_unusable_llm_answer_falls_back_to_heuristic():
    provider = ScriptedProvider("I cannot decide")
    spec = "- `parse_invoice()` reads an invoice file and returns the total\n"
    (verdict,) = verify_spec(spec, [("inv.py", CODE)], provider)
    assert verdict.source == "heuristic" and "LLM answer unusable" in verdict.reason


def test_llm_is_not_called_when_nothing_matches():
    provider = ScriptedProvider()
    (verdict,) = verify_spec("- Support exporting to a spreadsheet format", [("a.py", "x = 1\n")], provider)
    assert verdict.status == "missing" and provider.calls == []


def test_llm_extracts_requirements_from_prose():
    provider = ScriptedProvider('{"requirements": ["Users can log in", "Passwords are hashed"]}')
    verdicts = verify_spec("We need a login system where passwords are safely stored.", [("a.py", "x = 1\n")], provider)
    assert [v.requirement.text for v in verdicts] == ["Users can log in", "Passwords are hashed"]


def test_findings_only_for_unmet_requirements():
    verdicts = verify_spec(SPEC, [("inv.py", CODE)])
    findings = verdict_findings("SPEC.md", verdicts)
    by_req = {f.message.split()[0]: f for f in findings}
    assert set(by_req) == {"R1", "R4"}
    assert by_req["R1"].severity.label == "medium" and by_req["R4"].severity.label == "high"
    assert by_req["R4"].rule_id == "SPC-02" and by_req["R4"].path == "SPEC.md"


def test_cli_scan_with_spec(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0"\n')
    (tmp_path / "inv.py").write_text(CODE)
    (tmp_path / "SPEC.md").write_text(SPEC)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-network", "--spec", str(tmp_path / "SPEC.md"),
                                 "--format", "json", "--rule", "SPC-02"])
    data = json.loads(result.stdout)
    assert result.exit_code == 1
    assert [f["message"].split()[0] for f in data["findings"]] == ["R1", "R4"]
    assert "name matching only" in result.output


def test_cli_spec_errors(tmp_path):
    runner = CliRunner()
    (tmp_path / "a.py").write_text("x = 1\n")
    assert runner.invoke(app, ["scan", str(tmp_path), "--spec", str(tmp_path / "nope.md")]).exit_code == 2
    (tmp_path / "empty.md").write_text("# Nothing\njust prose\n")
    assert runner.invoke(app, ["scan", str(tmp_path), "--spec", str(tmp_path / "empty.md")]).exit_code == 2
    (tmp_path / "SPEC.md").write_text("- something must happen here\n")
    no_llm = runner.invoke(app, ["scan", str(tmp_path), "--spec", str(tmp_path / "SPEC.md"), "--llm"])
    assert no_llm.exit_code == 2 and "no LLM provider" in no_llm.output


def test_cli_spec_with_llm_over_http(tmp_path, fake_llm, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    (tmp_path / "slopguard.toml").write_text(
        f'[llm]\nprovider = "anthropic"\nmodel = "m"\nbase_url = "{fake_llm["url"]}"\n')
    (tmp_path / "inv.py").write_text(CODE)
    (tmp_path / "SPEC.md").write_text("- `parse_invoice()` reads an invoice file and returns the total\n")
    fake_llm["answers"].append('{"status": "missing", "reason": "stub only"}')
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "--no-network", "--spec", str(tmp_path / "SPEC.md"),
                                      "--llm", "--rule", "SPC-02", "--format", "json"])
    assert "sending requirement text" in result.output
    assert json.loads(result.stdout)["findings"][0]["message"].endswith("stub only")
    assert fake_llm["requests"][0]["path"] == "/v1/messages"
