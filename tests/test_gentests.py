import json

import pytest
from conftest import ScriptedProvider
from typer.testing import CliRunner

from slopguard.cli import app
from slopguard.gentests import (
    apply_test_results,
    generate_tests,
    interface_summary,
    validate_test_code,
)
from slopguard.llm import LLMError
from slopguard.sandbox import TestRun
from slopguard.spec import parse_spec, verify_spec

CODE = '''
def round_total(value: float) -> float:
    """Round a total to two decimals."""
    return round(value, 2)

class Invoice:
    def total(self) -> float:
        return 1.0
'''
SPEC = "- Totals should be rounded to two decimals\n- `Invoice.total()` returns a number\n"
GOOD_TEST = (
    "```python\nfrom mod import round_total\n\n"
    "def test_r1_rounds():\n    assert round_total(1.234) == 1.23\n\n"
    "def test_r2_total_is_number():\n    from mod import Invoice\n    assert isinstance(Invoice().total(), float)\n```"
)


def test_interface_summary_lists_public_signatures_only():
    text = interface_summary([("mod.py", CODE + "\ndef _private():\n    pass\n")])
    assert "def round_total(value: float) -> float  # Round a total to two decimals" in text
    assert "class Invoice" in text and "    def total(self) -> float" in text and "_private" not in text


def test_generate_tests_returns_validated_code():
    provider = ScriptedProvider(GOOD_TEST)
    code = generate_tests(parse_spec(SPEC), [("mod.py", CODE)], provider)
    assert "def test_r1_rounds" in code
    assert "R1: Totals should be rounded" in provider.calls[0][1]
    assert "def round_total" in provider.calls[0][1]


@pytest.mark.parametrize(
    "bad,message",
    [
        ("def test_x(:\n", "do not parse"),
        ("x = 1\n", "no test functions"),
        ("import subprocess\n\ndef test_x():\n    pass\n", "not allowed"),
        ("from urllib.request import urlopen\n\ndef test_x():\n    pass\n", "not allowed"),
    ],
)
def test_unsafe_or_broken_generated_tests_are_rejected(bad, message):
    with pytest.raises(LLMError, match=message):
        validate_test_code(bad)


def test_answer_without_code_block_is_rejected():
    with pytest.raises(LLMError, match="no Python code block"):
        generate_tests(parse_spec(SPEC), [("mod.py", CODE)], ScriptedProvider("sorry, I can't"))


def test_results_update_verdicts():
    verdicts = verify_spec(SPEC, [("mod.py", CODE)])
    run = TestRun("docker", 1, "", False, {
        "t.test_gen::test_r1_rounds": "passed",
        "t.test_gen::test_r2_total_is_number": "failed",
    })
    updated = {v.requirement.id: v for v in apply_test_results(verdicts, run)}
    assert updated["R1"].status == "met" and updated["R1"].source == "tests"
    assert updated["R2"].status != "met" and "test_r2_total_is_number" in updated["R2"].reason


def test_no_results_leaves_verdicts_alone():
    verdicts = verify_spec(SPEC, [("mod.py", CODE)])
    assert apply_test_results(verdicts, TestRun("local", 2, "", False, {})) == verdicts


def test_cli_gen_tests_end_to_end(tmp_path, fake_llm, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    (tmp_path / "slopguard.toml").write_text(
        f'[llm]\nprovider = "openai"\nmodel = "m"\nbase_url = "{fake_llm["url"]}"\n'
        '[sandbox]\nbackend = "local"\ntimeout = 60\n')
    (tmp_path / "mod.py").write_text(CODE)
    (tmp_path / "SPEC.md").write_text(SPEC)
    fake_llm["answers"].append(GOOD_TEST)
    result = CliRunner().invoke(app, ["gen-tests", "--spec", str(tmp_path / "SPEC.md"), str(tmp_path), "--run"])
    written = tmp_path / "tests" / "generated" / "test_spec_requirements.py"
    assert written.exists() and "test_r1_rounds" in written.read_text()
    assert "sandbox: local" in result.stdout
    assert result.exit_code == 0, result.output
    row = [line for line in result.stdout.splitlines() if "R1" in line]
    assert row and "met" in row[0] and "tests" in row[0]
    assert json.dumps(fake_llm["requests"][0]["body"]).count("Totals should be rounded") >= 1


def test_cli_gen_tests_without_provider(tmp_path):
    (tmp_path / "mod.py").write_text(CODE)
    (tmp_path / "SPEC.md").write_text(SPEC)
    result = CliRunner().invoke(app, ["gen-tests", "--spec", str(tmp_path / "SPEC.md"), str(tmp_path)])
    assert result.exit_code == 2 and "no LLM provider" in result.output
