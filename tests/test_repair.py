
import pytest
from conftest import ScriptedProvider
from typer.testing import CliRunner

from slopguard.cli import app
from slopguard.config import Config
from slopguard.context import build_project
from slopguard.models import Severity
from slopguard.repair import judge_candidate, repair
from slopguard.rules import all_rules

BAD = (
    "def solve(client, question):\n"
    "    reply = client.messages.create(model='m', max_tokens=50, messages=[])\n"
    "    return eval(reply.content[0].text)\n"
)
FIXED = (
    "import json\n\n\n"
    "def solve(client, question):\n"
    "    reply = client.messages.create(model='m', max_tokens=50, messages=[])\n"
    "    return json.loads(reply.content[0].text)\n"
)


def fenced(code: str) -> str:
    return f"Here you go\n```python\n{code}```"


@pytest.fixture
def setup(tmp_path):
    rules = [r for r in all_rules() if r.meta.module in ("llm", "inc", "sec")]
    project = build_project(tmp_path, Config(), network=False)
    return rules, project


def run(setup, provider, source=BAD, **kwargs):
    rules, project = setup
    return repair({"app.py": source}, rules, project, provider, **kwargs)


def test_accepts_a_fix_that_removes_the_serious_finding(setup):
    provider = ScriptedProvider(fenced(FIXED))
    result = run(setup, provider)
    assert result.current["app.py"] == FIXED and result.stopped == "no serious findings left"
    assert [a.accepted for r in result.rounds for a in r.attempts] == [True]
    assert "LLM-02" in provider.calls[0][1] and "line 3" in provider.calls[0][1]
    assert "-    return eval" in result.diff() and "+    return json.loads" in result.diff()


def test_clean_code_never_calls_the_model(setup):
    provider = ScriptedProvider()
    result = run(setup, provider, source=FIXED)
    assert provider.calls == [] and result.rounds == [] and result.changed_files() == []


@pytest.mark.parametrize(
    "answer,note",
    [
        ("no code at all", "no Python code block"),
        (fenced("def solve(:\n"), "does not parse"),
        (fenced(BAD), "unchanged"),
        (fenced("x = 1\n"), "truncated"),
        (fenced(BAD + "# a harmless comment\n"), "does not reduce"),
        (fenced(BAD.replace("eval(", "exec(")), "introduces LLM-02"),
    ],
)
def test_bad_proposals_are_rejected_and_nothing_changes(setup, answer, note):
    result = run(setup, ScriptedProvider(answer), max_rounds=1)
    attempt = result.rounds[0].attempts[0]
    assert not attempt.accepted and note in attempt.note
    assert result.current["app.py"] == BAD and result.stopped == "no progress in the last round"


def test_a_fix_that_adds_a_new_serious_problem_is_rejected(setup):
    worse = FIXED + "\nKEY = 'sk-" + "Zz9yXw8vUt7sRq6pOn5mLk4jIh3gFe2dCb1a" + "'\n"
    result = run(setup, ScriptedProvider(fenced(worse)), max_rounds=1)
    attempt = result.rounds[0].attempts[0]
    assert not attempt.accepted and "SEC-01" in attempt.note


def test_round_limit_and_progress(setup):
    two = BAD + "\n\ndef other(client):\n    return eval(client.messages.create(model='m', max_tokens=5, messages=[]).content[0].text)\n"
    half = two.replace("    return eval(reply.content[0].text)", "    return reply.content[0].text")
    done = half.replace("return eval(client.messages", "return (client.messages").replace("[0].text)\n", "[0].text)\n")
    provider = ScriptedProvider(fenced(half), fenced(done))
    result = run(setup, provider, source=two, max_rounds=2)
    assert len(result.rounds) == 2 and result.rounds[0].accepted == 1
    assert result.stopped in ("no serious findings left", "round limit reached")


def test_model_failure_is_reported_not_raised(setup):
    class Broken:
        name, model = "broken", "x"

        def complete(self, system, prompt, max_tokens=1024):
            from slopguard.llm import LLMError

            raise LLMError("boom")

    result = run(setup, Broken(), max_rounds=1)
    assert "model call failed: boom" in result.rounds[0].attempts[0].note


def test_oversized_files_are_not_sent(setup):
    big = BAD + "# padding\n" * 4000
    provider = ScriptedProvider()
    result = run(setup, provider, source=big, max_rounds=1)
    assert provider.calls == [] and "too large" in result.rounds[0].attempts[0].note


def test_judge_candidate_reports_counts(setup):
    from slopguard.engine import scan_text

    rules, project = setup
    before = scan_text("app.py", BAD, rules, project)
    ok, note, after = judge_candidate("app.py", BAD, FIXED, before, rules, project, Severity.HIGH)
    assert ok and "1 -> 0" in note and after == []


# -- CLI ------------------------------------------------------------------------------------


@pytest.fixture
def repo(tmp_path, fake_llm, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    (tmp_path / "slopguard.toml").write_text(
        f'[llm]\nprovider = "anthropic"\nmodel = "m"\nbase_url = "{fake_llm["url"]}"\n')
    (tmp_path / "app.py").write_text(BAD)
    fake_llm["answers"].append(fenced(FIXED))
    return tmp_path


def test_cli_fix_is_a_dry_run_by_default(repo, fake_llm):
    result = CliRunner().invoke(app, ["fix", str(repo), "--no-network"])
    assert "round 1: app.py: accepted" in result.stdout and "+    return json.loads" in result.stdout
    assert "dry run" in result.stdout and result.exit_code == 0
    assert (repo / "app.py").read_text() == BAD


def test_cli_fix_apply_writes_after_confirmation(repo):
    declined = CliRunner().invoke(app, ["fix", str(repo), "--no-network", "--apply"], input="n\n")
    assert "nothing written" in declined.stdout and (repo / "app.py").read_text() == BAD


def test_cli_fix_apply_yes(repo):
    result = CliRunner().invoke(app, ["fix", str(repo), "--no-network", "--apply", "--yes"])
    assert "wrote 1 file" in result.stdout and (repo / "app.py").read_text() == FIXED


def test_cli_fix_needs_a_provider(tmp_path):
    (tmp_path / "app.py").write_text(BAD)
    result = CliRunner().invoke(app, ["fix", str(tmp_path)])
    assert result.exit_code == 2 and "no LLM provider" in result.output
