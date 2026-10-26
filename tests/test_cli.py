import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from slopguard.cli import app
from slopguard.rules import all_rules

runner = CliRunner()

DANGEROUS = (
    "def run(client):\n"
    "    r = client.messages.create(model='m', messages=[])\n"
    "    eval(r.content[0].text)\n"
)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0"\n')
    (tmp_path / "bad.py").write_text(DANGEROUS)
    return tmp_path


def invoke(*args: str):
    return runner.invoke(app, list(args))


def test_version_and_help():
    assert "slopguard" in invoke("--version").stdout
    assert "scan" in invoke("--help").stdout


def test_scan_reports_and_exits_1(project):
    result = invoke("scan", str(project), "--no-network")
    assert result.exit_code == 1
    assert "LLM-02" in result.stdout
    assert "bad.py" in result.stdout


def test_scan_clean_project_exits_0(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    result = invoke("scan", str(tmp_path), "--no-network")
    assert result.exit_code == 0
    assert "no findings" in result.stdout


def test_json_output_is_valid_and_versioned(project):
    result = invoke("scan", str(project), "--no-network", "--format", "json")
    data = json.loads(result.stdout)
    assert data["version"] == 1
    assert data["findings"][0]["rule_id"] == "LLM-02"
    assert data["summary"]["by_severity"]["critical"] == 1


def test_sarif_output_structure(project, tmp_path):
    out = tmp_path / "out.sarif"
    result = invoke("scan", str(project), "--no-network", "-f", "sarif", "-o", str(out))
    assert result.exit_code == 1
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {r.meta.id for r in all_rules()}
    res = run["results"][0]
    assert res["ruleId"] == "LLM-02" and res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"] == "LLM-02"


def test_markdown_output(project):
    result = invoke("scan", str(project), "--no-network", "-f", "markdown")
    assert result.stdout.startswith("# slopguard report")
    assert "`LLM-02`" in result.stdout


def test_fail_on_none_and_severity_filter(project):
    assert invoke("scan", str(project), "--no-network", "--fail-on", "none").exit_code == 0
    shown = invoke("scan", str(project), "--no-network", "--severity", "critical")
    assert "LLM-02" in shown.stdout
    low = invoke("scan", str(project), "--no-network", "--module", "inc")
    assert low.exit_code == 0


def test_rule_and_module_filters(project):
    (project / "stub.py").write_text("def f():\n    pass\n")
    only = invoke("scan", str(project), "--no-network", "-r", "INC-02", "-f", "json")
    assert {f["rule_id"] for f in json.loads(only.stdout)["findings"]} == {"INC-02"}


def test_inline_suppression(project):
    lines = DANGEROUS.splitlines()
    lines[2] += "  # slopguard: ignore[LLM-02] reviewed"
    (project / "bad.py").write_text("\n".join(lines) + "\n")
    result = invoke("scan", str(project), "--no-network", "-f", "json")
    assert json.loads(result.stdout)["findings"] == []


def test_suppression_on_previous_line(project):
    lines = DANGEROUS.splitlines()
    lines.insert(2, "    # slopguard: ignore")
    (project / "bad.py").write_text("\n".join(lines) + "\n")
    result = invoke("scan", str(project), "--no-network", "-f", "json")
    assert json.loads(result.stdout)["findings"] == []


def test_baseline_roundtrip(project, tmp_path):
    base = tmp_path / "base.json"
    first = invoke("scan", str(project), "--no-network", "--write-baseline", str(base))
    assert first.exit_code == 1 and base.exists()
    second = invoke("scan", str(project), "--no-network", "--baseline", str(base))
    assert second.exit_code == 0
    (project / "new.py").write_text(DANGEROUS)
    third = invoke("scan", str(project), "--no-network", "--baseline", str(base), "-f", "json")
    assert third.exit_code == 1
    assert [f["path"] for f in json.loads(third.stdout)["findings"]] == ["new.py"]


def test_config_file_exclude_and_module_toggle(project):
    (project / "slopguard.toml").write_text('[scan]\nexclude = ["bad.py"]\n')
    result = invoke("scan", str(project), "--no-network")
    assert result.exit_code == 0
    (project / "slopguard.toml").write_text("[modules]\nllm = false\n")
    assert invoke("scan", str(project), "--no-network").exit_code == 0


def test_pyproject_tool_section(project):
    (project / "pyproject.toml").write_text('[tool.slopguard.scan]\nfail_on = "none"\n')
    assert invoke("scan", str(project), "--no-network").exit_code == 0


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "nope-does-not-exist"],
        ["scan", ".", "--format", "yaml"],
        ["scan", ".", "--severity", "huge"],
        ["scan", ".", "--module", "zzz"],
        ["scan", ".", "--rule", "ZZZ-99"],
        ["explain", "ZZZ-99"],
    ],
)
def test_usage_errors_exit_2(args, project, monkeypatch):
    monkeypatch.chdir(project)
    assert invoke(*args).exit_code == 2


def test_invalid_config_exits_2(project):
    (project / "slopguard.toml").write_text('[modules]\nbogus = true\n')
    result = invoke("scan", str(project), "--no-network")
    assert result.exit_code == 2


def test_rules_explain_init(tmp_path, monkeypatch):
    assert "LLM-02" in invoke("rules").stdout
    assert "Why it matters" in invoke("explain", "llm-02").stdout
    monkeypatch.chdir(tmp_path)
    assert invoke("init").exit_code == 0
    assert (tmp_path / "slopguard.toml").exists()
    assert invoke("init").exit_code == 2
    assert invoke("init", "--force").exit_code == 0


def test_staged_scans_only_staged_files(project, monkeypatch):
    import subprocess

    def git(*a):
        subprocess.run(["git", "-C", str(project), *a], check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    (project / "ok.py").write_text("x = 1\n")
    git("add", "ok.py")
    result = invoke("scan", str(project), "--no-network", "--staged")
    assert result.exit_code == 0
    git("add", "bad.py")
    assert invoke("scan", str(project), "--no-network", "--staged").exit_code == 1


def test_default_excludes_skip_venv(project):
    venv = project / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "evil.py").write_text(DANGEROUS)
    node = project / "node_modules" / "x"
    node.mkdir(parents=True)
    (node / "evil.py").write_text(DANGEROUS)
    data = json.loads(invoke("scan", str(project), "--no-network", "-f", "json").stdout)
    assert [f["path"] for f in data["findings"]] == ["bad.py"]
