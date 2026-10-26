import json
import subprocess

from conftest import ids
from typer.testing import CliRunner

from slopguard.cli import app

BASELINE = {
    f"app/mod{i}.py": (
        "import logging\nimport requests\n\nlog = logging.getLogger(__name__)\n\n\n"
        + "".join(
            f"def get_item_{i}_{j}(x) -> int:\n    log.info('x')\n    return requests.get(x)\n\n\n"
            for j in range(5)
        )
        + f"class Item{i}:\n    pass\n"
    )
    for i in range(5)
}

DRIFTING = (
    "import httpx\n\n\n"
    "def fetchUser(x):\n    print(x)\n    return httpx.get(x)\n\n\n"
    "class user_store:\n    pass\n"
)


def test_naming_library_and_idiom_drift(scan):
    files = {**BASELINE, "app/new.py": DRIFTING}
    findings = [f for f in scan(files, rule_ids=("DRF-01", "DRF-02", "DRF-03")) if f.path == "app/new.py"]
    assert sorted(ids(findings)) == ["DRF-01", "DRF-01", "DRF-02", "DRF-03", "DRF-03"]
    messages = " | ".join(f.message for f in findings)
    assert "fetchUser" in messages and "user_store" in messages
    assert "uses `httpx` for HTTP client, but the repo uses `requests`" in messages
    assert "print()" in messages and "return type hints" in messages


def test_conforming_code_has_no_drift(scan):
    conforming = (
        "import logging\nimport requests\n\nlog = logging.getLogger(__name__)\n\n\n"
        "def get_thing(x) -> int:\n    log.info('x')\n    return requests.get(x)\n"
    )
    files = {**BASELINE, "app/new.py": conforming}
    assert [f for f in scan(files, rule_ids=("DRF-01", "DRF-02", "DRF-03")) if f.path == "app/new.py"] == []


def test_small_repo_gives_no_opinion(scan):
    files = {"a.py": DRIFTING, "b.py": "x = 1\n"}
    assert scan(files, rule_ids=("DRF-01", "DRF-02", "DRF-03")) == []


def test_tests_and_scripts_are_exempt(scan):
    files = {**BASELINE, "tests/test_new.py": DRIFTING, "app/cli.py": "def main():\n    print('hi')\n"}
    found = scan(files, rule_ids=("DRF-01", "DRF-02", "DRF-03"))
    assert not [f for f in found if f.path in ("tests/test_new.py",)]
    assert not [f for f in found if f.path == "app/cli.py" and "print" in f.message]


def test_drift_is_off_by_default_and_opt_in_by_module(tmp_path):
    for rel, text in {**BASELINE, "app/new.py": DRIFTING}.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    runner = CliRunner()
    plain = json.loads(runner.invoke(app, ["scan", str(tmp_path), "--no-network", "-f", "json"]).stdout)
    assert not [f for f in plain["findings"] if f["rule_id"].startswith("DRF")]
    opted = json.loads(runner.invoke(app, ["scan", str(tmp_path), "--no-network", "-m", "drf", "-f", "json"]).stdout)
    assert {f["rule_id"] for f in opted["findings"]} == {"DRF-01", "DRF-02", "DRF-03"}


def test_only_changed_files_are_judged_and_excluded_from_the_baseline(tmp_path):
    def git(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    for rel, text in BASELINE.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    (tmp_path / "app" / "new.py").write_text(DRIFTING)
    git("add", "app/new.py")
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "--no-network", "-m", "drf", "--staged", "-f", "json"])
    paths = {f["path"] for f in json.loads(result.stdout)["findings"]}
    assert paths == {"app/new.py"}
