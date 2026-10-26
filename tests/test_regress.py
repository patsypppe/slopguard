import subprocess
from pathlib import Path

import pytest

from slopguard.regress import RegressionError, regress, weakened_test_findings

GOOD_MODULE = "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n"
GOOD_TESTS = (
    "from calc import add, sub\n\n"
    "def test_add():\n    assert add(1, 2) == 3\n    assert add(0, 0) == 0\n\n"
    "def test_sub():\n    assert sub(3, 1) == 2\n"
)


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "tests").mkdir()
    (tmp_path / "calc.py").write_text(GOOD_MODULE)
    (tmp_path / "tests" / "test_calc.py").write_text(GOOD_TESTS)
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    return tmp_path


def messages(findings):
    return [(f.rule_id, f.message) for f in findings]


def test_no_change_no_findings(repo):
    assert weakened_test_findings(repo, "HEAD") == []


def test_removed_test_is_reported(repo):
    (repo / "tests" / "test_calc.py").write_text(GOOD_TESTS.split("def test_sub")[0])
    findings = weakened_test_findings(repo, "HEAD")
    assert len(findings) == 1 and "test_sub" in findings[0].message
    assert findings[0].rule_id == "REG-02" and findings[0].path == "tests/test_calc.py"


def test_deleted_test_file(repo):
    (repo / "tests" / "test_calc.py").unlink()
    findings = weakened_test_findings(repo, "HEAD")
    assert [f.message for f in findings] == ["test file deleted (2 test(s))"]


def test_added_skip_and_xfail(repo):
    edited = GOOD_TESTS.replace("def test_sub", "@pytest.mark.skip(reason='later')\ndef test_sub")
    (repo / "tests" / "test_calc.py").write_text("import pytest\n" + edited)
    findings = weakened_test_findings(repo, "HEAD")
    assert any("skip or xfail added" in f.message for f in findings)


def test_fewer_assertions_is_medium(repo):
    (repo / "tests" / "test_calc.py").write_text(GOOD_TESTS.replace("    assert add(0, 0) == 0\n", ""))
    (finding,) = weakened_test_findings(repo, "HEAD")
    assert "fewer assertion" in finding.message and finding.severity.label == "medium"


def test_non_test_files_are_ignored(repo):
    (repo / "calc.py").write_text("def add(a, b):\n    return 0\n")
    assert weakened_test_findings(repo, "HEAD") == []


def test_renamed_test_is_not_a_removal_when_name_is_kept(repo):
    (repo / "tests" / "test_calc.py").write_text(GOOD_TESTS + "\ndef test_extra():\n    assert True\n")
    assert weakened_test_findings(repo, "HEAD") == []


def test_regressed_test_detected_by_running_suite(repo):
    (repo / "calc.py").write_text(GOOD_MODULE.replace("a + b", "a - b"))
    findings = regress(repo, "HEAD", run_tests=True)
    broken = [f for f in findings if f.rule_id == "REG-01"]
    assert len(broken) == 1 and "test_add" in broken[0].message and "now fails" in broken[0].message


def test_suite_that_still_passes_has_no_regressions(repo):
    (repo / "calc.py").write_text(GOOD_MODULE + "\ndef mul(a, b):\n    return a * b\n")
    assert regress(repo, "HEAD", run_tests=True) == []


def test_bad_ref_raises(repo):
    with pytest.raises(RegressionError):
        regress(repo, "no-such-ref", run_tests=False)
