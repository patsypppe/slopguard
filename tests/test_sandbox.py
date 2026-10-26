from pathlib import Path

import pytest

from slopguard import sandbox
from slopguard.sandbox import SandboxError, pick_backend, run_tests

PASSING = "def test_ok():\n    assert 1 + 1 == 2\n"
FAILING = "def test_bad():\n    assert 1 + 1 == 3\n"
HANGING = "import time\n\ndef test_hang():\n    time.sleep(30)\n"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "mod.py").write_text("VALUE = 41\n")
    return tmp_path


def test_local_backend_runs_and_reports_per_test(project):
    run = run_tests(project, {"tests_gen/test_a.py": PASSING + FAILING}, backend="local", timeout=60)
    assert run.backend == "local" and not run.passed
    assert run.results == {"tests_gen.test_a::test_ok": "passed", "tests_gen.test_a::test_bad": "failed"}


def test_tests_can_import_project_modules(project):
    code = "from mod import VALUE\n\ndef test_value():\n    assert VALUE == 41\n"
    assert run_tests(project, {"t/test_m.py": code}, backend="local").passed


def test_timeout_kills_the_run(project):
    run = run_tests(project, {"t/test_h.py": HANGING}, backend="local", timeout=2)
    assert run.timed_out and not run.passed


def test_project_files_are_copied_not_modified(project):
    code = "def test_w():\n    open('scratch.txt', 'w').write('x')\n"
    run_tests(project, {"t/test_w.py": code}, backend="local")
    assert not (project / "scratch.txt").exists() and not (project / "t").exists()


def test_secrets_in_environment_are_not_passed_on(project, monkeypatch):
    monkeypatch.setenv("SUPER_SECRET_TOKEN", "hunter2")
    code = "import os\n\ndef test_env():\n    assert 'SUPER_SECRET_TOKEN' not in os.environ\n"
    assert run_tests(project, {"t/test_e.py": code}, backend="local").passed


def test_auto_refuses_when_no_isolated_backend(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    monkeypatch.setattr(sandbox, "unshare_available", lambda: False)
    with pytest.raises(SandboxError, match="no isolated backend"):
        pick_backend("auto")
    assert pick_backend("local") == "local"


def test_auto_prefers_docker_then_unshare(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    monkeypatch.setattr(sandbox, "unshare_available", lambda: True)
    assert pick_backend("auto") == "docker"
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    assert pick_backend("auto") == "unshare"
    with pytest.raises(SandboxError, match="docker was requested"):
        pick_backend("docker")


@pytest.mark.skipif(not sandbox.unshare_available(), reason="user namespaces unavailable")
def test_unshare_backend_has_no_network(project):
    """A fresh network namespace has only the loopback interface."""
    code = (
        "import socket\n\n"
        "def test_only_loopback():\n"
        "    names = [name for _, name in socket.if_nameindex()]\n"
        "    assert names == ['lo'], names\n"
    )
    run = run_tests(project, {"t/test_n.py": code}, backend="unshare", timeout=60)
    assert run.backend == "unshare" and run.passed, run.output


def test_oversized_project_is_refused(project, monkeypatch):
    monkeypatch.setattr(sandbox, "MAX_COPY_BYTES", 10)
    (project / "big.txt").write_text("x" * 100)
    with pytest.raises(SandboxError, match="larger than"):
        run_tests(project, {"t/test_a.py": PASSING}, backend="local")
