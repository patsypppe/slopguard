"""Run untrusted, generated tests with as much isolation as the machine offers.

Backends, strongest first:

* ``docker``: a throwaway container with no network, capped memory, CPUs and processes.
  The image must contain pytest (set ``[sandbox] image``).
* ``unshare``: a Linux user and network namespace, so the tests have no network, plus CPU,
  memory and file-size limits. They still see the host filesystem copy in a temp directory.
* ``local``: no isolation beyond a temp copy, a minimal environment and resource limits.
  Used only when asked for by name.

``auto`` picks docker, then unshare, and otherwise refuses instead of running unsafely.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from slopguard.config import DEFAULT_EXCLUDE_DIRS

MAX_COPY_BYTES = 50 * 1024 * 1024
MAX_OUTPUT = 6000


class SandboxError(Exception):
    """No safe backend, or the project could not be prepared."""


@dataclass
class TestRun:
    __test__ = False  # not a pytest test class

    backend: str
    returncode: int | None
    output: str
    timed_out: bool
    results: dict[str, str]

    @property
    def passed(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        done = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                              capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0 and bool(done.stdout.strip())


def unshare_available() -> bool:
    if shutil.which("unshare") is None:
        return False
    try:
        done = subprocess.run(["unshare", "--net", "--map-root-user", "true"],
                              capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


def pick_backend(preferred: str) -> str:
    if preferred == "local":
        return "local"
    if preferred in ("auto", "docker") and docker_available():
        return "docker"
    if preferred == "docker":
        raise SandboxError("docker was requested but no working Docker daemon was found")
    if preferred in ("auto", "unshare") and unshare_available():
        return "unshare"
    raise SandboxError(
        "no isolated backend available (need a Docker daemon or Linux user namespaces). "
        'Set `backend = "local"` under [sandbox] to run without network isolation, at your own risk.'
    )


def copy_project(root: Path, destination: Path) -> None:
    total = 0

    def ignore(folder: str, names: list[str]) -> set[str]:
        return {n for n in names if n in DEFAULT_EXCLUDE_DIRS or n.endswith(".pyc")}

    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDE_DIRS]
        for name in files:
            try:
                total += (Path(current) / name).stat().st_size
            except OSError:
                continue
        if total > MAX_COPY_BYTES:
            raise SandboxError(f"project is larger than {MAX_COPY_BYTES // (1024 * 1024)} MB; refusing to copy")
    shutil.copytree(root, destination, ignore=ignore, dirs_exist_ok=True)


def _limits(timeout: int):
    def apply() -> None:  # runs in the child before exec
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (timeout + 5, timeout + 5))
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        resource.setrlimit(resource.RLIMIT_FSIZE, (50 * 1024**2, 50 * 1024**2))

    return apply


def run_tests(
    project_root: Path,
    test_sources: dict[str, str],
    *,
    backend: str = "auto",
    image: str = "python:3.12-slim",
    timeout: int = 120,
) -> TestRun:
    """Copy the project, add ``test_sources`` (relative path -> code) and run them."""
    chosen = pick_backend(backend)
    with tempfile.TemporaryDirectory(prefix="slopguard-") as tmp:
        work = Path(tmp) / "work"
        copy_project(project_root, work)
        targets = []
        for rel, code in test_sources.items():
            target = work / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(code)
            targets.append(rel)
        report = "slopguard-report.xml"
        pytest_args = ["-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider",
                       f"--junitxml={report}", *targets]
        env = {"PATH": os.environ.get("PATH", ""), "HOME": tmp, "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONPATH": os.pathsep.join([str(work / "src"), str(work)])}
        if chosen == "docker":
            cmd = ["docker", "run", "--rm", "--network", "none", "--memory", "512m", "--cpus", "1",
                   "--pids-limit", "256", "-v", f"{work}:/work", "-w", "/work",
                   "-e", "PYTHONPATH=/work/src:/work", image, "python", *pytest_args]
            run_env = None
        elif chosen == "unshare":
            cmd = ["unshare", "--net", "--map-root-user", sys.executable, *pytest_args]
            run_env = env
        else:
            cmd = [sys.executable, *pytest_args]
            run_env = env
        started = subprocess.Popen(
            cmd, cwd=work, env=run_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, start_new_session=True,
            preexec_fn=_limits(timeout) if chosen != "docker" and os.name == "posix" else None,  # noqa: PLW1509
        )
        try:
            output, _ = started.communicate(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(started.pid, signal.SIGKILL)
            output, _ = started.communicate()
            timed_out = True
        results: dict[str, str] = {}
        report_path = work / report
        if report_path.exists():
            from slopguard.regress import _read_junit

            results = _read_junit(report_path)
        return TestRun(chosen, started.returncode, (output or "")[-MAX_OUTPUT:], timed_out, results)
