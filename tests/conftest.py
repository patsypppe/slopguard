from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from slopguard.config import Config
from slopguard.context import build_project
from slopguard.engine import discover, run_scan
from slopguard.registry import RegistryClient
from slopguard.rules import all_rules


@pytest.fixture
def scan(tmp_path: Path) -> Callable[..., list]:
    """Write files into a temp project, scan them and return the findings."""

    def _scan(
        files: dict[str, str],
        *,
        rule_ids: tuple[str, ...] = (),
        known_packages: frozenset[str] = frozenset(),
        config: Config | None = None,
        network: bool = False,
    ) -> list:
        for name, content in files.items():
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        config = config or Config()
        registry = None
        if network:
            registry = RegistryClient(
                cache_path=tmp_path / ".cache.json",
                fetcher=lambda name: 200 if name in known_packages else 404,
                json_fetcher=lambda name: None,
            )
        project = build_project(tmp_path, config, network=False, registry=registry)
        rules = [r for r in all_rules() if not rule_ids or r.meta.id in rule_ids]
        suffixes = {s for r in rules for s in r.file_types}
        found = discover([tmp_path], tmp_path, config, suffixes)
        return run_scan(found, rules, project).findings

    return _scan


def ids(findings: list) -> list[str]:
    return [f.rule_id for f in findings]


class ScriptedProvider:
    """A provider that replays canned answers and records what it was asked."""

    name = "scripted"
    model = "test-model"

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> str:
        self.calls.append((system, prompt))
        if not self.answers:
            raise AssertionError("provider was called more often than scripted")
        return self.answers.pop(0)


@pytest.fixture
def fake_llm():
    """A local HTTP server that speaks the Anthropic, OpenAI and Ollama wire formats."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    state = {"answers": [], "requests": [], "status": 200}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            state["requests"].append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
            if state["status"] != 200:
                self.send_response(state["status"])
                self.end_headers()
                self.wfile.write(b'{"error": "scripted failure"}')
                return
            text = state["answers"].pop(0) if state["answers"] else ""
            if self.path.endswith("/v1/messages"):
                payload = {"content": [{"type": "text", "text": text}]}
            elif self.path.endswith("/chat/completions"):
                payload = {"choices": [{"message": {"content": text}}]}
            else:
                payload = {"message": {"content": text}}
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state["url"] = f"http://127.0.0.1:{server.server_port}"
    yield state
    server.shutdown()
