"""LLM provider interface and small HTTP clients.

slopguard never needs a model for its scanning rules. Providers are used only by features
that opt in: judging requirements, generating tests and proposing repairs. No SDK is
required; the clients speak plain HTTPS with ``urllib``. There is deliberately no default
model name: model IDs change, so the user sets the one they want.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any, Protocol

from slopguard.config import Config


class LLMError(Exception):
    """Raised for configuration problems, transport failures and unusable answers."""


class Provider(Protocol):
    name: str
    model: str

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> str: ...


def _post_json(url: str, headers: Mapping[str, str], payload: dict, timeout: int = 90) -> dict:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        url, data=body, headers={"content-type": "application/json", **headers}, method="POST"
    )
    delay = 1.0
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            retryable = exc.code == 429 or 500 <= exc.code < 600
            if retryable and attempt < 2:
                time.sleep(delay)
                delay *= 2
                continue
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise LLMError(f"{url} answered HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt < 2:
                time.sleep(delay)
                delay *= 2
                continue
            raise LLMError(f"could not reach {url}: {exc}") from exc
        except ValueError as exc:
            raise LLMError(f"{url} returned invalid JSON") from exc
    raise LLMError(f"could not reach {url}")  # pragma: no cover


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str, base_url: str = "") -> None:
        self.api_key, self.model = api_key, model
        self.base_url = (base_url or "https://api.anthropic.com").rstrip("/")

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> str:
        data = _post_json(
            f"{self.base_url}/v1/messages",
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        try:
            blocks = [b["text"] for b in data["content"] if b.get("type") == "text"]
        except (KeyError, TypeError) as exc:
            raise LLMError("unexpected response shape from Anthropic") from exc
        if not blocks:
            raise LLMError("Anthropic returned no text")
        return "".join(blocks)


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str, base_url: str = "") -> None:
        self.api_key, self.model = api_key, model
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> str:
        data = _post_json(
            f"{self.base_url}/chat/completions",
            {"authorization": f"Bearer {self.api_key}"},
            {
                "model": self.model,
                "max_completion_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError("unexpected response shape from OpenAI") from exc
        if not text:
            raise LLMError("OpenAI returned no text")
        return text


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str, base_url: str = "") -> None:
        self.model = model
        self.base_url = (base_url or "http://localhost:11434").rstrip("/")

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> str:
        data = _post_json(
            f"{self.base_url}/api/chat",
            {},
            {
                "model": self.model,
                "stream": False,
                "options": {"num_predict": max_tokens},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=300,
        )
        try:
            return data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LLMError("unexpected response shape from Ollama") from exc


def get_provider(config: Config, env: Mapping[str, str] | None = None) -> Provider:
    """Build the configured provider or explain exactly what is missing."""
    env = os.environ if env is None else env
    name = config.llm_provider
    if name == "none":
        raise LLMError(
            "no LLM provider configured. Add an [llm] section to slopguard.toml "
            '(provider = "anthropic", "openai" or "ollama", and model = "<model id>")'
        )
    model = config.llm_model or env.get("SLOPGUARD_LLM_MODEL", "")
    if not model:
        raise LLMError("no model set: add `model = ...` under [llm] or set SLOPGUARD_LLM_MODEL")
    if name == "ollama":
        return OllamaProvider(model, config.llm_base_url)
    key_var = "ANTHROPIC_API_KEY" if name == "anthropic" else "OPENAI_API_KEY"
    key = env.get(key_var, "")
    if not key:
        raise LLMError(f"{key_var} is not set")
    cls = AnthropicProvider if name == "anthropic" else OpenAIProvider
    return cls(key, model, config.llm_base_url)


_FENCE = re.compile(r"```(?:json|python|py)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_code_block(text: str, language: str = "python") -> str | None:
    """Return the first fenced block, preferring one tagged with ``language``."""
    tagged = re.search(rf"```{language}\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if tagged:
        return tagged.group(1)
    generic = _FENCE.search(text)
    return generic.group(1) if generic else None


def extract_json(text: str) -> Any:
    """Parse the first JSON object or array found in a model answer."""
    candidates = [m.group(1) for m in _FENCE.finditer(text)] + [text]
    for candidate in candidates:
        for opener, closer in (("{", "}"), ("[", "]")):
            start = candidate.find(opener)
            end = candidate.rfind(closer)
            if start != -1 and end > start:
                try:
                    return json.loads(candidate[start : end + 1])
                except ValueError:
                    continue
    raise LLMError("the model's answer did not contain valid JSON")
