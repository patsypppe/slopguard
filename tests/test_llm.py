import pytest

from slopguard.config import Config
from slopguard.llm import (
    AnthropicProvider,
    LLMError,
    OllamaProvider,
    OpenAIProvider,
    extract_code_block,
    extract_json,
    get_provider,
)


def test_anthropic_request_and_response(fake_llm):
    fake_llm["answers"].append("hello")
    provider = AnthropicProvider("k-123", "some-model", fake_llm["url"])
    assert provider.complete("be brief", "hi", 50) == "hello"
    request = fake_llm["requests"][0]
    assert request["path"] == "/v1/messages"
    assert request["headers"]["x-api-key"] == "k-123"
    assert request["body"]["system"] == "be brief" and request["body"]["max_tokens"] == 50
    assert request["body"]["messages"] == [{"role": "user", "content": "hi"}]


def test_openai_request_and_response(fake_llm):
    fake_llm["answers"].append("hello")
    provider = OpenAIProvider("sk-test", "some-model", fake_llm["url"])
    assert provider.complete("sys", "hi", 20) == "hello"
    request = fake_llm["requests"][0]
    assert request["path"] == "/chat/completions"
    assert request["headers"]["authorization"] == "Bearer sk-test"
    assert request["body"]["messages"][0] == {"role": "system", "content": "sys"}


def test_ollama_request_and_response(fake_llm):
    fake_llm["answers"].append("hello")
    provider = OllamaProvider("llama-x", fake_llm["url"])
    assert provider.complete("sys", "hi", 20) == "hello"
    body = fake_llm["requests"][0]["body"]
    assert body["stream"] is False and body["options"]["num_predict"] == 20


def test_http_error_becomes_llm_error(fake_llm):
    fake_llm["status"] = 400
    with pytest.raises(LLMError, match="HTTP 400"):
        OpenAIProvider("k", "m", fake_llm["url"]).complete("s", "p")


def test_unreachable_server_becomes_llm_error(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    with pytest.raises(LLMError, match="could not reach"):
        OllamaProvider("m", "http://127.0.0.1:1").complete("s", "p")


def test_get_provider_requires_configuration():
    with pytest.raises(LLMError, match="no LLM provider"):
        get_provider(Config(), {})
    with pytest.raises(LLMError, match="no model"):
        get_provider(Config(llm_provider="anthropic"), {"ANTHROPIC_API_KEY": "k"})
    with pytest.raises(LLMError, match="ANTHROPIC_API_KEY"):
        get_provider(Config(llm_provider="anthropic", llm_model="m"), {})


def test_get_provider_builds_each_kind():
    cfg = Config(llm_provider="openai", llm_model="m")
    assert get_provider(cfg, {"OPENAI_API_KEY": "k"}).name == "openai"
    assert get_provider(Config(llm_provider="ollama", llm_model="m"), {}).name == "ollama"
    env = {"ANTHROPIC_API_KEY": "k", "SLOPGUARD_LLM_MODEL": "from-env"}
    provider = get_provider(Config(llm_provider="anthropic"), env)
    assert provider.model == "from-env"


def test_extract_json_variants():
    assert extract_json('Sure! {"a": 1} done') == {"a": 1}
    assert extract_json('```json\n["x", "y"]\n```') == ["x", "y"]
    with pytest.raises(LLMError):
        extract_json("no json here")


def test_extract_code_block_prefers_python():
    text = "```json\n{}\n```\n```python\nx = 1\n```"
    assert extract_code_block(text) == "x = 1\n"
    assert extract_code_block("```\nplain\n```") == "plain\n"
    assert extract_code_block("nothing") is None
