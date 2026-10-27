"""Cases found by scanning mature, human-written packages (requests, rich, openai, litellm...).

Each one was a false positive at first. They are kept here so the rules do not drift back.
"""

from conftest import ids

KEY = "sk-" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3kL6"


def test_env_var_names_and_dotted_keys_are_not_secrets(scan):
    source = (
        'ENV_API_KEY = "ANTHROPIC_API_KEY"\n'
        'ENV_AUTH_TOKEN = "ANTHROPIC_AUTH_TOKEN"\n'
        'GRANT_TYPE_REFRESH_TOKEN = "refresh_token"\n'
        'LLM_TOKEN_COUNT_PROMPT = "llm.token_count.prompt"\n'
        'api_key_header = "X-Api-Key-Header-Value"\n'
        'AWS_SECRET_ENV = "AWS_SECRET_ACCESS_KEY_ID1"\n'
    )
    assert scan({"a.py": source}, rule_ids=("SEC-01",)) == []


def test_real_looking_credentials_are_still_found(scan):
    source = f'token = "q9X$kP2mZr7LwT4bNc"\nclient = Client(api_key="{KEY}")\nsecret = "9f86d081884c7d659a2feaa0c55ad015"\n'
    assert [f.line for f in scan({"a.py": source}, rule_ids=("SEC-01",))] == [1, 2, 3]


def test_documented_example_keys_are_ignored(scan):
    assert scan({"a.py": 'k = "AKIAIOSFODNN7EXAMPLE"\n'}, rule_ids=("SEC-01",)) == []


def test_private_key_header_needs_key_material(scan):
    header_only = 'PREFIX = "-----BEGIN RSA PRIVATE KEY-----"\nif PREFIX in text:\n    pass\n'
    placeholder = '{"placeholder": "-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----"}\n'
    body = "A" * 64
    real = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"
    assert scan({"a.py": header_only, "b.json": placeholder}, rule_ids=("SEC-01",)) == []
    assert ids(scan({"c.pem.py": real}, rule_ids=("SEC-01",))) == ["SEC-01"]


def test_ordinary_comments_that_mention_implementation_are_not_placeholders(scan):
    source = (
        "# provided a lot of what went into the implementation here in\n"
        "# if we have a known extends already we don't need that code here\n"
        "# Sneak in the reporting logic here\n"
    )
    assert scan({"a.py": source}, rule_ids=("INC-01",)) == []


def test_imperative_placeholders_are_still_found(scan):
    source = "# Implement rerank logic here based on the provider\n# Your client code here\n# add your code here\n"
    assert len(scan({"a.py": source}, rule_ids=("INC-01",))) == 3


def test_hook_methods_are_low_severity_and_documented_hooks_are_skipped(scan):
    source = (
        "class Base:\n"
        "    def close(self):\n        pass\n"
        "    def on_text(self, text):\n        '''Subclasses override this hook.'''\n"
        "def helper():\n    pass\n"
    )
    findings = scan({"a.py": source}, rule_ids=("INC-02",))
    by_name = {f.message.split("`")[1]: f for f in findings}
    assert set(by_name) == {"close", "helper"}
    assert by_name["close"].severity.label == "low" and by_name["close"].confidence < 0.5
    assert by_name["helper"].severity.label == "medium" and by_name["helper"].confidence > 0.8


def test_explained_swallow_and_narrow_catches_are_clean(scan):
    source = (
        "try:\n    cleanup()\nexcept Exception:  # best effort, the file may be gone\n    pass\n"
        "try:\n    cleanup()\nexcept Exception:\n    # nothing to do if the socket is closed\n    pass\n"
        "try:\n    value = d['k']\nexcept KeyError:\n    pass\n"
    )
    assert scan({"a.py": source}, rule_ids=("INC-04",)) == []


def test_endpoints_and_self_named_values_are_not_secrets(scan):
    source = (
        'TOKEN_ENDPOINT = "/v1/oauth/token"\n'
        'oauth_client_secret = "oauth-client-secret"\n'
        "'''Example api_key='d5349b7e1d1f4e0b8f6a2c9d3e5f7a1b'.'''\n"
    )
    assert scan({"a.py": source}, rule_ids=("SEC-01",)) == []


def test_notes_that_say_add_things_here_are_not_placeholders(scan):
    source = "# Add vertex_ai here once verified.\n# Add more providers here as needed\nx = 1  # Add any extra metadata here\n"
    assert scan({"a.py": source}, rule_ids=("INC-01",)) == []


def test_typed_ellipsis_stubs_are_low_severity(scan):
    source = "def get_origin(t: type) -> type | None: ...\n\ndef todo():\n    pass\n"
    by_name = {f.message.split("`")[1]: f for f in scan({"a.py": source}, rule_ids=("INC-02",))}
    assert by_name["get_origin"].severity.label == "low" and by_name["todo"].severity.label == "medium"


def test_import_names_that_differ_from_the_distribution_are_mapped(scan):
    source = "import pkg_resources\nimport zmq\nimport slugify\nimport grpc\n"
    found = scan({"a.py": source}, rule_ids=("HAL-01",), known_packages=frozenset(
        {"setuptools", "pyzmq", "python-slugify", "grpcio"}), network=True)
    assert found == []


def test_namespace_packages_and_new_stdlib_modules_are_not_missing_packages(scan):
    source = "import opentelemetry.trace\nimport opensearchpy\nimport tomllib\nimport annotationlib\n"
    found = scan({"a.py": source}, rule_ids=("HAL-01",), network=True,
                 known_packages=frozenset({"opentelemetry-api", "opensearch-py"}))
    assert found == []


def test_unknown_imports_in_optional_places_are_medium_not_high(scan):
    source = (
        "import ghostlib_top\n"
        "def lazy():\n    import ghostlib_lazy\n"
        "try:\n    import ghostlib_guarded\nexcept ImportError:\n    pass\n"
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import ghostlib_types\n"
    )
    found = {f.message.split("`")[1]: f for f in scan({"a.py": source}, rule_ids=("HAL-01",), network=True)}
    assert found["ghostlib_top"].severity.label == "high" and found["ghostlib_top"].confidence > 0.8
    for name in ("ghostlib_lazy", "ghostlib_guarded", "ghostlib_types"):
        assert found[name].severity.label == "medium" and found[name].confidence <= 0.5
