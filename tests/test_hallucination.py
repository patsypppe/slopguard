from conftest import ids


def test_nonexistent_package_is_flagged(scan):
    source = "import requests\nimport fastllmkit_pro\n"
    findings = scan(
        {"a.py": source},
        rule_ids=("HAL-01",),
        known_packages=frozenset({"requests"}),
        network=True,
    )
    assert ids(findings) == ["HAL-01"]
    assert "fastllmkit_pro" in findings[0].message
    assert findings[0].line == 2


def test_stdlib_local_and_relative_imports_are_not_looked_up(scan):
    files = {
        "a.py": "import os\nimport helpers\nfrom . import sibling\nfrom pkg import thing\n",
        "helpers.py": "x = 1\n",
        "pkg/__init__.py": "",
        "pkg/thing.py": "",
    }
    assert scan(files, rule_ids=("HAL-01",), network=True) == []


def test_alias_maps_import_name_to_distribution(scan):
    findings = scan(
        {"a.py": "import yaml\n"},
        rule_ids=("HAL-01",),
        known_packages=frozenset({"pyyaml"}),
        network=True,
    )
    # pyyaml may also be installed in the test environment; either way it is not flagged
    assert findings == []


def test_unknown_registry_answer_is_not_flagged(scan, tmp_path):
    from slopguard.config import Config
    from slopguard.context import build_project
    from slopguard.engine import discover, run_scan
    from slopguard.registry import RegistryClient
    from slopguard.rules import all_rules

    (tmp_path / "a.py").write_text("import totally_made_up_pkg\n")
    registry = RegistryClient(cache_path=tmp_path / "c.json", fetcher=lambda n: None)
    project = build_project(tmp_path, Config(), network=False, registry=registry)
    rules = [r for r in all_rules() if r.meta.id == "HAL-01"]
    files = discover([tmp_path], tmp_path, Config(), {".py"})
    assert run_scan(files, rules, project).findings == []


def test_registry_results_are_cached(tmp_path):
    from slopguard.registry import RegistryClient

    calls = []

    def fetch(name):
        calls.append(name)
        return 404

    client = RegistryClient(cache_path=tmp_path / "c.json", fetcher=fetch)
    assert client.exists("Some_Pkg") is False
    assert client.exists("some-pkg") is False
    assert calls == ["some-pkg"]
    client.save()
    again = RegistryClient(cache_path=tmp_path / "c.json", fetcher=fetch)
    assert again.exists("some-pkg") is False
    assert calls == ["some-pkg"]


def test_undeclared_dependency(scan):
    files = {
        "requirements.txt": "requests>=2\n# comment\n",
        "a.py": "import requests\nimport numpy\nimport os\n",
    }
    findings = scan(files, rule_ids=("HAL-04",))
    assert ids(findings) == ["HAL-04"]
    assert "numpy" in findings[0].message


def test_declared_via_pyproject_and_alias(scan):
    pyproject = '[project]\nname = "demo"\nversion = "0"\ndependencies = ["PyYAML>=6", "httpx"]\n'
    files = {"pyproject.toml": pyproject, "a.py": "import yaml\nimport httpx\n"}
    assert scan(files, rule_ids=("HAL-04",)) == []


def test_no_manifest_means_rule_is_skipped(scan):
    assert scan({"a.py": "import numpy\n"}, rule_ids=("HAL-04",)) == []


def test_guarded_optional_import_is_not_undeclared(scan):
    source = "try:\n    import numpy\nexcept ImportError:\n    numpy = None\n"
    files = {"requirements.txt": "requests\n", "a.py": source}
    assert scan(files, rule_ids=("HAL-04",)) == []
