import pytest

import slopguard
from slopguard.config import Config, ConfigError

BAD = "def f(client):\n    return eval(client.messages.create(model='m', max_tokens=5, messages=[]).content[0].text)\n"


def test_top_level_names_are_lazy_and_complete():
    assert slopguard.__version__
    for name in ("scan", "scan_source", "Finding", "Severity", "Config", "ScanResult"):
        assert getattr(slopguard, name) is not None
    with pytest.raises(AttributeError):
        slopguard.does_not_exist  # noqa: B018


def test_scan_paths(tmp_path):
    (tmp_path / "bad.py").write_text(BAD)
    (tmp_path / "ok.py").write_text("x = 1\n")
    result = slopguard.scan([tmp_path], network=False)
    assert result.files_scanned == 2
    assert [(f.rule_id, f.path, f.severity.label) for f in result.findings] == [("LLM-02", "bad.py", "critical")]


def test_scan_filters_and_config(tmp_path):
    (tmp_path / "bad.py").write_text(BAD)
    assert slopguard.scan([tmp_path], network=False, modules=["inc"]).findings == []
    assert slopguard.scan([tmp_path], network=False, rules=["llm-02"]).findings[0].rule_id == "LLM-02"
    off = Config()
    off.modules["llm"] = False
    assert slopguard.scan([tmp_path], network=False, config=off).findings == []


def test_scan_reads_config_file(tmp_path):
    (tmp_path / "bad.py").write_text(BAD)
    (tmp_path / "slopguard.toml").write_text("[modules]\nllm = false\n")
    assert slopguard.scan([tmp_path], network=False).findings == []
    (tmp_path / "bad.toml").write_text("[modules]\nbogus = true\n")
    with pytest.raises(ConfigError):
        slopguard.scan([tmp_path], network=False, config_path=tmp_path / "bad.toml")


def test_scan_errors():
    with pytest.raises(FileNotFoundError):
        slopguard.scan(["/no/such/place"])
    with pytest.raises(ValueError, match="unknown module"):
        slopguard.scan(["."], modules=["zzz"], network=False)
    with pytest.raises(ValueError, match="unknown rule"):
        slopguard.scan(["."], rules=["ZZZ-1"], network=False)


def test_scan_source_for_checking_an_answer_before_saving_it():
    findings = slopguard.scan_source(BAD)
    assert [f.rule_id for f in findings] == ["LLM-02"]
    assert slopguard.scan_source("def f(:\n")[0].rule_id == "INC-08"
    assert slopguard.scan_source("x = 1\n") == []
    assert slopguard.scan_source(BAD, rules=["INC-02"]) == []
