from slopguard import docgen


def test_generated_docs_are_current():
    assert docgen.main(["--check"]) == 0, "run: python -m slopguard.docgen"


def test_every_command_is_documented():
    text = docgen.cli_markdown()
    for command in ("scan", "regress", "gen-tests", "fix", "rules", "explain", "init", "bench"):
        assert f"## slopguard {command}" in text
    assert "`--fail-on`" in text and "default: high" in text
