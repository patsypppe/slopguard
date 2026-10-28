from slopguard import docgen


def test_generated_docs_are_current():
    assert docgen.main(["--check"]) == 0, "run: python -m slopguard.docgen"


def test_every_command_is_documented():
    text = docgen.cli_markdown()
    for command in ("scan", "regress", "gen-tests", "fix", "rules", "explain", "init", "bench"):
        assert f"## slopguard {command}" in text
    assert "`--fail-on`" in text and "default: high" in text


# -- links ---------------------------------------------------------------------------------

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$", re.MULTILINE)


def markdown_files():
    files = [*ROOT.glob("*.md"), *(ROOT / "docs").rglob("*.md"), *(ROOT / "examples").rglob("*.md")]
    return sorted(files)


def slug(heading: str) -> str:
    """GitHub's heading anchors: lowercase, drop punctuation, spaces to dashes."""
    text = re.sub(r"`([^`]*)`", r"\1", heading).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    text = re.sub(r"```.*?```", "", path.read_text(), flags=re.DOTALL)
    return {slug(m.group(2)) for m in HEADING.finditer(text)}


def test_relative_links_and_anchors_resolve():
    problems = []
    for source in markdown_files():
        text = re.sub(r"```.*?```", "", source.read_text(), flags=re.DOTALL)
        for target in LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path_part, _, fragment = target.partition("#")
            resolved = (source.parent / path_part).resolve() if path_part else source
            if not resolved.exists():
                problems.append(f"{source.relative_to(ROOT)}: {target} does not exist")
            elif fragment and resolved.suffix == ".md" and fragment not in anchors(resolved):
                problems.append(f"{source.relative_to(ROOT)}: {target} has no such heading")
    assert not problems, "\n".join(problems)
