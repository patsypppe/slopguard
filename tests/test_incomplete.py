from conftest import ids


def test_placeholder_comment(scan):
    source = "def f():\n    x = 1\n    # ... rest of code here\n    return x\n"
    assert ids(scan({"a.py": source}, rule_ids=("INC-01",))) == ["INC-01"]


def test_placeholder_variants_and_clean_comment(scan):
    source = "# existing code remains unchanged\n# add your logic here\n# compute the total\n"
    findings = scan({"a.py": source}, rule_ids=("INC-01",))
    assert [f.line for f in findings] == [1, 2]


def test_hollow_functions(scan):
    source = (
        "def a():\n    pass\n"
        "def b():\n    ...\n"
        "def c():\n    '''doc'''\n    raise NotImplementedError('todo')\n"
        "def d():\n    '''only a docstring'''\n"
        "def ok():\n    return 1\n"
    )
    findings = scan({"a.py": source}, rule_ids=("INC-02",))
    assert [f.line for f in findings] == [1, 3, 5, 8]


def test_hollow_exemptions(scan):
    source = (
        "from abc import ABC, abstractmethod\n"
        "from typing import Protocol\n"
        "class Base(ABC):\n"
        "    @abstractmethod\n"
        "    def run(self):\n        pass\n"
        "class P(Protocol):\n"
        "    def go(self): ...\n"
        "class C:\n"
        "    def __init__(self):\n        pass\n"
    )
    assert scan({"a.py": source}, rule_ids=("INC-02",)) == []


def test_not_implemented_in_method_has_lower_confidence(scan):
    source = "class C:\n    def m(self):\n        raise NotImplementedError\n"
    finding = scan({"a.py": source}, rule_ids=("INC-02",))[0]
    assert finding.confidence < 0.6


def test_swallowed_exceptions(scan):
    source = (
        "try:\n    risky()\nexcept:\n    pass\n"
        "try:\n    risky()\nexcept Exception:\n    pass\n"
        "try:\n    risky()\nexcept ValueError:\n    ...\n"
        "try:\n    import x\nexcept ImportError:\n    pass\n"
        "try:\n    risky()\nexcept Exception as e:\n    log(e)\n"
    )
    findings = scan({"a.py": source}, rule_ids=("INC-04",))
    assert [f.line for f in findings] == [3, 7]  # narrow types are deliberate, so not flagged
    assert findings[0].severity.label == "medium" and findings[1].severity.label == "low"
    assert findings[1].confidence < findings[0].confidence


def test_chat_residue_outside_strings(scan):
    source = "x = 1\n```python\ny = 2\n"
    assert ids(scan({"a.py": source}, rule_ids=("INC-05",))) == ["INC-05"]


def test_fence_inside_docstring_is_clean(scan):
    source = 'def f():\n    """\n    ```python\n    f()\n    ```\n    """\n    return 1\n'
    assert scan({"a.py": source}, rule_ids=("INC-05",)) == []


def test_chat_comment(scan):
    source = "# Here is the updated function\ndef f():\n    return 1\n"
    assert ids(scan({"a.py": source}, rule_ids=("INC-05",))) == ["INC-05"]


def test_todo_density_threshold(scan):
    source = "".join(f"# TODO item {i}\n" for i in range(5)) + "x = 1\n"
    assert ids(scan({"a.py": source}, rule_ids=("INC-06",))) == ["INC-06"]
    assert scan({"a.py": "# TODO one\nx = 1\n"}, rule_ids=("INC-06",)) == []


def test_unparseable_truncated_file(scan):
    findings = scan({"a.py": "def f(:\n    return (1,\n"}, rule_ids=("INC-08",))
    assert ids(findings) == ["INC-08"]
    findings = scan({"b.py": "x = [1, 2,\n"}, rule_ids=("INC-08",))
    (truncated,) = [f for f in findings if f.path == "b.py"]
    assert "truncated" in truncated.message


def test_other_rules_skip_unparseable_files(scan):
    assert scan({"a.py": "def f(:\n"}, rule_ids=("INC-02", "INC-04", "LLM-02")) == []
