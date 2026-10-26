from conftest import ids

RULES = ("LLM-02", "LLM-03")


def test_anthropic_output_to_eval(scan):
    source = (
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "def run(q):\n"
        "    msg = client.messages.create(model='m', messages=[{'role': 'user', 'content': q}])\n"
        "    code = msg.content[0].text\n"
        "    return eval(code)\n"
    )
    findings = scan({"a.py": source}, rule_ids=RULES)
    assert ids(findings) == ["LLM-02"]
    assert findings[0].line == 6
    assert any("messages.create" in step for step in findings[0].trace)
    assert findings[0].confidence >= 0.9


def test_openai_output_to_subprocess_via_fstring(scan):
    source = (
        "import subprocess\n"
        "def run(client, q):\n"
        "    r = client.chat.completions.create(model='m', messages=[])\n"
        "    cmd = r.choices[0].message.content.strip()\n"
        "    subprocess.run(f'echo {cmd}', shell=True)\n"
    )
    assert ids(scan({"a.py": source}, rule_ids=RULES)) == ["LLM-03"]


def test_langchain_invoke_and_exec(scan):
    source = "def run(llm, p):\n    out = llm.invoke(p)\n    exec(out.content)\n"
    assert ids(scan({"a.py": source}, rule_ids=RULES)) == ["LLM-02"]


def test_awaited_call_and_os_system(scan):
    source = (
        "import os\n"
        "async def run(client):\n"
        "    r = await client.messages.create(model='m', messages=[])\n"
        "    os.system(r.content[0].text)\n"
    )
    assert ids(scan({"a.py": source}, rule_ids=RULES)) == ["LLM-03"]


def test_literal_eval_sanitizer_is_clean(scan):
    source = (
        "import ast\n"
        "def run(client):\n"
        "    r = client.messages.create(model='m', messages=[])\n"
        "    return eval(ast.literal_eval(r.content[0].text))\n"
    )
    assert scan({"a.py": source}, rule_ids=RULES) == []


def test_reassignment_clears_taint(scan):
    source = (
        "def run(client):\n"
        "    x = client.messages.create(model='m', messages=[]).content[0].text\n"
        "    x = 'print(1)'\n"
        "    eval(x)\n"
    )
    assert scan({"a.py": source}, rule_ids=RULES) == []


def test_eval_of_constant_and_unrelated_calls_are_clean(scan):
    source = "def f(x):\n    eval('1 + 1')\n    model.eval()\n    return x.messages.list()\n"
    assert scan({"a.py": source}, rule_ids=RULES) == []


def test_parameter_named_like_model_output_has_lower_confidence(scan):
    source = "def run(llm_output):\n    exec(llm_output)\n"
    finding = scan({"a.py": source}, rule_ids=RULES)[0]
    assert finding.rule_id == "LLM-02"
    assert finding.confidence < 0.6


def test_taint_flows_through_loops_and_with(scan):
    source = (
        "def run(client):\n"
        "    r = client.messages.create(model='m', messages=[])\n"
        "    for part in r.content:\n"
        "        eval(part.text)\n"
    )
    assert ids(scan({"a.py": source}, rule_ids=RULES)) == ["LLM-02"]


def test_module_level_flow_and_nested_function(scan):
    source = (
        "r = client.messages.create(model='m', messages=[])\n"
        "eval(r.content[0].text)\n"
        "def outer():\n"
        "    def inner(llm):\n"
        "        exec(llm.invoke('x'))\n"
    )
    findings = scan({"a.py": source}, rule_ids=RULES)
    assert [f.line for f in findings] == [2, 5]


def test_custom_source_and_sanitizer_from_config(scan):
    from slopguard.config import Config

    cfg = Config(taint_sources=["myapp.ask"], taint_sanitizers=["myapp.safe"])
    source = (
        "import myapp\n"
        "def a():\n    eval(myapp.ask('q'))\n"
        "def b():\n    eval(myapp.safe(myapp.ask('q')))\n"
    )
    findings = scan({"a.py": source}, rule_ids=RULES, config=cfg)
    assert [f.line for f in findings] == [3]
