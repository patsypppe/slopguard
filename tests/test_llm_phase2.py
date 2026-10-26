from conftest import ids

FLOW = ("LLM-01", "LLM-02", "LLM-03", "LLM-04", "LLM-05", "LLM-06")
AGENT = ("LLM-08", "LLM-09", "LLM-12")


# -- LLM-01: untrusted input reaching the prompt ------------------------------------------


def test_request_param_in_system_prompt(scan):
    source = (
        "def run(client, request):\n"
        "    topic = request.args['topic']\n"
        "    return client.messages.create(\n"
        "        model='m', max_tokens=5, system=f'You only discuss {topic}', messages=[])\n"
    )
    findings = scan({"a.py": source}, rule_ids=FLOW)
    assert ids(findings) == ["LLM-01"]
    assert "system prompt" in findings[0].message
    assert findings[0].confidence >= 0.9


def test_input_into_system_message_dict(scan):
    source = (
        "def run(client):\n"
        "    who = input('who? ')\n"
        "    messages = [{'role': 'system', 'content': 'Help ' + who}]\n"
        "    return client.chat.completions.create(model='m', max_tokens=5, messages=messages)\n"
    )
    assert ids(scan({"a.py": source}, rule_ids=FLOW)) == ["LLM-01"]


def test_langchain_system_tuple_and_system_message(scan):
    source = (
        "def a(llm, user_input):\n"
        "    return llm.invoke([('system', f'Be nice to {user_input}')])\n"
        "def b(llm, user_input):\n"
        "    return llm.invoke([SystemMessage(content=user_input)])\n"
    )
    findings = scan({"a.py": source}, rule_ids=FLOW)
    assert [f.line for f in findings] == [2, 4]


def test_prompt_string_concatenation_is_low_confidence(scan):
    source = (
        "def run(client):\n"
        "    q = input('?')\n"
        "    return client.models.generate_content(model='m', contents=f'Summarize: {q}')\n"
    )
    finding = scan({"a.py": source}, rule_ids=FLOW)[0]
    assert finding.rule_id == "LLM-01" and finding.confidence <= 0.5


def test_untrusted_text_as_user_message_is_clean(scan):
    source = (
        "def run(client):\n"
        "    q = input('?')\n"
        "    return client.messages.create(\n"
        "        model='m', max_tokens=5, system='Fixed rules',\n"
        "        messages=[{'role': 'user', 'content': q}])\n"
    )
    assert scan({"a.py": source}, rule_ids=FLOW) == []


# -- LLM-04/05/06: model output into SQL, paths and URLs ---------------------------------


def test_model_output_to_sql(scan):
    source = (
        "def run(client, db):\n"
        "    sql = client.messages.create(model='m', messages=[]).content[0].text\n"
        "    db.execute(sql)\n"
    )
    assert ids(scan({"a.py": source}, rule_ids=FLOW)) == ["LLM-04"]


def test_parameterised_query_is_clean(scan):
    source = (
        "def run(client, db):\n"
        "    who = client.messages.create(model='m', messages=[]).content[0].text\n"
        "    db.execute('SELECT * FROM t WHERE name = ?', (who,))\n"
    )
    assert scan({"a.py": source}, rule_ids=FLOW) == []


def test_model_output_to_path_and_url(scan):
    source = (
        "import requests\n"
        "def run(client):\n"
        "    r = client.messages.create(model='m', messages=[])\n"
        "    target = r.content[0].text\n"
        "    open(target, 'w')\n"
        "    requests.get(target)\n"
    )
    findings = scan({"a.py": source}, rule_ids=FLOW)
    assert sorted(ids(findings)) == ["LLM-05", "LLM-06"]
    assert all(f.confidence <= 0.75 for f in findings)


# -- LLM-08 / LLM-09: agent tools ---------------------------------------------------------


SHELL_TOOL = (
    "import subprocess\n"
    "from langchain.tools import tool\n"
    "@tool\n"
    "def run_command(cmd: str) -> str:\n"
    "    '''Run a shell command.'''\n"
    "    return subprocess.run(cmd, shell=True, capture_output=True).stdout\n"
)


def test_tool_argument_reaches_shell(scan):
    findings = scan({"a.py": SHELL_TOOL}, rule_ids=AGENT)
    assert ids(findings) == ["LLM-08"]
    assert "run_command" in findings[0].message
    assert findings[0].confidence >= 0.9


def test_tool_registered_through_factory(scan):
    source = (
        "import os\n"
        "def read_it(path):\n    return open(path).read()\n"
        "tools = [Tool(name='read', func=read_it, description='read')]\n"
    )
    findings = scan({"a.py": source}, rule_ids=AGENT)
    assert ids(findings) == ["LLM-08"]


def test_safe_tool_is_clean(scan):
    source = "@tool\ndef add(a: int, b: int) -> int:\n    return a + b\n"
    assert scan({"a.py": source}, rule_ids=AGENT) == []


def test_non_tool_function_is_clean(scan):
    source = "import subprocess\ndef helper(cmd):\n    subprocess.run(cmd)\n"
    assert scan({"a.py": source}, rule_ids=AGENT) == []


def test_dangerous_toolkits_and_flags(scan):
    source = (
        "tools = [ShellTool(), PythonREPLTool()]\n"
        "agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)\n"
        "extra = load_tools(['terminal', 'wikipedia'])\n"
        "safe = load_tools(['wikipedia'])\n"
        "ok = create_agent(llm, allow_dangerous_code=False)\n"
    )
    findings = scan({"a.py": source}, rule_ids=AGENT)
    assert [f.line for f in findings] == [1, 1, 2, 3]
    assert all(f.rule_id == "LLM-08" for f in findings)


def test_destructive_tool_without_confirmation(scan):
    source = "@tool\ndef delete_file(path: str):\n    os.remove(path)\n    return 'ok'\n"
    findings = scan({"a.py": source}, rule_ids=("LLM-09",))
    assert ids(findings) == ["LLM-09"]


def test_destructive_tool_with_confirmation_is_clean(scan):
    with_param = "@tool\ndef delete_file(path: str, confirmed: bool):\n    os.remove(path)\n"
    with_call = "@tool\ndef drop(name: str):\n    if not ask_user('sure?'):\n        return\n    db.drop(name)\n"
    assert scan({"a.py": with_param}, rule_ids=("LLM-09",)) == []
    assert scan({"b.py": with_call}, rule_ids=("LLM-09",)) == []


def test_destructive_sql_string_in_tool(scan):
    source = "@tool\ndef wipe(table: str):\n    cur.execute('DELETE FROM logs')\n"
    assert ids(scan({"a.py": source}, rule_ids=("LLM-09",))) == ["LLM-09"]


# -- LLM-12: no token cap ------------------------------------------------------------------


def test_missing_max_tokens(scan):
    source = (
        "a = client.chat.completions.create(model='m', messages=[])\n"
        "b = client.chat.completions.create(model='m', messages=[], max_tokens=100)\n"
        "c = client.responses.create(model='m', input='x', max_output_tokens=50)\n"
        "d = client.chat.completions.create(**params)\n"
        "e = client.responses.create(model='m', input='x')\n"
    )
    findings = scan({"a.py": source}, rule_ids=("LLM-12",))
    assert [f.line for f in findings] == [1, 5]
