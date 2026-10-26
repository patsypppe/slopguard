from conftest import ids

# Secret-looking values are built at runtime so no real-looking key is committed.
OPENAI = "sk-" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3kL6"
ANTHROPIC = "sk-ant-" + "Xy7Zq2Wv9Lm4Np6Rt8Bd1Fg3Hj5Kc"
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"


def test_detects_openai_key(scan):
    findings = scan({"app.py": f'client = OpenAI(api_key="{OPENAI}")\n'}, rule_ids=("SEC-01",))
    assert ids(findings) == ["SEC-01"]
    assert "OpenAI" in findings[0].message


def test_detects_anthropic_before_openai_pattern(scan):
    findings = scan({"app.py": f'KEY = "{ANTHROPIC}"\n'}, rule_ids=("SEC-01",))
    assert "Anthropic" in findings[0].message


def test_detects_aws_key_in_env_file(scan):
    findings = scan({".env": f"AWS_ACCESS_KEY_ID={AWS}\n"}, rule_ids=("SEC-01",))
    assert ids(findings) == ["SEC-01"]


def test_secret_is_masked_in_output(scan):
    finding = scan({"app.py": f'k = "{OPENAI}"\n'}, rule_ids=("SEC-01",))[0]
    assert OPENAI not in finding.excerpt
    assert OPENAI not in finding.message


def test_generic_assignment_with_high_entropy(scan):
    findings = scan({"cfg.py": 'db_password = "q9X$kP2mZr7LwT4b"\n'}, rule_ids=("SEC-01",))
    assert ids(findings) == ["SEC-01"]


def test_placeholders_and_env_reads_are_clean(scan):
    source = (
        'api_key = "your-api-key-here"\n'
        'token = "<token>"\n'
        'secret = os.environ["SECRET"]\n'
        'password = "changeme-please"\n'
    )
    assert scan({"ok.py": source}, rule_ids=("SEC-01",)) == []


def test_low_entropy_value_is_clean(scan):
    assert scan({"ok.py": 'api_key = "aaaaaaaaaaaaaaaaaaaa"\n'}, rule_ids=("SEC-01",)) == []
