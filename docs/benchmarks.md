# Benchmark: slopguard against other scanners

Generated 2026-10-27 by `benchmarks/compare.py`. Do not edit by hand.

## What this measures, and what it does not

- **Corpus:** 21 files with known problems and 13 safe files in `benchmarks/corpus/`. The maintainers wrote it, and it is built around the problems slopguard targets. It is a *coverage* check on LLM-era problems, **not** a general quality ranking: Bandit and Semgrep are broader tools that were not built for these cases.
- **Method:** each tool runs as an external program and only its JSON report is read. A tool *flags* a file if it reports at least one finding at or above the severity shown (its own scale mapped to low / medium / high). Per-rule scoring is not possible because the rule sets differ.
- **Semgrep** ran with the public community rules of `semgrep-rules` at `16b9e6d`, not its commercial packs. The `ai/` folder holds SDK best-practice lints (missing user id, missing system prompt, no error handling), so it is reported as its own row instead of being mixed with the security rules. The rules are used locally for this comparison only and are not redistributed.
- **vibechck** is AGPL-3.0. It is run as a black box and none of its code is used by slopguard.
- slopguard's own rules were tuned against this corpus, so its numbers here are optimistic. The two files labelled `gap_*` are known misses and count against it.

## Files flagged: Any severity

| Tool | LLM-app security | Hardcoded secrets | Incomplete code | Hallucinated packages | False alarms on safe files |
| --- | --- | --- | --- | --- | --- |
| slopguard | 13/15 | 1/1 | 4/4 | 1/1 | 0/13 |
| Bandit | 6/15 | 1/1 | 1/4 | 0/1 | 2/13 |
| Semgrep (python rules) | 8/15 | 0/1 | 2/4 | 0/1 | 2/13 |
| Semgrep (ai rules) | 13/15 | 0/1 | 0/4 | 0/1 | 8/13 |
| vibechck | 4/15 | 0/1 | 3/4 | 0/1 | 4/13 |

## Files flagged: Medium severity or higher

| Tool | LLM-app security | Hardcoded secrets | Incomplete code | Hallucinated packages | False alarms on safe files |
| --- | --- | --- | --- | --- | --- |
| slopguard | 12/15 | 1/1 | 3/4 | 1/1 | 0/13 |
| Bandit | 6/15 | 0/1 | 0/4 | 0/1 | 1/13 |
| Semgrep (python rules) | 8/15 | 0/1 | 2/4 | 0/1 | 2/13 |
| Semgrep (ai rules) | 12/15 | 0/1 | 0/4 | 0/1 | 6/13 |
| vibechck | 0/15 | 0/1 | 2/4 | 0/1 | 1/13 |

## Tools and timing

| Tool | Version | Time on corpus | Note |
| --- | --- | --- | --- |
| slopguard | 0.1.0 | 0.1s |  |
| Bandit | 1.9.4 | 0.2s | 1 file(s) it could not parse |
| Semgrep (python rules) | 1.182.1 | 17.4s | public semgrep-rules @ 16b9e6d |
| Semgrep (ai rules) | 1.182.1 | 5.2s | public semgrep-rules @ 16b9e6d |
| vibechck | 0.2.9 (npm) | 0.7s | AGPL-3.0; run as a black box |

## Per file: rule IDs reported at medium severity or higher

A tool can flag a file for an unrelated reason, so read the rule IDs, not only the marks.

<details><summary>Show every file</summary>

| File | Expected | slopguard | Bandit | Semgrep (python rules) | Semgrep (ai rules) | vibechck |
| --- | --- | --- | --- | --- | --- | --- |
| `vulnerable/gap_cross_function.py` | LLM-02 | - | `B307` | `eval-detected` | `anthropic-missing-metadata-user-id-python`, `anthropic-missing-system-prompt-python`, `anthropic-no-error-handling` +1 | - |
| `vulnerable/gap_instance_attribute.py` | LLM-02 | - | `B102` | `exec-detected` | `anthropic-missing-metadata-user-id-python`, `anthropic-missing-system-prompt-python`, `anthropic-no-error-handling` +1 | - |
| `vulnerable/hal03_typo.py` | HAL-03 | `HAL-03` | - | - | - | - |
| `vulnerable/inc_chat_residue.py` | INC-05, INC-08 | `INC-05`, `INC-08` | - | - | - | - |
| `vulnerable/inc_placeholder.py` | INC-01 | `INC-01` | - | - | - | - |
| `vulnerable/inc_stub.py` | INC-02 | `INC-02` | - | `pass-body-fn` | - | `hollow-function` |
| `vulnerable/inc_swallow.py` | INC-04 | - | - | `unspecified-open-encoding` | - | `unlogged-error` |
| `vulnerable/llm01_format.py` | LLM-01 | `LLM-01` | - | - | `anthropic-missing-metadata-user-id-python`, `anthropic-no-error-handling`, `anthropic-user-input-in-system-prompt-python` | - |
| `vulnerable/llm01_system_dict.py` | LLM-01 | `LLM-01` | - | - | `openai-missing-moderation`, `openai-missing-user-parameter-python`, `openai-no-error-handling` | - |
| `vulnerable/llm01_system_prompt.py` | LLM-01 | `LLM-01` | - | - | `anthropic-missing-metadata-user-id-python`, `anthropic-no-error-handling` | - |
| `vulnerable/llm02_eval_openai.py` | LLM-02 | `LLM-02` | `B307` | `eval-detected` | `openai-missing-moderation`, `openai-missing-system-message-python`, `openai-missing-user-parameter-python` +3 | - |
| `vulnerable/llm02_exec_langchain.py` | LLM-02 | `LLM-02` | `B102` | `exec-detected` | - | - |
| `vulnerable/llm03_shell.py` | LLM-03 | `LLM-03` | `B602` | `dangerous-subprocess-use-audit`, `subprocess-shell-true` | `anthropic-missing-metadata-user-id-python`, `anthropic-missing-system-prompt-python`, `anthropic-no-error-handling` +1 | - |
| `vulnerable/llm04_sql.py` | LLM-04 | `LLM-04` | - | - | `anthropic-missing-metadata-user-id-python`, `anthropic-missing-system-prompt-python`, `anthropic-no-error-handling` +1 | - |
| `vulnerable/llm05_path.py` | LLM-05 | `LLM-05` | - | `unspecified-open-encoding` | `anthropic-missing-metadata-user-id-python`, `anthropic-missing-system-prompt-python`, `anthropic-no-error-handling` +1 | - |
| `vulnerable/llm06_url.py` | LLM-06 | `LLM-06` | - | `use-raise-for-status` | `anthropic-missing-metadata-user-id-python`, `anthropic-missing-system-prompt-python`, `anthropic-no-error-handling` +1 | - |
| `vulnerable/llm08_shell_tool.py` | LLM-08 | `LLM-08` | `B602` | `dangerous-subprocess-use-audit`, `subprocess-shell-true` | `mcp-command-injection-python` | - |
| `vulnerable/llm08_toolkit.py` | LLM-08 | `LLM-08` | - | - | - | - |
| `vulnerable/llm09_delete_tool.py` | LLM-08, LLM-09 | `LLM-09`, `LLM-08` | - | - | - | - |
| `vulnerable/llm12_unbounded.py` | LLM-12 | - | - | - | `openai-missing-max-tokens-python`, `openai-missing-moderation`, `openai-missing-system-message-python` +2 | - |
| `vulnerable/sec_password.py` | SEC-01 | `SEC-01` | - | - | - | - |
| `safe/safe_abstract.py` | none | - | - | - | - | `hollow-function` |
| `safe/safe_add_tool.py` | none | - | - | - | - | - |
| `safe/safe_allowlist_command.py` | none | - | - | `dangerous-subprocess-use-audit` | `anthropic-missing-metadata-user-id-python`, `anthropic-missing-system-prompt-python`, `anthropic-no-error-handling` +1 | - |
| `safe/safe_confirmed_delete.py` | none | - | - | - | - | - |
| `safe/safe_constant_eval.py` | none | - | `B307` | - | - | - |
| `safe/safe_env_key.py` | none | - | - | - | - | - |
| `safe/safe_json_output.py` | none | - | - | - | `anthropic-missing-metadata-user-id-python`, `anthropic-missing-system-prompt-python`, `anthropic-no-error-handling` +1 | - |
| `safe/safe_literal_eval.py` | none | - | - | - | `anthropic-missing-metadata-user-id-python`, `anthropic-missing-system-prompt-python`, `anthropic-no-error-handling` +1 | - |
| `safe/safe_logged_except.py` | none | - | - | `unspecified-open-encoding` | - | - |
| `safe/safe_parameterised_sql.py` | none | - | - | - | `anthropic-missing-metadata-user-id-python`, `anthropic-missing-system-prompt-python`, `anthropic-no-error-handling` +1 | - |
| `safe/safe_real_imports.py` | none | - | - | - | - | - |
| `safe/safe_token_cap.py` | none | - | - | - | `openai-missing-moderation`, `openai-missing-system-message-python`, `openai-missing-user-parameter-python` +1 | - |
| `safe/safe_user_message.py` | none | - | - | - | `anthropic-missing-metadata-user-id-python`, `anthropic-no-error-handling` | - |

</details>
