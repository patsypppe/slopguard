# 0001: JavaScript and TypeScript support is deferred

Status: accepted for 1.0. Revisit after 1.0 using the criteria below.

## Context

The roadmap listed a "JS/TS decision" for Phase 4. AI-generated code is not only Python, and the
tool that inspired this project's capability list (vibechck) targets JavaScript, TypeScript and
Python.

## Decision

slopguard 1.0 analyses **Python only**. JavaScript and TypeScript files are ignored, silently, as
any other unsupported file type.

## Why

- The valuable part, the taint engine, is written against Python's `ast`. A JS/TS version needs a
  second parser (tree-sitter), a second set of sources, sinks and SDK names (`openai`, `@anthropic-ai/sdk`,
  `ai`, LangChain.js), and its own benchmark corpus. That is a second product, not a flag.
- Shipping a thin JS/TS mode would mostly repeat the pattern checks that already exist elsewhere,
  and would dilute the part that is new: LLM-specific flow analysis with measured precision.
- Package checks (HAL rules) would need npm registry lookups and a different alias and typosquat model.
- Every rule needs positive and negative fixtures and a measured false-positive rate on real code.
  We have that for Python (see `docs/real-world-check.md`) and would not have it for JS/TS.

## Revisit when

1. At least three users or contributors ask for it with a concrete project in mind.
2. A contributor commits to maintaining the JS/TS rule set and its corpus.
3. The rule engine has been split so rules declare their language, with Python behaviour unchanged.

## Consequences

- The README says "Python" wherever it matters, and `slopguard scan` on a JS project reports
  `0 files scanned`. That is easy to misread as "clean", so the terminal output should say when no
  supported files were found (tracked as a follow-up).
