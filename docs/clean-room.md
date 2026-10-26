# Clean-room record

slopguard covers some of the same capability classes as other AI-code linters, notably
`vibechck` (npm, AGPL-3.0-or-later). To keep slopguard free to use under the MIT licence,
it was built clean-room.

## Sources used

| Date | Source | What was taken |
| --- | --- | --- |
| 2026-10-26 | Public README and npm metadata of `vibechck` (description, keywords, dependency names) | The list of capability classes, such as "detect hollow functions" and "detect hallucinated packages" |
| 2026-10-26 | PyPI and npm listings for `slopcheck` | Existence of the project and its one-line description only |

## Not used

- The source code, repository, tarball or tests of any of these tools.
- Their regular expressions, rule definitions, thresholds, messages, config schema or
  file layout.

## Rules for contributors

1. Capability classes are ideas and may be reimplemented. Implementations must be your own.
2. If you have read another tool's source, do not write the matching slopguard rule.
3. Cite the public reference for each rule (CWE, OWASP, vendor documentation) in the rule's
   metadata, not another tool's behaviour.
4. Other tools may be run as black boxes for benchmarking. Never import, vendor or call
   them from the shipped package.

This note is a record of intent, not legal advice.
