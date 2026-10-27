# Security policy

## Reporting a vulnerability in slopguard

Please report privately through GitHub's "Report a vulnerability" feature on this repository
(Security tab), not in a public issue. Include the version, how to reproduce, and the impact you see.

Areas that matter most:

- slopguard parsing or scanning untrusted code. It must only parse with `ast` and never import or
  execute scanned code; any way to make it run code from the scanned project is a vulnerability.
- The sandbox used for generated tests (`slopguard gen-tests --run`): an escape, or tests reaching
  the network or host files when a backend claims to prevent that.
- Leaking secrets: findings mask matched values, and logs must never print a full credential.
- The GitHub Action: anything that lets a pull request from a fork run code with write access.

## What slopguard does not promise

It reports risk. A clean scan is not proof of safety, and fixes proposed by `slopguard fix` need
human review. Running it on code you are not allowed to test is your responsibility.
