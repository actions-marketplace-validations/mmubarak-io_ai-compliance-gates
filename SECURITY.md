# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `v1.x`  | ✅ |
| `main`  | ✅ (development; may change without notice) |

Pin adopting workflows to a release tag (`@v1`), not to `main`.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it through GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/MohamedMubarak123/gitops-compliant-ai/security/advisories/new).
That channel is private to the maintainers until an advisory is published.

Please include:

- what the issue is and which component it affects (a gate script, a
  composite action, the Rego pack, the reusable workflow);
- how to reproduce it, ideally as a minimal repo or workflow;
- what an attacker gains.

You can expect an acknowledgement within 7 days and an assessment within 30.

## What counts as a vulnerability here

This project is a CI gate, so its threat model is a little unusual. All of
these are in scope:

- **A gate that passes when it should block.** A false negative in the PII
  scanner, the model card validator or the Rego pack is a security issue,
  not just a bug. It produces an evidence pack asserting compliance that
  was never verified.
- **A gate that reports success without checking anything.** Scanning zero
  files must exit `2` (misconfigured), never `0`.
- **Script or template injection** through action inputs, config files or
  scanned data.
- **Supply-chain weaknesses** in how the actions install their tools, such
  as an unpinned or unverified download.
- **Evidence tampering**: anything that lets a run produce an evidence pack
  that misrepresents what was checked.

Out of scope: findings that require an already-compromised runner, and
false *positives* in the recognizers (open those as normal issues).

## Handling of personal data

Every fixture in this repository is synthetic. If you believe real personal
data has been committed here, report it through the private channel above
and it will be treated as a security incident, not a normal issue.
