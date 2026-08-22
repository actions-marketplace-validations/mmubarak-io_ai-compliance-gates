# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Adopters should pin to a release tag (`@v1`). `main` may change without notice.

## [1.0.0] - 2026-08-22

First tagged release. Everything below landed before `v1`, but is listed
because the fail-open fixes change gate behaviour in ways an adopter needs
to know about.

### Fixed: gates that reported success without checking

These are the reason this release exists. Each one could produce a green
check, and an evidence pack asserting compliance, for a check that never
actually ran.

- **Scanning nothing is no longer a pass.** `pii_scanner.py` and
  `model_card_validator.py` now exit `2` (misconfigured) when the target
  resolves to zero files. Previously a mistyped `data-path` produced a
  passing gate. Pass `--allow-empty` (or the `allow-empty` action input) if
  scanning nothing is genuinely expected.
- **`--output-format json` now exits non-zero on findings.** The JSON branch
  of `pii_scanner.py` returned `0` even when PII was detected, silently
  disarming the gate for anyone consuming JSON in CI.
- **Model cards are discovered recursively.** The validator used a
  non-recursive glob, so cards in nested directories were skipped and the
  gate passed without seeing them.
- **The policy pack evaluates files together.** `conftest` now runs with
  `--combine`. Per-file evaluation made `POL-PRIV-010` fire a false positive
  on every file lacking a diagnostic setting, and made `POL-PRIV-007` pass
  silently whenever `variables.tf` wasn't in the path list.
- **Terraform paths that match nothing now fail.** The policy action exits
  `2` instead of checking an empty file list.
- **Gates that never ran are recorded.** The evidence pack lists every gate
  with an explicit `NOT_RUN`, `NO_DATA` or `MALFORMED_REPORT` status instead
  of omitting it. A crashed gate used to vanish from the artifact entirely,
  leaving a pack that read as a clean bill of health.

### Fixed: detection accuracy

- Column-name heuristics match on token boundaries, so `name` no longer
  flags `filename` or `hostname`.
- UAE phone detection uses digit lookarounds instead of `\b`, so a long
  numeric id such as `990501234567` is no longer read as a phone number.
- Risk scores take the highest risk per column instead of summing every
  finding, which double-counted a column caught by both name and value.
- `disable_patterns` now also suppresses Presidio's built-in recognizers,
  and configured `risk` values are honoured on the Presidio path. The same
  config previously produced different results depending on whether
  Presidio happened to be installed.

### Security

- **The reference module now defaults to deny at the network layer.**
  `azurerm_storage_account` gained `network_rules { default_action = "Deny" }`
  and `azurerm_key_vault` gained `network_acls { default_action = "Deny" }`.
  `public_network_access_enabled = false` alone still left both services
  reachable through network rules that default to Allow.
- **Two new POL-SEC-001 rules** enforce exactly that, so the policy pack
  catches the gap itself instead of relying on an external scanner.
- **The conftest download is checksum-verified.** `policy-check` pins the
  SHA-256 of the release tarball and refuses to install on mismatch. Bumping
  `conftest-version` now requires supplying the matching `conftest-sha256`.
- **Action inputs are passed through `env`,** not interpolated into shell
  script bodies. Terraform path globs are expanded without `eval`, so an
  input containing shell metacharacters is treated as data.
- All composite action steps run under `set -euo pipefail`.

### Added

- `--allow-empty` flag and matching `allow-empty` action inputs.
- `--fail-on-violation` flag on the evidence pack generator.
- Config validation for `compliance.config.yml`: malformed patterns, bad
  risk values and mis-shaped schemas now produce a specific message naming
  the offending key, instead of a `KeyError` surfacing as a bogus result.
- `examples/terraform/non_compliant/`, a deliberately non-compliant
  Terraform fixture, split across two files so the cross-file rules are
  actually exercised. CI blocks on it as a negative test.
- Python 3.11, 3.12 and 3.13 CI matrix. The scripts used `str | None`
  annotations, which require 3.10+, while nothing declared a minimum at all.
- Community health files: `SECURITY.md`, `CODE_OF_CONDUCT.md`,
  issue and PR templates, `CODEOWNERS`, Dependabot config.

### Changed

- **Minimum Python is now 3.11.** Python 3.9 reached end of life in October
  2025, and pandas 3.x requires 3.11 or newer. A toolkit whose job is to
  assert compliance should not run its gates on an unpatched interpreter.
  The CI matrix is now 3.11, 3.12 and 3.13.
- **The composite actions install from `requirements.txt`.** They previously
  ran `pip install pandas pyyaml` with no constraint, so an adopter's gate
  used whatever version happened to be newest that day and could drift from
  the versions this project tests. The gates that only need PyYAML use the
  same file as a constraints file.
- Dependency floors stay permissive (`pandas>=2.0.0`, `pyyaml>=6.0`). Both
  pandas 2.3.3 and pandas 3.0.5 pass the full suite on 3.12, so narrowing
  the floor would drop working configurations for no gain.

### Changed (CI)

- The Trivy job now actually scans. It had two independent faults: the step
  referenced `aquasecurity/trivy-action@0.28.0` while the tag is `v0.28.0`,
  so the job died at setup; and after fixing that, trivy-action `v0.33.1`
  defaults to trivy `v0.65.0`, which has no GitHub release, so its installer
  exited 1 and every scan step was silently skipped. Now pinned to
  trivy-action `v0.33.1` with `version: v0.74.0`, and
  `examples/terraform/non_compliant` excluded because that fixture is
  insecure by design.
- `terraform fmt -check` passes. It had never been run against
  `infrastructure/`, so the job failed and `init` and `validate` never ran.

### Changed

- The evidence pack format is now version `1.1`: gates carry a
  `report_status` field and the pack carries `gates_not_run`.
- Conftest runs once per check rather than twice; GitHub annotations are
  rendered from the JSON report.
- Reusable workflow and README examples reference `@v1` instead of `@main`.

[1.0.0]: https://github.com/MohamedMubarak123/gitops-compliant-ai/releases/tag/v1.0.0
