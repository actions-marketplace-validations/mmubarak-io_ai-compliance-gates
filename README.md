# AI Compliance Gates

*GitOps for compliant AI: every policy is an executable check that blocks the pipeline.*

[![CI](https://github.com/mmubarak-io/ai-compliance-gates/actions/workflows/ci.yml/badge.svg)](https://github.com/mmubarak-io/ai-compliance-gates/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

**Drop-in compliance gates for ML pipelines**: reusable GitHub Actions that
make UAE PDPL, GDPR, and EU AI Act requirements *machine-enforced* in CI,
not paragraphs in a policy document nobody checks.

```yaml
# .github/workflows/compliance.yml: full adoption in one job
jobs:
  compliance:
    uses: mmubarak-io/ai-compliance-gates/.github/workflows/gates.yml@v1
    with:
      data-path: ./data
      model-cards-path: ./model_cards
      terraform-paths: "infra/*.tf"
```

## Why this exists

Teams shipping ML in the Gulf face three regulatory pressures at once: the
**UAE Personal Data Protection Law** (Federal Decree-Law 45/2021), **GDPR**
for any EU data subjects, and the **EU AI Act** for AI systems touching the
EU market. The usual answer is a compliance spreadsheet that drifts from
reality the day it's written.

This toolkit takes the GitOps answer instead: **every policy is an executable
check that blocks the pipeline.** If your Terraform allows public network
access, the build fails and cites the PDPL article you'd be violating. If a
dataset contains an Emirates ID, it never reaches training.

## The gates

| Action | What it enforces | Regulation |
|--------|------------------|------------|
| `pii-scan` | Datasets are free of PII, including **UAE-specific patterns** (Emirates ID, +971 phones, AE IBANs) that generic scanners miss. Reads CSV, TSV, JSON, JSON Lines and Parquet, compressed or not | UAE PDPL Art. 20, GDPR Art. 32 |
| `model-card-check` | AI documentation is complete; every missing field cites the **EU AI Act article** it fails | EU AI Act Annex IV, Art. 9/13/14 |
| `policy-check` | Terraform satisfies the policy register via **OPA/Conftest**: TLS 1.2, no public access, UAE-only regions, RBAC, audit logging, retention | UAE PDPL Art. 9, 20, 22-23; GDPR Art. 5, 30, 32 |
| `evidence-pack` | Every run emits an **auditor-facing artifact**: what was checked, against which regulation, at which commit | GDPR Art. 5(2), EU AI Act Art. 12 |

Each gate is also a standalone composite action:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: mmubarak-io/ai-compliance-gates/.github/actions/pii-scan@v1
    with:
      path: ./data
  - uses: mmubarak-io/ai-compliance-gates/.github/actions/policy-check@v1
    with:
      terraform-paths: "infra/*.tf"
```

## Make the policies yours

Nothing is hardcoded to this repo's profile. Copy
[`templates/compliance.config.yml`](templates/compliance.config.yml) into
your repo to:

- add your own PII patterns (a KSA Iqama example is included) or disable
  built-in ones
- swap the model card schema for your internal documentation policy or
  another framework (NIST AI RMF, ISO 42001)

and point the `config` input at it. The infrastructure rules live in
[`policy/`](policy/) as plain Rego. Fork the policy pack, keep the engine.
The policy register
([`templates/policy_mapping.yml`](templates/policy_mapping.yml)) maps every
policy to the regulation it implements *and* the executable check that
enforces it. Nothing in it is decorative.

## How the gates fail

A compliance gate is only worth the trust you put in it if it fails in the
right direction. Every gate here follows one contract:

| Exit code | Meaning | CI result |
|-----------|---------|-----------|
| `0` | Checked something, found nothing wrong | ✅ pass |
| `1` | Policy violation: PII found, card incomplete, Terraform non-compliant | ❌ blocked |
| `2` | **Misconfigured**: the gate could not check what it was pointed at | ❌ blocked |

Exit code `2` is the one that matters. A gate pointed at a path that matches
no files does **not** report success: a mistyped `data-path` would otherwise
produce a green check, and an evidence pack asserting compliance for a scan
that examined nothing. If scanning nothing is genuinely expected, opt in
explicitly:

```yaml
- uses: mmubarak-io/ai-compliance-gates/.github/actions/pii-scan@v1
  with:
    path: ./data
    allow-empty: true   # only if an empty data directory is normal for you
```

**Partial coverage fails the same way.** A PII gate pointed at a directory
holding one CSV and fifty Parquet shards used to scan the CSV, find nothing,
and return green for the whole directory, a fail-open wearing the costume of
a pass. The scanner reads every tabular format pandas can (CSV, TSV, JSON,
JSON Lines, Parquet, compressed or not), and anything it still cannot open is
listed as unscanned and blocks the gate. Opt out only deliberately:

```yaml
- uses: mmubarak-io/ai-compliance-gates/.github/actions/pii-scan@v1
  with:
    path: ./data
    allow-unscanned: true   # records the gap instead of blocking on it
```

Files skipped that way stay named in the report and mark their gate
`PARTIAL` in the evidence pack. Never `PASS`.

The same principle runs through the rest of the toolkit:

- An unreadable or malformed input file is treated as a **finding**, not as
  a pass.
- A gate that never ran appears in the evidence pack as `NOT_RUN`, so a
  crashed check can't quietly disappear from the audit artifact.
- A malformed `compliance.config.yml` stops the run with a message naming
  the offending key, rather than being silently ignored.
- The evidence pack carries a `sha256` of its own content and of every gate
  report it was built from. `--verify` recomputes both, so a pack edited
  after generation, or paired with different gate outputs, no longer
  verifies:

  ```bash
  python scripts/generate_evidence_pack.py --verify evidence/evidence_pack.json
  ```

  This is a checksum, not a signature: it detects post-hoc edits, not who
  made them. The `evidence-pack` action exposes the digest as a
  `content-digest` output so you can feed it to
  [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
  and get signed provenance today; native Sigstore attestation is on the
  roadmap.

## Architecture

![ArchiMate architecture for AI Compliance Gates](docs/architecture.svg)

## Try it locally

Requires **Python 3.11+**.

```bash
git clone https://github.com/mmubarak-io/ai-compliance-gates.git
cd ai-compliance-gates
pip install -r requirements.txt

# Watch the PII gate block dirty data (Emirates IDs, UAE phones, IBANs)...
python scripts/pii_scanner.py --path ./examples/sample_data/customers.csv

# ...and pass anonymized data
python scripts/pii_scanner.py --path ./examples/sample_data/customers_anonymized.csv

# Validate model cards against EU AI Act Annex IV
python scripts/model_card_validator.py --path ./examples/model_cards/compliant
python scripts/model_card_validator.py --path ./examples/model_cards/non_compliant  # see it fail
```

All sample data is **synthetic**. The examples double as this repo's
integration tests. CI runs every gate against them, including negative
tests proving the gates actually block.

For NLP-based detection of names and locations (Microsoft Presidio), add
`pip install -r requirements-nlp.txt`; the scanner upgrades automatically.

## UAE-specific PII detection

Generic PII scanners don't know what an Emirates ID looks like. This one does:

| Entity | Pattern | Example (synthetic) |
|--------|---------|---------------------|
| `AE_EMIRATES_ID` | `784-YYYY-NNNNNNN-C` | 784-1985-1234567-1 |
| `AE_PHONE_NUMBER` | +971 / 05X mobile & landline | +971-50-123-4567 |
| `AE_IBAN` | `AE` + 21 digits | AE07 033 1234... |

## Reference infrastructure (Azure UAE North)

`infrastructure/` contains a complete Terraform module for a compliant ML
platform (storage with TLS 1.2/private access/RBAC, Key Vault, Log
Analytics audit trail, compliance tags) that passes the full policy pack.
Use it as a starting point or bring your own Terraform; the `policy-check`
gate works against any HCL.

It is synthetic reference material built from public sources. The `azurerm_*`
arguments come from the [Terraform AzureRM provider
registry](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs),
and `uaenorth`/`uaecentral` are Azure's [published region
names](https://learn.microsoft.com/azure/reliability/regions-list). UAE North
appears because POL-PRIV-003 (data residency, UAE PDPL Art. 22-23) is only
enforceable against a concrete region. It is the executable form of a public
regulatory requirement, not a description of anyone's environment. The module
carries no subscription, tenant or resource identifiers, and its defaults
(`compliantml`, `dev`) are placeholders: it exists so the policy pack has a
realistic target to run against.

## Repository layout

```
├── .github/
│   ├── actions/           # Reusable composite actions (the product)
│   └── workflows/         # ci.yml (dogfooding) + gates.yml (workflow_call)
├── scripts/               # Gate engines: PII scan, model cards, evidence pack
├── policy/                # OPA/Rego policy pack (UAE PDPL / GDPR profile)
├── templates/             # Policy register + compliance.config.yml
├── infrastructure/        # Reference Terraform (Azure UAE North)
├── examples/              # Synthetic fixtures; also the integration tests
│   ├── sample_data/       #   clean + deliberately dirty CSVs
│   ├── model_cards/       #   compliant + non-compliant cards
│   └── terraform/         #   deliberately non-compliant HCL
├── tests/                 # pytest suite
└── docs/                  # ArchiMate architecture (drawio + svg)
```

## Roadmap

- [x] `v1` release tag
- [ ] GitHub Marketplace listing for the individual actions
- [ ] Arabic-language PII detection (Arabic names, addresses)
- [ ] KSA PDPL and Qatar PDPPL policy packs
- [ ] pip-installable CLI for GitLab / Azure DevOps / pre-commit
- [ ] `terraform plan` JSON enforcement for deployed-state drift
- [ ] Signed evidence packs (Sigstore/cosign attestation)

## Contributing

Policy packs for new jurisdictions and region-specific PII recognizers are
especially welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

Release notes live in [CHANGELOG.md](CHANGELOG.md). Security issues,
**including any gate that passes when it should block**, go through the
private channel in [SECURITY.md](SECURITY.md), not a public issue.

## Disclaimer

**Not legal advice.** This project maps technical controls to GDPR, UAE PDPL, and
EU AI Act provisions for engineering convenience. Passing these gates does not by
itself establish legal compliance — validate against the current regulations and
qualified counsel for your jurisdiction. Provided under the MIT License, without
warranty. The "compliant" labels in `examples/` are illustrative sample data, not
a legal determination.

## License

MIT. See [LICENSE](LICENSE).
