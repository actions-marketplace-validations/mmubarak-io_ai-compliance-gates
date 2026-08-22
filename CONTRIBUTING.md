# Contributing

Contributions are welcome — especially new jurisdiction policy packs and
PII recognizers.

## Getting started

```bash
pip install -r requirements.txt pytest
pytest tests/ -v
```

## What we're looking for

- **Policy packs**: Rego rules for other jurisdictions (KSA PDPL, Qatar
  PDPPL, DIFC DP Law). Follow the pattern in `policy/terraform_compliance.rego`:
  every rule tagged with a policy ID and the regulation article it enforces.
- **PII recognizers**: region-specific patterns (national IDs, phone formats,
  IBANs). Add the pattern to `scripts/pii_scanner.py` or contribute it as a
  documented `custom_patterns` example in `templates/compliance.config.yml`,
  with a test either way.
- **Model card schemas**: alternative profiles (e.g. NIST AI RMF, ISO 42001)
  as config files.

## Ground rules

- Every gate change needs a test in `tests/`.
- Every policy rule must cite the regulation it enforces — no rules that
  exist "because it seems secure."
- Sample data must be synthetic. Never commit real personal data, even as a
  test fixture.
- Keep the core dependency-light; heavyweight dependencies (NLP models etc.)
  go behind optional extras.

## Pull requests

Fork, branch, commit (short and simple messages), open a PR against `main`.
CI must be green — the pipeline dogfoods the toolkit against `examples/`,
so a broken gate blocks your PR by design.
