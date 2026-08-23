# Demo Guide

## Demo 1: UAE PII gate
```bash
# Blocked: Emirates IDs, +971 phones, AE IBANs detected
python scripts/pii_scanner.py --path ./examples/sample_data/customers.csv

# Passes: anonymized dataset
python scripts/pii_scanner.py --path ./examples/sample_data/customers_anonymized.csv
```

## Demo 2: Model card validation (EU AI Act)
```bash
# Fails with article-level citations
python scripts/model_card_validator.py --path ./examples/model_cards/non_compliant

# Passes 100/100
python scripts/model_card_validator.py --path ./examples/model_cards/compliant
```

## Demo 3: Policy enforcement with OPA
```bash
# Passes: Terraform satisfies the policy register
conftest test --parser hcl2 -p policy \
  infrastructure/modules/ml-platform/main.tf \
  infrastructure/modules/ml-platform/variables.tf

# Now edit main.tf: set public_network_access_enabled = true
# Re-run: fails with [POL-SEC-001] + the PDPL article
```

## Demo 4: Evidence pack
```bash
mkdir -p reports
python scripts/pii_scanner.py --path ./examples/sample_data/customers_anonymized.csv \
  --output-format json --output-file reports/pii_scan.json
python scripts/model_card_validator.py --path ./examples/model_cards/compliant \
  --output-format json --output-file reports/model_cards.json
conftest test --parser hcl2 -p policy \
  infrastructure/modules/ml-platform/*.tf --output json > reports/conftest.json
python scripts/generate_evidence_pack.py \
  --pii-report reports/pii_scan.json \
  --model-card-report reports/model_cards.json \
  --conftest-report reports/conftest.json
cat evidence/evidence_pack.md
