# Demo Guide

## Demo 1: PII Scanner
```bash
python scripts/pii_scanner.py --path ./sample_data/customers.csv
python scripts/pii_scanner.py --path ./sample_data/customers_anonymized.csv
```

## Demo 2: Model Card Validator
```bash
python scripts/model_card_validator.py --path ./model_cards/churn_model_v1.yml
python scripts/model_card_validator.py --path ./model_cards/churn_model_v2_compliant.yml
```

## Demo 3: Show Terraform code
Open infrastructure/modules/ml-platform/main.tf
