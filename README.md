# GitOps for Compliant AI (Azure UAE)

Automate compliance in ML pipelines using Terraform + Azure.

## Quick Start
```bash
pip install -r requirements.txt
python scripts/pii_scanner.py --path ./sample_data
python scripts/model_card_validator.py --path ./model_cards
```

## Azure Resources (UAE North Region)
- Storage Account with encryption & lifecycle policies
- Azure Monitor diagnostic logging
- Key Vault for secrets management
- RBAC access controls
