#!/usr/bin/env python3
"""Model Card Validator — Implements POL-GOV-002.

Validates model cards against documentation requirements derived from:
  - EU AI Act (Regulation 2024/1689), Annex IV technical documentation
  - UAE Personal Data Protection Law (Federal Decree-Law No. 45/2021)
  - GDPR Art. 13-14 transparency obligations

Each required section is mapped to the specific provision it satisfies,
so a failing check tells you *which regulation* you're not meeting.
"""

import argparse
import json
import sys
from pathlib import Path

import yaml

# section -> (fields, regulation basis)
REQUIRED = {
    "model_details": {
        "fields": ["name", "version", "date", "type", "architecture"],
        "basis": "EU AI Act Annex IV(1) — general description of the AI system",
    },
    "intended_use": {
        "fields": ["primary_uses", "out_of_scope_uses", "target_users"],
        "basis": "EU AI Act Art. 13 — transparency; intended purpose and misuse",
    },
    "training_data": {
        "fields": ["datasets", "preprocessing", "data_sources"],
        "basis": "EU AI Act Annex IV(2)(d) — data requirements & provenance; UAE PDPL Art. 5 (lawful collection)",
    },
    "evaluation": {
        "fields": ["metrics", "datasets", "results"],
        "basis": "EU AI Act Annex IV(2)(g) — validation and testing procedures",
    },
    "ethical_considerations": {
        "fields": ["bias_analysis", "fairness_assessment", "harmful_use_mitigation"],
        "basis": "EU AI Act Art. 9 — risk management; Art. 10(2)(f) — bias examination",
    },
    "privacy_security": {
        "fields": ["privacy_measures", "data_protection", "security_measures"],
        "basis": "UAE PDPL Art. 20 — security of processing; GDPR Art. 32",
    },
}

RECOMMENDED = {
    "privacy_security.data_subject_rights": "UAE PDPL Art. 13-18 — access, rectification, erasure rights",
    "privacy_security.legal_basis": "UAE PDPL Art. 4 — lawful basis for processing; GDPR Art. 6",
    "model_details.risk_classification": "EU AI Act Art. 6 — risk-based classification",
    "evaluation.human_oversight": "EU AI Act Art. 14 — human oversight measures",
}


def load_schema(config_path: str | None):
    """Return (required, recommended), replaced by user config if provided."""
    required, recommended = REQUIRED, RECOMMENDED
    if config_path:
        user = (yaml.safe_load(Path(config_path).read_text()) or {}).get("model_cards", {})
        if "required" in user:
            required = user["required"]
        if "recommended" in user:
            recommended = user["recommended"]
    return required, recommended


def validate(path: Path, required: dict = REQUIRED, recommended: dict = RECOMMENDED) -> dict:
    result = {"file": str(path), "policy_id": "POL-GOV-002", "valid": True,
              "errors": [], "warnings": [], "score": 100}
    try:
        with open(path) as f:
            card = yaml.safe_load(f)
        if not card:
            return {**result, "valid": False, "errors": [{"issue": "Empty file"}], "score": 0}

        for section, spec in required.items():
            if section not in card:
                result["errors"].append({"issue": f"Missing section: {section}", "basis": spec["basis"]})
                result["score"] -= 15
                continue
            for field in spec["fields"]:
                if field not in (card[section] or {}):
                    result["errors"].append({"issue": f"Missing field: {section}.{field}", "basis": spec["basis"]})
                    result["score"] -= 5

        for dotted, basis in recommended.items():
            section, field = dotted.split(".")
            if field not in (card.get(section) or {}):
                result["warnings"].append({"issue": f"Recommended: {dotted}", "basis": basis})

        result["valid"] = len(result["errors"]) == 0
        result["score"] = max(0, result["score"])
    except Exception as e:  # noqa: BLE001
        result = {**result, "valid": False, "errors": [{"issue": str(e)}], "score": 0}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True)
    parser.add_argument("--output-format", choices=["json", "github", "pretty"], default="pretty")
    parser.add_argument("--output-file", help="Write JSON results to this file (for evidence pack)")
    parser.add_argument("--config", help="Path to compliance.config.yml (replaces built-in schema)")
    args = parser.parse_args()

    required, recommended = load_schema(args.config)
    path = Path(args.path)
    files = sorted(list(path.glob("*.yml")) + list(path.glob("*.yaml"))) if path.is_dir() else [path]
    results = [validate(f, required, recommended) for f in files]
    valid = sum(1 for r in results if r["valid"])

    report = {
        "policy_id": "POL-GOV-002",
        "check": "model_card_validation",
        "summary": {"cards_checked": len(results), "compliant": valid},
        "results": results,
    }

    if args.output_file:
        Path(args.output_file).write_text(json.dumps(report, indent=2))

    if args.output_format == "json":
        print(json.dumps(report, indent=2))
    elif args.output_format == "github":
        for r in results:
            for e in r["errors"]:
                print(f"::error title=Model Card ({Path(r['file']).name})::{e['issue']} [{e.get('basis','')}]")
    else:
        print("\n" + "=" * 60)
        print("📋 MODEL CARD VALIDATION  (EU AI Act / UAE PDPL / GDPR)")
        print("=" * 60)
        for r in results:
            status = "✅ COMPLIANT" if r["valid"] else "❌ NON-COMPLIANT"
            print(f"\n📄 {Path(r['file']).name}: {status} ({r['score']}/100)")
            for e in r["errors"]:
                print(f"   ❌ {e['issue']}")
                if e.get("basis"):
                    print(f"      ↳ {e['basis']}")
            for w in r["warnings"]:
                print(f"   ⚠️  {w['issue']}")
                print(f"      ↳ {w['basis']}")
        print("\n" + "=" * 60)
        print(f"✅ Compliant: {valid}/{len(results)}")
        print("=" * 60)

    sys.exit(0 if valid == len(results) else 1)


if __name__ == "__main__":
    main()
