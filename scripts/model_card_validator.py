#!/usr/bin/env python3
"""Model Card Validator - AI Act Compliance"""

import argparse
import sys
from pathlib import Path
import yaml

REQUIRED = {
    "model_details": ["name", "version", "date", "type", "architecture"],
    "intended_use": ["primary_uses", "out_of_scope_uses", "target_users"],
    "training_data": ["datasets", "preprocessing", "data_sources"],
    "evaluation": ["metrics", "datasets", "results"],
    "ethical_considerations": ["bias_analysis", "fairness_assessment", "harmful_use_mitigation"],
    "privacy_security": ["privacy_measures", "data_protection", "security_measures"]
}

def validate(path: Path) -> dict:
    result = {"file": str(path), "valid": True, "errors": [], "warnings": [], "score": 100}
    try:
        with open(path) as f:
            card = yaml.safe_load(f)
        if not card:
            return {"file": str(path), "valid": False, "errors": ["Empty file"], "score": 0}
        
        for section, fields in REQUIRED.items():
            if section not in card:
                result["errors"].append(f"Missing: {section}")
                result["score"] -= 15
                continue
            for field in fields:
                if field not in card[section]:
                    result["errors"].append(f"Missing: {section}.{field}")
                    result["score"] -= 5
        
        privacy = card.get("privacy_security", {})
        if "data_subject_rights" not in privacy:
            result["warnings"].append("Missing: data_subject_rights")
        if "legal_basis" not in privacy:
            result["warnings"].append("Missing: legal_basis")
        
        result["valid"] = len(result["errors"]) == 0
        result["score"] = max(0, result["score"])
    except Exception as e:
        result = {"file": str(path), "valid": False, "errors": [str(e)], "score": 0}
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    args = parser.parse_args()
    
    path = Path(args.path)
    files = list(path.glob("*.yml")) + list(path.glob("*.yaml")) if path.is_dir() else [path]
    results = [validate(f) for f in files]
    
    print("\n" + "=" * 60)
    print("📋 MODEL CARD VALIDATION")
    print("=" * 60)
    
    for r in results:
        status = "✅ COMPLIANT" if r["valid"] else "❌ NON-COMPLIANT"
        print(f"\n📄 {Path(r['file']).name}: {status} ({r['score']}/100)")
        for e in r["errors"]:
            print(f"   ❌ {e}")
        for w in r["warnings"]:
            print(f"   ⚠️  {w}")
    
    valid = sum(1 for r in results if r["valid"])
    print("\n" + "=" * 60)
    print(f"✅ Compliant: {valid}/{len(results)}")
    print("=" * 60)
    
    sys.exit(0 if valid == len(results) else 1)

if __name__ == "__main__":
    main()
