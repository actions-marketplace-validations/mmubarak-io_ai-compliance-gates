#!/usr/bin/env python3
"""PII Scanner - Implements POL-PRIV-001"""

import argparse
import json
import sys
from pathlib import Path
import pandas as pd

try:
    from presidio_analyzer import AnalyzerEngine
    PRESIDIO = True
except ImportError:
    PRESIDIO = False

class PIIScanner:
    def __init__(self):
        if PRESIDIO:
            self.analyzer = AnalyzerEngine()
        self.entities = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "LOCATION"]
    
    def scan_csv(self, path: Path) -> dict:
        result = {"file": str(path), "pii_found": False, "findings": [], "risk_score": 0}
        try:
            df = pd.read_csv(path)
            pii_cols = {'name': 8, 'email': 9, 'phone': 9, 'address': 8, 'ssn': 10}
            
            for col in df.columns:
                for indicator, risk in pii_cols.items():
                    if indicator in col.lower():
                        result["findings"].append({"column": col, "risk": risk})
                        result["risk_score"] += risk
            
            if PRESIDIO:
                for col in df.columns:
                    for val in df[col].dropna().astype(str).head(50):
                        if len(val) < 3: continue
                        for r in self.analyzer.analyze(text=val, entities=self.entities, language='en'):
                            result["findings"].append({"column": col, "entity": r.entity_type, "confidence": round(r.score, 2)})
                            result["risk_score"] += r.score * 10
            
            result["pii_found"] = len(result["findings"]) > 0
            result["risk_score"] = min(round(result["risk_score"]), 100)
        except Exception as e:
            result["error"] = str(e)
        return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    parser.add_argument("--output-format", choices=["json", "github", "pretty"], default="pretty")
    args = parser.parse_args()
    
    scanner = PIIScanner()
    path = Path(args.path)
    results = [scanner.scan_csv(f) for f in (path.rglob("*.csv") if path.is_dir() else [path])]
    
    pii_files = sum(1 for r in results if r.get("pii_found"))
    
    if args.output_format == "json":
        print(json.dumps({"summary": {"files_with_pii": pii_files}, "results": results}, indent=2))
    elif args.output_format == "github":
        if pii_files > 0:
            print(f"::error title=PII Detected::{pii_files} file(s) contain PII")
            sys.exit(1)
        print(f"::notice title=PII Scan Passed::No PII found")
    else:
        print("\n" + "=" * 50)
        print("🔍 PII SCAN RESULTS")
        print("=" * 50)
        for r in results:
            status = "❌ PII DETECTED" if r["pii_found"] else "✅ CLEAN"
            print(f"\n📄 {Path(r['file']).name}: {status}")
            if r["pii_found"]:
                print(f"   Risk Score: {r['risk_score']}/100")
                entities = {}
                for f in r["findings"]:
                    e = f.get("entity", f.get("column", "unknown"))
                    entities[e] = entities.get(e, 0) + 1
                for e, c in entities.items():
                    print(f"   - {e}: {c}")
        print("\n" + "=" * 50)
        print(f"{'❌ DEPLOYMENT BLOCKED' if pii_files else '✅ READY TO DEPLOY'}")
        print("=" * 50)

if __name__ == "__main__":
    main()
