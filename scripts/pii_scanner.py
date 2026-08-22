#!/usr/bin/env python3
"""PII Scanner — Implements POL-PRIV-001 (UAE PDPL Art. 20 / GDPR Art. 32).

Detects PII in tabular data before it enters the ML pipeline, with
UAE-specific recognizers that generic scanners miss:

  - Emirates ID       784-YYYY-NNNNNNN-C
  - UAE phone numbers +971-5X / 05X mobile and landline formats
  - UAE IBAN          AE + 21 digits

Works standalone (regex engine) and upgrades automatically to
Microsoft Presidio NLP detection when installed.
"""

import argparse
import json
import re
import sys
from pathlib import Path

import pandas as pd

try:
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer

    PRESIDIO = True
except ImportError:
    PRESIDIO = False

# ---------------------------------------------------------------------------
# UAE-specific patterns (used by both the regex engine and Presidio)
# ---------------------------------------------------------------------------
UAE_PATTERNS = {
    "AE_EMIRATES_ID": {
        "regex": r"\b784[- ]?(19|20)\d{2}[- ]?\d{7}[- ]?\d\b",
        "risk": 10,
        "description": "Emirates ID number",
    },
    "AE_PHONE_NUMBER": {
        "regex": r"(?:\+971|00971|0)[- ]?(?:2|3|4|6|7|9|5[0245689])[- ]?\d{3}[- ]?\d{4}\b",
        "risk": 8,
        "description": "UAE phone number",
    },
    "AE_IBAN": {
        "regex": r"\bAE\d{2}[- ]?\d{3}[- ]?\d{16}\b",
        "risk": 10,
        "description": "UAE IBAN",
    },
    "EMAIL_ADDRESS": {
        "regex": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
        "risk": 9,
        "description": "Email address",
    },
}

# Column-name heuristics (fast first pass)
PII_COLUMN_HINTS = {
    "name": 8, "email": 9, "phone": 9, "mobile": 9, "address": 8,
    "ssn": 10, "emirates_id": 10, "eid": 10, "passport": 10,
    "iban": 10, "dob": 8, "birth": 8, "national_id": 10,
}


def load_config(path: str | None) -> dict:
    """Merge a user compliance.config.yml over the built-in defaults."""
    import yaml

    cfg = {"patterns": dict(UAE_PATTERNS), "column_hints": dict(PII_COLUMN_HINTS), "sample_rows": 50}
    if path:
        user = (yaml.safe_load(Path(path).read_text()) or {}).get("pii_scan", {})
        cfg["patterns"].update(user.get("custom_patterns", {}))
        for entity in user.get("disable_patterns", []):
            cfg["patterns"].pop(entity, None)
        cfg["column_hints"].update(user.get("column_hints", {}))
        cfg["sample_rows"] = user.get("sample_rows", cfg["sample_rows"])
    return cfg


def build_analyzer(patterns: dict):
    """Presidio analyzer extended with configured recognizers."""
    analyzer = AnalyzerEngine()
    for entity, spec in patterns.items():
        if entity == "EMAIL_ADDRESS":
            continue  # built into Presidio
        analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity=entity,
                patterns=[Pattern(name=entity.lower(), regex=spec["regex"], score=0.85)],
            )
        )
    return analyzer


class PIIScanner:
    BASE_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "LOCATION"]

    @property
    def ENTITIES(self):
        return sorted(set(self.BASE_ENTITIES) | set(self.patterns))

    def __init__(self, sample_rows: int = 50, patterns: dict | None = None, column_hints: dict | None = None):
        self.sample_rows = sample_rows
        self.patterns = patterns or UAE_PATTERNS
        self.column_hints = column_hints or PII_COLUMN_HINTS
        self.analyzer = build_analyzer(self.patterns) if PRESIDIO else None
        self.compiled = {e: re.compile(s["regex"]) for e, s in self.patterns.items()}

    # -- engines ------------------------------------------------------------
    def _regex_scan(self, col: str, values) -> list:
        findings = []
        for entity, pattern in self.compiled.items():
            hits = sum(1 for v in values if pattern.search(v))
            if hits:
                findings.append({
                    "column": col,
                    "entity": entity,
                    "matches": hits,
                    "engine": "regex",
                    "risk": self.patterns[entity]["risk"],
                })
        return findings

    def _presidio_scan(self, col: str, values) -> list:
        findings, seen = [], {}
        for val in values:
            for r in self.analyzer.analyze(text=val, entities=self.ENTITIES, language="en"):
                key = (col, r.entity_type)
                seen.setdefault(key, {"count": 0, "max_conf": 0.0})
                seen[key]["count"] += 1
                seen[key]["max_conf"] = max(seen[key]["max_conf"], r.score)
        for (c, entity), agg in seen.items():
            findings.append({
                "column": c,
                "entity": entity,
                "matches": agg["count"],
                "confidence": round(agg["max_conf"], 2),
                "engine": "presidio",
                "risk": round(agg["max_conf"] * 10),
            })
        return findings

    # -- public -------------------------------------------------------------
    def scan_csv(self, path: Path) -> dict:
        result = {
            "file": str(path),
            "policy_id": "POL-PRIV-001",
            "pii_found": False,
            "findings": [],
            "risk_score": 0,
            "engine": "presidio" if PRESIDIO else "regex",
        }
        try:
            df = pd.read_csv(path)

            # Pass 1: column-name heuristics
            for col in df.columns:
                for hint, risk in self.column_hints.items():
                    if hint in col.lower():
                        result["findings"].append(
                            {"column": col, "entity": f"COLUMN_NAME:{hint}", "engine": "heuristic", "risk": risk}
                        )

            # Pass 2: value scan
            for col in df.columns:
                values = [v for v in df[col].dropna().astype(str).head(self.sample_rows) if len(v) >= 3]
                if not values:
                    continue
                if PRESIDIO:
                    result["findings"].extend(self._presidio_scan(col, values))
                else:
                    result["findings"].extend(self._regex_scan(col, values))

            result["pii_found"] = len(result["findings"]) > 0
            result["risk_score"] = min(sum(f.get("risk", 0) for f in result["findings"]), 100)
        except Exception as e:  # noqa: BLE001 - report, don't crash the gate
            result["error"] = str(e)
            result["pii_found"] = True  # fail closed
            result["risk_score"] = 100
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True)
    parser.add_argument("--output-format", choices=["json", "github", "pretty"], default="pretty")
    parser.add_argument("--output-file", help="Write JSON results to this file (for evidence pack)")
    parser.add_argument("--config", help="Path to compliance.config.yml (extends/overrides built-in patterns)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    scanner = PIIScanner(sample_rows=cfg["sample_rows"], patterns=cfg["patterns"], column_hints=cfg["column_hints"])
    path = Path(args.path)
    files = sorted(path.rglob("*.csv")) if path.is_dir() else [path]
    results = [scanner.scan_csv(f) for f in files]

    pii_files = sum(1 for r in results if r.get("pii_found"))
    report = {
        "policy_id": "POL-PRIV-001",
        "check": "pii_scan",
        "engine": "presidio" if PRESIDIO else "regex",
        "summary": {"files_scanned": len(results), "files_with_pii": pii_files},
        "results": results,
    }

    if args.output_file:
        Path(args.output_file).write_text(json.dumps(report, indent=2))

    if args.output_format == "json":
        print(json.dumps(report, indent=2))
    elif args.output_format == "github":
        if pii_files > 0:
            print(f"::error title=PII Detected (POL-PRIV-001)::{pii_files} file(s) contain PII")
            sys.exit(1)
        print("::notice title=PII Scan Passed::No PII found")
    else:
        print("\n" + "=" * 50)
        print(f"🔍 PII SCAN RESULTS  (engine: {report['engine']})")
        print("=" * 50)
        for r in results:
            status = "❌ PII DETECTED" if r["pii_found"] else "✅ CLEAN"
            print(f"\n📄 {Path(r['file']).name}: {status}")
            if r["pii_found"]:
                print(f"   Risk Score: {r['risk_score']}/100")
                entities = {}
                for f in r["findings"]:
                    e = f.get("entity", "unknown")
                    entities[e] = entities.get(e, 0) + f.get("matches", 1)
                for e, c in sorted(entities.items()):
                    print(f"   - {e}: {c}")
        print("\n" + "=" * 50)
        print("❌ DEPLOYMENT BLOCKED" if pii_files else "✅ READY TO DEPLOY")
        print("=" * 50)
        if pii_files:
            sys.exit(1)


if __name__ == "__main__":
    main()
