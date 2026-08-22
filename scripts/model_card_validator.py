#!/usr/bin/env python3
"""Model Card Validator — Implements POL-GOV-002.

Validates model cards against documentation requirements derived from:
  - EU AI Act (Regulation 2024/1689), Annex IV technical documentation
  - UAE Personal Data Protection Law (Federal Decree-Law No. 45/2021)
  - GDPR Art. 13-14 transparency obligations

Each required section is mapped to the specific provision it satisfies,
so a failing check tells you *which regulation* you're not meeting.

Exit codes:
  0  every card valid
  1  at least one card invalid (policy violation — the gate blocks)
  2  misconfiguration (bad config, or nothing to validate)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

EXIT_OK, EXIT_VIOLATION, EXIT_MISCONFIGURED = 0, 1, 2

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


class ConfigError(Exception):
    """Raised for a malformed compliance.config.yml, with a usable message."""


def _validate_schema(required, recommended) -> list:
    """Return human-readable problems with a user-supplied schema."""
    problems = []

    if not isinstance(required, dict):
        problems.append("model_cards.required must be a mapping of section -> {fields, basis}")
    else:
        for section, spec in required.items():
            if not isinstance(spec, dict):
                problems.append(f"model_cards.required.{section} must be a mapping with 'fields' and 'basis'")
                continue
            if not isinstance(spec.get("fields"), list):
                problems.append(f"model_cards.required.{section}.fields must be a list of field names")
            if not isinstance(spec.get("basis"), str):
                problems.append(
                    f"model_cards.required.{section}.basis must be a string naming the regulation or "
                    f"internal policy the section satisfies"
                )

    if not isinstance(recommended, dict):
        problems.append("model_cards.recommended must be a mapping of 'section.field' -> basis")
    else:
        for dotted in recommended:
            if not isinstance(dotted, str) or dotted.count(".") != 1:
                problems.append(
                    f"model_cards.recommended key {dotted!r} must be exactly 'section.field' (one dot)"
                )

    return problems


def load_schema(config_path: str | None):
    """Return (required, recommended), replaced by user config if provided."""
    required, recommended = REQUIRED, RECOMMENDED
    if not config_path:
        return required, recommended

    try:
        raw = yaml.safe_load(Path(config_path).read_text()) or {}
    except FileNotFoundError:
        raise ConfigError(f"Config file not found: {config_path}")
    except yaml.YAMLError as exc:
        raise ConfigError(f"Config file {config_path} is not valid YAML: {exc}")
    if not isinstance(raw, dict):
        raise ConfigError(f"Config file {config_path} must contain a YAML mapping at the top level")

    user = raw.get("model_cards") or {}
    if not isinstance(user, dict):
        raise ConfigError("model_cards section must be a mapping")

    if "required" in user:
        required = user["required"]
    if "recommended" in user:
        recommended = user["recommended"]

    problems = _validate_schema(required, recommended)
    if problems:
        raise ConfigError(
            "Invalid model_cards config in {}:\n  - {}".format(config_path, "\n  - ".join(problems))
        )
    return required, recommended


def discover_files(path: Path) -> list:
    """Model cards to validate. Directories are searched recursively, matching
    the PII scanner — a non-recursive glob silently skipped nested cards."""
    if not path.is_dir():
        return [path]
    return sorted(list(path.rglob("*.yml")) + list(path.rglob("*.yaml")))


def _has_field(section_value, field: str) -> bool:
    """Field presence, tolerant of a section that isn't a mapping."""
    if isinstance(section_value, dict):
        return field in section_value
    return False


def validate(path: Path, required: dict = REQUIRED, recommended: dict = RECOMMENDED) -> dict:
    result = {"file": str(path), "policy_id": "POL-GOV-002", "valid": True,
              "errors": [], "warnings": [], "score": 100}
    try:
        with open(path) as f:
            card = yaml.safe_load(f)
        if not card:
            return {**result, "valid": False, "errors": [{"issue": "Empty file"}], "score": 0}
        if not isinstance(card, dict):
            return {**result, "valid": False,
                    "errors": [{"issue": "Model card must be a YAML mapping of sections"}], "score": 0}

        for section, spec in required.items():
            if section not in card:
                result["errors"].append({"issue": f"Missing section: {section}", "basis": spec["basis"]})
                result["score"] -= 15
                continue
            for field in spec["fields"]:
                if not _has_field(card[section], field):
                    result["errors"].append({"issue": f"Missing field: {section}.{field}", "basis": spec["basis"]})
                    result["score"] -= 5

        for dotted, basis in recommended.items():
            section, field = dotted.split(".")
            if not _has_field(card.get(section), field):
                result["warnings"].append({"issue": f"Recommended: {dotted}", "basis": basis})

        result["valid"] = len(result["errors"]) == 0
        result["score"] = max(0, result["score"])
    except Exception as e:  # noqa: BLE001
        result = {**result, "valid": False, "errors": [{"issue": str(e)}], "score": 0}
    return result


def _fail(message: str, output_format: str, title: str) -> None:
    if output_format == "github":
        print(f"::error title={title}::{message}")
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(EXIT_MISCONFIGURED)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True)
    parser.add_argument("--output-format", choices=["json", "github", "pretty"], default="pretty")
    parser.add_argument("--output-file", help="Write JSON results to this file (for evidence pack)")
    parser.add_argument("--config", help="Path to compliance.config.yml (replaces built-in schema)")
    parser.add_argument("--allow-empty", action="store_true",
                        help="Treat 'no model cards found' as a pass instead of a misconfiguration")
    args = parser.parse_args()

    try:
        required, recommended = load_schema(args.config)
    except ConfigError as exc:
        _fail(str(exc), args.output_format, "Model Card Config Invalid (POL-GOV-002)")

    path = Path(args.path)
    files = discover_files(path)

    if not files and not args.allow_empty:
        _fail(
            f"No model cards (*.yml / *.yaml) found under '{path}'. Refusing to report success for a "
            f"check that examined nothing — pass --allow-empty if this is intentional.",
            args.output_format,
            "Model Card Check Misconfigured (POL-GOV-002)",
        )

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
        if valid == len(results):
            print(f"::notice title=Model Card Validation Passed::{valid} card(s) compliant")
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

    sys.exit(EXIT_OK if valid == len(results) else EXIT_VIOLATION)


if __name__ == "__main__":
    main()
