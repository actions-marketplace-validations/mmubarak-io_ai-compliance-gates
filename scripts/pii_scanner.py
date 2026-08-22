#!/usr/bin/env python3
"""PII Scanner: implements POL-PRIV-001 (UAE PDPL Art. 20 / GDPR Art. 32).

Detects PII in tabular data before it enters the ML pipeline, with
UAE-specific recognizers that generic scanners miss:

  - Emirates ID       784-YYYY-NNNNNNN-C
  - UAE phone numbers +971-5X / 05X mobile and landline formats
  - UAE IBAN          AE + 21 digits

Reads every tabular format pandas can: CSV, TSV, JSON, JSON Lines and
Parquet, including .gz/.bz2/.xz/.zst variants.

Works standalone (regex engine) and upgrades automatically to
Microsoft Presidio NLP detection when installed.

Exit codes:
  0  no PII found
  1  PII found (policy violation; the gate blocks)
  2  misconfiguration (bad config, nothing to scan, or data the
     scanner cannot read)

Exit code 2 matters: a gate that scans zero files must not report
success, or a mistyped path becomes a green check that looks like
proof of compliance. Partial coverage is the same failure wearing a
different hat: a directory of Parquet shards next to one CSV used to
scan the CSV and report a clean pass for the whole directory. Files
the scanner cannot read are now listed as unscanned and block the
gate unless --allow-unscanned is passed.
"""

from __future__ import annotations

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

EXIT_OK, EXIT_VIOLATION, EXIT_MISCONFIGURED = 0, 1, 2

DEFAULT_RISK = 5

# ---------------------------------------------------------------------------
# UAE-specific patterns (used by both the regex engine and Presidio)
# ---------------------------------------------------------------------------
# Digit boundaries use lookarounds rather than \b: \b is satisfied by any
# non-word character, so "+971..." embedded in a longer digit run still
# matched and produced false positives on numeric IDs.
UAE_PATTERNS = {
    "AE_EMIRATES_ID": {
        "regex": r"(?<!\d)784[- ]?(19|20)\d{2}[- ]?\d{7}[- ]?\d(?!\d)",
        "risk": 10,
        "description": "Emirates ID number",
    },
    "AE_PHONE_NUMBER": {
        "regex": r"(?<!\d)(?:\+971|00971|0)[- ]?(?:2|3|4|6|7|9|5[0245689])[- ]?\d{3}[- ]?\d{4}(?!\d)",
        "risk": 8,
        "description": "UAE phone number",
    },
    "AE_IBAN": {
        "regex": r"\bAE\d{2}[- ]?\d{3}[- ]?\d{16}(?!\d)",
        "risk": 10,
        "description": "UAE IBAN",
    },
    "EMAIL_ADDRESS": {
        "regex": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
        "risk": 9,
        "description": "Email address",
    },
}

# ---------------------------------------------------------------------------
# Formats the scanner can read
# ---------------------------------------------------------------------------
# A gate that silently ignores the formats it cannot parse reports a clean
# pass for data it never opened, so what is readable is declared explicitly
# and everything else is accounted for as a coverage gap.
READERS = {
    ".csv": lambda p: pd.read_csv(p),
    ".tsv": lambda p: pd.read_csv(p, sep="\t"),
    ".json": lambda p: pd.read_json(p),
    ".jsonl": lambda p: pd.read_json(p, lines=True),
    ".ndjson": lambda p: pd.read_json(p, lines=True),
    ".parquet": lambda p: pd.read_parquet(p),
}

# pandas infers these from the filename, so they wrap a real format rather
# than being one: data.jsonl.gz is JSON Lines, not an unreadable archive.
COMPRESSION_SUFFIXES = {".gz", ".bz2", ".xz", ".zst", ".zip"}

# Formats that hold tabular data the scanner has no reader for. Finding one
# under a scan target is a coverage gap to report, not a file to ignore.
# Bare archives are here too: whatever a data.zip holds, the gate did not
# look inside it.
UNREADABLE_DATA_SUFFIXES = {
    ".xlsx", ".xls", ".xlsm", ".feather", ".orc", ".avro", ".arrow",
    ".dta", ".sav", ".sas7bdat", ".sqlite", ".db", ".tar",
} | COMPRESSION_SUFFIXES


def _data_suffix(path: Path) -> str:
    """The format-bearing suffix, looking through any compression wrapper.

    data.csv.gz is a CSV. data.zip and data.tar.gz are archives whose contents
    the scanner never sees, so they keep their own suffix and land in
    UNREADABLE_DATA_SUFFIXES instead of falling through unclassified.
    """
    suffixes = [s.lower() for s in path.suffixes]
    if not suffixes:
        return ""
    if suffixes[-1] in COMPRESSION_SUFFIXES:
        inner = suffixes[-2] if len(suffixes) > 1 else ""
        return inner if inner in READERS else suffixes[-1]
    return suffixes[-1]


def _normalize_ext(ext: str) -> str:
    ext = str(ext).lower().strip()
    return ext if ext.startswith(".") else f".{ext}"


def read_table(path: Path):
    """Load a supported tabular file into a DataFrame."""
    reader = READERS.get(_data_suffix(path))
    if reader is None:
        raise ValueError(f"no reader for '{path.name}': unsupported format")
    return reader(path)


# Column-name heuristics (fast first pass)
PII_COLUMN_HINTS = {
    "name": 8, "email": 9, "phone": 9, "mobile": 9, "address": 8,
    "ssn": 10, "emirates_id": 10, "eid": 10, "passport": 10,
    "iban": 10, "dob": 8, "birth": 8, "national_id": 10,
}


class ConfigError(Exception):
    """Raised for a malformed compliance.config.yml, with a usable message."""


def _hint_matches(hint: str, column: str) -> bool:
    """Match a hint on token boundaries, so 'name' doesn't fire on 'filename'."""
    return re.search(rf"(?:^|[^a-z0-9]){re.escape(hint)}(?:[^a-z0-9]|$)", column.lower()) is not None


def _validate_pii_config(user: dict) -> list:
    """Return a list of human-readable problems with the pii_scan config."""
    problems = []

    patterns = user.get("custom_patterns") or {}
    if not isinstance(patterns, dict):
        problems.append("pii_scan.custom_patterns must be a mapping of ENTITY_NAME -> {regex, risk}")
        patterns = {}
    for name, spec in patterns.items():
        if not isinstance(spec, dict):
            problems.append(f"pii_scan.custom_patterns.{name} must be a mapping with a 'regex' key")
            continue
        if "regex" not in spec:
            problems.append(f"pii_scan.custom_patterns.{name} is missing the required key 'regex'")
        else:
            try:
                re.compile(spec["regex"])
            except re.error as exc:
                problems.append(f"pii_scan.custom_patterns.{name}.regex is not a valid regex: {exc}")
        risk = spec.get("risk", DEFAULT_RISK)
        if not isinstance(risk, int) or isinstance(risk, bool) or not 1 <= risk <= 10:
            problems.append(f"pii_scan.custom_patterns.{name}.risk must be an integer 1-10 (got {risk!r})")

    disabled = user.get("disable_patterns") or []
    if not isinstance(disabled, list):
        problems.append("pii_scan.disable_patterns must be a list of entity names")

    hints = user.get("column_hints") or {}
    if not isinstance(hints, dict):
        problems.append("pii_scan.column_hints must be a mapping of substring -> risk")
    else:
        for hint, risk in hints.items():
            if not isinstance(risk, int) or isinstance(risk, bool) or not 1 <= risk <= 10:
                problems.append(f"pii_scan.column_hints.{hint} must be an integer 1-10 (got {risk!r})")

    exts = user.get("scan_extensions")
    if exts is not None:
        if not isinstance(exts, list) or not all(isinstance(e, str) for e in exts):
            problems.append("pii_scan.scan_extensions must be a list of file extensions, e.g. ['.csv', '.parquet']")
        elif not exts:
            problems.append("pii_scan.scan_extensions is empty, which would scan nothing")
        else:
            unknown = sorted({e for e in exts if _normalize_ext(e) not in READERS})
            if unknown:
                problems.append(
                    "pii_scan.scan_extensions contains formats the scanner cannot read: "
                    f"{', '.join(unknown)} (supported: {', '.join(sorted(READERS))})"
                )

    rows = user.get("sample_rows", 50)
    if not isinstance(rows, int) or isinstance(rows, bool) or rows < 1:
        problems.append(f"pii_scan.sample_rows must be a positive integer (got {rows!r})")

    return problems


def load_config(path: str | None) -> dict:
    """Merge a user compliance.config.yml over the built-in defaults.

    Raises ConfigError with every problem listed, rather than dying on the
    first KeyError deep inside a scan.
    """
    import yaml

    cfg = {
        "patterns": dict(UAE_PATTERNS),
        "column_hints": dict(PII_COLUMN_HINTS),
        "sample_rows": 50,
        "disabled": set(),
        "scan_extensions": set(READERS),
    }
    if not path:
        return cfg

    try:
        raw = yaml.safe_load(Path(path).read_text()) or {}
    except FileNotFoundError:
        raise ConfigError(f"Config file not found: {path}")
    except yaml.YAMLError as exc:
        raise ConfigError(f"Config file {path} is not valid YAML: {exc}")
    if not isinstance(raw, dict):
        raise ConfigError(f"Config file {path} must contain a YAML mapping at the top level")

    user = raw.get("pii_scan") or {}
    if not isinstance(user, dict):
        raise ConfigError("pii_scan section must be a mapping")

    problems = _validate_pii_config(user)
    if problems:
        raise ConfigError("Invalid pii_scan config in {}:\n  - {}".format(path, "\n  - ".join(problems)))

    for name, spec in (user.get("custom_patterns") or {}).items():
        cfg["patterns"][name] = {**spec, "risk": spec.get("risk", DEFAULT_RISK)}
    for entity in user.get("disable_patterns") or []:
        cfg["patterns"].pop(entity, None)
        cfg["disabled"].add(entity)
    cfg["column_hints"].update(user.get("column_hints") or {})
    cfg["sample_rows"] = user.get("sample_rows", cfg["sample_rows"])
    if user.get("scan_extensions") is not None:
        cfg["scan_extensions"] = {_normalize_ext(e) for e in user["scan_extensions"]}
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


def discover_files(path: Path, extensions: set | None = None) -> tuple:
    """Split a scan target into (files to scan, files left unscanned).

    A file is used as-is; a directory is searched recursively. Data files the
    scanner has no reader for -- or whose format the config excluded -- are
    returned as unscanned rather than dropped, because a scan that skipped
    half the directory must not be reported as a scan of the directory.
    """
    allowed = set(READERS) if extensions is None else extensions
    if not path.is_dir():
        return ([path], []) if _data_suffix(path) in allowed else ([], [path])

    to_scan, unscanned = [], []
    for f in sorted(p for p in path.rglob("*") if p.is_file()):
        ext = _data_suffix(f)
        if ext in allowed:
            to_scan.append(f)
        elif ext in READERS or ext in UNREADABLE_DATA_SUFFIXES:
            unscanned.append(f)
    return to_scan, unscanned


class PIIScanner:
    BASE_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "LOCATION"]

    @property
    def ENTITIES(self):
        # disable_patterns must also suppress Presidio's own built-in
        # recognizers, or disabling EMAIL_ADDRESS silently does nothing
        # whenever Presidio happens to be installed.
        return sorted((set(self.BASE_ENTITIES) | set(self.patterns)) - self.disabled)

    def __init__(self, sample_rows: int = 50, patterns: dict | None = None,
                 column_hints: dict | None = None, disabled: set | None = None):
        self.sample_rows = sample_rows
        self.patterns = patterns or UAE_PATTERNS
        self.column_hints = column_hints or PII_COLUMN_HINTS
        self.disabled = set(disabled or ())
        self.analyzer = build_analyzer(self.patterns) if PRESIDIO else None
        self.compiled = {e: re.compile(s["regex"]) for e, s in self.patterns.items()}

    def _risk_of(self, entity: str, fallback: int) -> int:
        """Configured risk wins over an engine-derived score, so the same
        config produces the same number on both engines."""
        configured = self.patterns.get(entity, {}).get("risk")
        return configured if configured is not None else fallback

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
                    "risk": self.patterns[entity].get("risk", DEFAULT_RISK),
                })
        return findings

    def _presidio_scan(self, col: str, values) -> list:
        findings, seen = [], {}
        for val in values:
            for r in self.analyzer.analyze(text=val, entities=self.ENTITIES, language="en"):
                if r.entity_type in self.disabled:
                    continue
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
                "risk": self._risk_of(entity, round(agg["max_conf"] * 10)),
            })
        return findings

    @staticmethod
    def _score(findings: list) -> int:
        """Highest risk per column, summed. Summing every finding instead
        double-counted a column flagged by both its name and its values."""
        by_column = {}
        for f in findings:
            col = f.get("column", "")
            by_column[col] = max(by_column.get(col, 0), f.get("risk", 0))
        return min(sum(by_column.values()), 100)

    # -- public -------------------------------------------------------------
    def scan_file(self, path: Path) -> dict:
        result = {
            "file": str(path),
            "policy_id": "POL-PRIV-001",
            "pii_found": False,
            "findings": [],
            "risk_score": 0,
            "engine": "presidio" if PRESIDIO else "regex",
        }
        try:
            df = read_table(path)

            # Pass 1: column-name heuristics
            for col in df.columns:
                for hint, risk in self.column_hints.items():
                    if _hint_matches(hint, str(col)):
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
            result["risk_score"] = self._score(result["findings"])
        except Exception as e:  # noqa: BLE001 - report, don't crash the gate
            result["error"] = str(e)
            result["pii_found"] = True  # fail closed
            result["risk_score"] = 100
        return result

    # Kept for the v1 Python API, which predates non-CSV support.
    scan_csv = scan_file


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
    parser.add_argument("--config", help="Path to compliance.config.yml (extends/overrides built-in patterns)")
    parser.add_argument("--allow-empty", action="store_true",
                        help="Treat 'no data files found' as a pass instead of a misconfiguration")
    parser.add_argument("--allow-unscanned", action="store_true",
                        help="Proceed when the target holds data files the scanner cannot read. "
                             "They stay listed in the report as a coverage gap.")
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        _fail(str(exc), args.output_format, "PII Scan Config Invalid (POL-PRIV-001)")

    scanner = PIIScanner(
        sample_rows=cfg["sample_rows"],
        patterns=cfg["patterns"],
        column_hints=cfg["column_hints"],
        disabled=cfg["disabled"],
    )
    path = Path(args.path)
    files, unscanned = discover_files(path, cfg["scan_extensions"])

    if not files and not unscanned and not args.allow_empty:
        _fail(
            f"No readable data files found under '{path}'. Refusing to report success for a scan "
            f"that examined nothing. Supported formats: {', '.join(sorted(READERS))}. "
            f"Pass --allow-empty if this is intentional.",
            args.output_format,
            "PII Scan Misconfigured (POL-PRIV-001)",
        )

    if unscanned and not args.allow_unscanned:
        shown = ", ".join(str(f) for f in unscanned[:10])
        more = f" (+{len(unscanned) - 10} more)" if len(unscanned) > 10 else ""
        _fail(
            f"{len(unscanned)} data file(s) under '{path}' cannot be scanned: {shown}{more}. "
            f"Passing the gate would claim coverage this scan does not have. Convert them to a "
            f"supported format ({', '.join(sorted(READERS))}), point the gate at a narrower path, "
            f"or pass --allow-unscanned to record the gap and continue.",
            args.output_format,
            "PII Scan Coverage Gap (POL-PRIV-001)",
        )

    results = [scanner.scan_file(f) for f in files]

    pii_files = sum(1 for r in results if r.get("pii_found"))
    report = {
        "policy_id": "POL-PRIV-001",
        "check": "pii_scan",
        "engine": "presidio" if PRESIDIO else "regex",
        "summary": {
            "files_scanned": len(results),
            "files_with_pii": pii_files,
            "files_unscanned": len(unscanned),
        },
        "unscanned": [str(f) for f in unscanned],
        "results": results,
    }

    if args.output_file:
        Path(args.output_file).write_text(json.dumps(report, indent=2))

    if args.output_format == "json":
        print(json.dumps(report, indent=2))
    elif args.output_format == "github":
        if unscanned:
            print(f"::warning title=PII Scan Coverage Gap (POL-PRIV-001)::{len(unscanned)} data "
                  f"file(s) were not scanned; this run is not evidence of compliance for them")
        if pii_files > 0:
            print(f"::error title=PII Detected (POL-PRIV-001)::{pii_files} file(s) contain PII")
        else:
            print(f"::notice title=PII Scan Passed::No PII found in {len(results)} file(s)")
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
        if unscanned:
            print(f"\n⚠️  NOT SCANNED ({len(unscanned)} file(s) in an unsupported format):")
            for f in unscanned[:10]:
                print(f"   - {f}")
            if len(unscanned) > 10:
                print(f"   ... and {len(unscanned) - 10} more")
            print("   This run is not evidence of compliance for these files.")
        print("\n" + "=" * 50)
        print("❌ DEPLOYMENT BLOCKED" if pii_files else "✅ READY TO DEPLOY")
        print("=" * 50)

    # One exit path for every format: --output-format json used to return 0
    # on dirty data, which silently disarmed the gate for JSON consumers.
    sys.exit(EXIT_VIOLATION if pii_files else EXIT_OK)


if __name__ == "__main__":
    main()
