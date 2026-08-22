#!/usr/bin/env python3
"""Evidence Pack Generator: implements POL-GOV-003.

Aggregates the outputs of every compliance gate into a single,
auditor-facing artifact: what was checked, against which policy and
regulation, with what result, at which commit, and when.

Supports UAE PDPL Art. 20 (demonstrable security measures),
GDPR Art. 5(2) (accountability), and EU AI Act Art. 12 (record-keeping).

An absent report is recorded as NOT_RUN rather than omitted. A gate that
crashed used to vanish from the pack entirely, leaving an artifact that
read as a clean bill of health for a check that never happened.

Usage (typically in CI, after the gates have run):
    python scripts/generate_evidence_pack.py \
        --pii-report reports/pii_scan.json \
        --model-card-report reports/model_cards.json \
        --conftest-report reports/conftest.json \
        --output-dir evidence
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

EXIT_OK, EXIT_VIOLATION = 0, 1


def git_info() -> dict:
    def run(*cmd):
        try:
            return subprocess.check_output(["git", *cmd], text=True).strip()
        except Exception:
            return "unknown"

    return {
        "commit_sha": run("rev-parse", "HEAD"),
        "branch": run("rev-parse", "--abbrev-ref", "HEAD"),
        "commit_date": run("log", "-1", "--format=%cI"),
    }


def load_report(path: str | None):
    """Return (data, status) where status is ok | missing | malformed."""
    if not path:
        return None, "missing"
    p = Path(path)
    if not p.exists():
        return None, "missing"
    try:
        return json.loads(p.read_text()), "ok"
    except (json.JSONDecodeError, OSError):
        return None, "malformed"


def summarize_conftest(raw) -> dict | None:
    """conftest --output json emits a list of per-file results."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        raw = [raw]
    failures, successes = 0, 0
    messages = []
    for entry in raw:
        successes += entry.get("successes", 0)
        for f in entry.get("failures", []) or []:
            failures += 1
            messages.append(f.get("msg", ""))
    return {"checks_passed": successes, "violations": failures, "violation_messages": messages}


def _gate(name, policy_id, regulation, tool, status, result, detail):
    return {
        "gate": name, "policy_id": policy_id, "regulation": regulation,
        "tool": tool, "report_status": status, "result": result, "detail": detail,
    }


def build_gates(pii, pii_status, cards, cards_status, conftest, conftest_status) -> list:
    gates = []

    if pii_status == "ok":
        summary = pii.get("summary", {})
        scanned = summary.get("files_scanned", 0)
        if scanned == 0:
            result = "NO_DATA"
        else:
            result = "PASS" if summary.get("files_with_pii", 1) == 0 else "FAIL"
        detail = summary
    else:
        result, detail = ("NOT_RUN" if pii_status == "missing" else "MALFORMED_REPORT"), {}
    gates.append(_gate(
        "PII Scan", "POL-PRIV-001", "UAE PDPL Art. 20; GDPR Art. 32",
        f"pii_scanner.py ({pii.get('engine') if pii else 'n/a'})", pii_status, result, detail,
    ))

    if cards_status == "ok":
        summary = cards.get("summary", {})
        checked = summary.get("cards_checked", 0)
        if checked == 0:
            result = "NO_DATA"
        else:
            result = "PASS" if summary.get("compliant", -1) == checked else "FAIL"
        detail = summary
    else:
        result, detail = ("NOT_RUN" if cards_status == "missing" else "MALFORMED_REPORT"), {}
    gates.append(_gate(
        "Model Card Validation", "POL-GOV-002",
        "EU AI Act Annex IV, Art. 9/13/14; UAE PDPL Art. 4-5, 13-20",
        "model_card_validator.py", cards_status, result, detail,
    ))

    if conftest_status == "ok" and conftest is not None:
        result = "PASS" if conftest["violations"] == 0 else "FAIL"
        detail = conftest
    else:
        result, detail = ("NOT_RUN" if conftest_status == "missing" else "MALFORMED_REPORT"), {}
    gates.append(_gate(
        "Infrastructure Policy-as-Code",
        "POL-PRIV-001/002/003, POL-SEC-001/002, POL-PRIV-004",
        "UAE PDPL Art. 9, 20, 22-23; GDPR Art. 5, 30, 32",
        "conftest (OPA/Rego)", conftest_status, result, detail,
    ))

    return gates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pii-report")
    parser.add_argument("--model-card-report")
    parser.add_argument("--conftest-report")
    parser.add_argument("--policy-mapping", default="templates/policy_mapping.yml")
    parser.add_argument("--output-dir", default="evidence")
    parser.add_argument("--fail-on-violation", action="store_true",
                        help="Exit 1 when the overall result is not PASS (default: always exit 0, "
                             "since the individual gates have already failed the build)")
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    pii, pii_status = load_report(args.pii_report)
    cards, cards_status = load_report(args.model_card_report)
    conftest_raw, conftest_status = load_report(args.conftest_report)
    conftest = summarize_conftest(conftest_raw) if conftest_status == "ok" else None

    mapping = {}
    mapping_path = Path(args.policy_mapping)
    if mapping_path.exists():
        try:
            mapping = yaml.safe_load(mapping_path.read_text()) or {}
        except yaml.YAMLError:
            mapping = {}

    gates = build_gates(pii, pii_status, cards, cards_status, conftest, conftest_status)

    executed = [g for g in gates if g["result"] not in ("NOT_RUN",)]
    overall = "PASS" if executed and all(g["result"] == "PASS" for g in executed) else "FAIL"

    pack = {
        "evidence_pack_version": "1.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository_state": git_info(),
        "overall_result": overall,
        "gates": gates,
        "gates_not_run": [g["gate"] for g in gates if g["result"] == "NOT_RUN"],
        "policy_register": mapping.get("policies", []),
    }

    (out / "evidence_pack.json").write_text(json.dumps(pack, indent=2))

    # Human-readable summary for auditors / DPOs
    icons = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "NOT_RUN": "⚪ NOT RUN",
             "NO_DATA": "⚠️ NO DATA", "MALFORMED_REPORT": "⚠️ MALFORMED REPORT"}
    lines = [
        "# Compliance Evidence Pack",
        "",
        f"**Generated:** {pack['generated_at']}",
        f"**Commit:** `{pack['repository_state']['commit_sha']}` on `{pack['repository_state']['branch']}`",
        f"**Overall result:** {'✅ PASS' if overall == 'PASS' else '❌ FAIL'}",
        "",
        "| Gate | Policy | Regulation | Result |",
        "|------|--------|------------|--------|",
    ]
    for g in gates:
        lines.append(f"| {g['gate']} | {g['policy_id']} | {g['regulation']} | {icons.get(g['result'], g['result'])} |")
    if pack["gates_not_run"]:
        lines += [
            "",
            f"> ⚪ **{len(pack['gates_not_run'])} gate(s) did not run:** "
            f"{', '.join(pack['gates_not_run'])}. This pack is not evidence of compliance "
            f"for those controls.",
        ]
    lines += [
        "",
        "## Gate details",
        "```json",
        json.dumps([{k: g[k] for k in ('gate', 'result', 'detail')} for g in gates], indent=2),
        "```",
        "",
        "_This artifact was generated automatically by CI and reflects the state of the_",
        "_repository at the referenced commit. Retain per your evidence retention policy._",
    ]
    (out / "evidence_pack.md").write_text("\n".join(lines))

    print(f"Evidence pack written to {out}/ (overall: {overall})")
    if pack["gates_not_run"]:
        print(f"  gates not run: {', '.join(pack['gates_not_run'])}")

    sys.exit(EXIT_VIOLATION if (args.fail_on_violation and overall != "PASS") else EXIT_OK)


if __name__ == "__main__":
    main()
