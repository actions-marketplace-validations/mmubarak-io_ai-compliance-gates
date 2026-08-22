#!/usr/bin/env python3
"""Evidence Pack Generator — Implements POL-GOV-003.

Aggregates the outputs of every compliance gate into a single,
auditor-facing artifact: what was checked, against which policy and
regulation, with what result, at which commit, and when.

Supports UAE PDPL Art. 20 (demonstrable security measures),
GDPR Art. 5(2) (accountability), and EU AI Act Art. 12 (record-keeping).

Usage (typically in CI, after the gates have run):
    python scripts/generate_evidence_pack.py \
        --pii-report reports/pii_scan.json \
        --model-card-report reports/model_cards.json \
        --conftest-report reports/conftest.json \
        --output-dir evidence
"""

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml


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


def load_json(path: str | None) -> dict | None:
    if not path or not Path(path).exists():
        return None
    return json.loads(Path(path).read_text())


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pii-report")
    parser.add_argument("--model-card-report")
    parser.add_argument("--conftest-report")
    parser.add_argument("--policy-mapping", default="templates/policy_mapping.yml")
    parser.add_argument("--output-dir", default="evidence")
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    pii = load_json(args.pii_report)
    cards = load_json(args.model_card_report)
    conftest = summarize_conftest(load_json(args.conftest_report))
    mapping = yaml.safe_load(Path(args.policy_mapping).read_text()) if Path(args.policy_mapping).exists() else {}

    gates = []
    if pii:
        gates.append({
            "gate": "PII Scan",
            "policy_id": "POL-PRIV-001",
            "regulation": "UAE PDPL Art. 20; GDPR Art. 32",
            "tool": f"pii_scanner.py ({pii.get('engine')})",
            "result": "PASS" if pii["summary"]["files_with_pii"] == 0 else "FAIL",
            "detail": pii["summary"],
        })
    if cards:
        s = cards["summary"]
        gates.append({
            "gate": "Model Card Validation",
            "policy_id": "POL-GOV-002",
            "regulation": "EU AI Act Annex IV, Art. 9/13/14; UAE PDPL Art. 4-5, 13-20",
            "tool": "model_card_validator.py",
            "result": "PASS" if s["compliant"] == s["cards_checked"] else "FAIL",
            "detail": s,
        })
    if conftest:
        gates.append({
            "gate": "Infrastructure Policy-as-Code",
            "policy_id": "POL-PRIV-001/006/007, POL-SEC-001/002, POL-PRIV-010",
            "regulation": "UAE PDPL Art. 9, 20, 22-23; GDPR Art. 5, 30, 32",
            "tool": "conftest (OPA/Rego)",
            "result": "PASS" if conftest["violations"] == 0 else "FAIL",
            "detail": conftest,
        })

    overall = "PASS" if all(g["result"] == "PASS" for g in gates) and gates else "FAIL"

    pack = {
        "evidence_pack_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository_state": git_info(),
        "overall_result": overall,
        "gates": gates,
        "policy_register": mapping.get("policies", []),
    }

    (out / "evidence_pack.json").write_text(json.dumps(pack, indent=2))

    # Human-readable summary for auditors / DPOs
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
        lines.append(f"| {g['gate']} | {g['policy_id']} | {g['regulation']} | {g['result']} |")
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

    print(f"Evidence pack written to {out}/ — overall: {overall}")


if __name__ == "__main__":
    main()
