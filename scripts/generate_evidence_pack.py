#!/usr/bin/env python3
"""Evidence Pack Generator: implements POL-GOV-003.

Aggregates the outputs of every compliance gate into a single,
auditor-facing artifact: what was checked, against which policy and
regulation, with what result, at which commit, and when.

Supports UAE PDPL Art. 20 (demonstrable security measures),
GDPR Art. 5(2) (accountability), and EU AI Act Art. 12 (record-keeping).

An absent report is recorded as NOT_RUN rather than omitted. A gate that
crashed used to vanish from the pack entirely, leaving an artifact that
read as a clean bill of health for a check that never happened. A gate
that ran but could not cover its whole target is recorded as PARTIAL,
for the same reason.

Integrity: the pack carries a sha256 of its own content and of every
gate report it was built from, and `--verify` recomputes them. That
detects edits made after generation by anyone who does not also
recompute the digest, and pins the pack to the exact gate outputs it
summarizes. It is a checksum, not a signature: it proves nothing about
who produced the pack. For tamper-evidence an auditor can rely on,
publish the digest through a signed CI attestation (GitHub artifact
attestations, Sigstore) and check the pack against that.

Usage (typically in CI, after the gates have run):
    python scripts/generate_evidence_pack.py \
        --pii-report reports/pii_scan.json \
        --model-card-report reports/model_cards.json \
        --conftest-report reports/conftest.json \
        --output-dir evidence

    python scripts/generate_evidence_pack.py --verify evidence/evidence_pack.json
"""

from __future__ import annotations

import argparse
import hashlib
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


def file_digest(path: str | None) -> str | None:
    """sha256 of a gate report, so the pack is pinned to the exact output
    it summarizes. None when the report is absent."""
    if not path or not Path(path).exists():
        return None
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def content_digest(pack: dict) -> str:
    """sha256 over the pack's canonical JSON, excluding the integrity block
    itself so the value can be recomputed from the published artifact."""
    body = {k: v for k, v in pack.items() if k != "integrity"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_pack(path: str) -> int:
    """Recompute a pack's digest and compare it to the recorded one."""
    try:
        pack = json.loads(Path(path).read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"UNVERIFIABLE: {path} could not be read as an evidence pack ({exc})", file=sys.stderr)
        return EXIT_VIOLATION

    recorded = (pack.get("integrity") or {}).get("content_digest")
    if not recorded:
        print(f"UNVERIFIABLE: {path} carries no integrity digest (generated before v1.1?)", file=sys.stderr)
        return EXIT_VIOLATION

    actual = content_digest(pack)
    if actual != recorded:
        print(f"TAMPERED: {path} does not match its recorded digest\n"
              f"  recorded: {recorded}\n  actual:   {actual}", file=sys.stderr)
        return EXIT_VIOLATION

    print(f"OK: {path} matches its recorded digest ({recorded[:16]}...)")
    stale = [g["gate"] for g in pack.get("gates", [])
             if g.get("report_sha256") and file_digest(g.get("report_path")) not in (None, g["report_sha256"])]
    if stale:
        print(f"WARNING: gate report(s) changed since generation: {', '.join(stale)}", file=sys.stderr)
        return EXIT_VIOLATION
    return EXIT_OK


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
        elif summary.get("files_with_pii", 1) != 0:
            result = "FAIL"
        elif summary.get("files_unscanned", 0):
            # Clean, but not over everything it was pointed at. Reporting PASS
            # would claim coverage the scan did not have.
            result = "PARTIAL"
        else:
            result = "PASS"
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
    parser.add_argument("--verify", metavar="PACK",
                        help="Recompute the digests of an existing evidence_pack.json and exit "
                             "non-zero if it no longer matches. Generates nothing.")
    args = parser.parse_args()

    if args.verify:
        sys.exit(verify_pack(args.verify))

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

    # Pin each gate to the exact report it was summarized from, so a pack can
    # be checked against the artifacts it claims to describe.
    sources = {
        "PII Scan": args.pii_report,
        "Model Card Validation": args.model_card_report,
        "Infrastructure Policy-as-Code": args.conftest_report,
    }
    for g in gates:
        g["report_path"] = sources.get(g["gate"])
        g["report_sha256"] = file_digest(sources.get(g["gate"]))

    executed = [g for g in gates if g["result"] not in ("NOT_RUN",)]
    if not executed or not all(g["result"] in ("PASS", "PARTIAL") for g in executed):
        overall = "FAIL"
    elif any(g["result"] == "PARTIAL" for g in executed):
        overall = "PARTIAL"
    else:
        overall = "PASS"

    pack = {
        "evidence_pack_version": "1.2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository_state": git_info(),
        "overall_result": overall,
        "gates": gates,
        "gates_not_run": [g["gate"] for g in gates if g["result"] == "NOT_RUN"],
        "policy_register": mapping.get("policies", []),
    }
    pack["integrity"] = {
        "algorithm": "sha256",
        "content_digest": content_digest(pack),
        "covers": "every field of this pack except `integrity`, as canonical JSON",
        "verify": "python scripts/generate_evidence_pack.py --verify <path to this file>",
        "note": "A checksum, not a signature: it detects post-hoc edits, not who made them.",
    }

    (out / "evidence_pack.json").write_text(json.dumps(pack, indent=2))

    # Human-readable summary for auditors / DPOs
    icons = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "NOT_RUN": "⚪ NOT RUN",
             "PARTIAL": "⚠️ PARTIAL", "NO_DATA": "⚠️ NO DATA",
             "MALFORMED_REPORT": "⚠️ MALFORMED REPORT"}
    lines = [
        "# Compliance Evidence Pack",
        "",
        f"**Generated:** {pack['generated_at']}",
        f"**Commit:** `{pack['repository_state']['commit_sha']}` on `{pack['repository_state']['branch']}`",
        f"**Overall result:** {icons.get(overall, overall)}",
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
    partial = [g for g in gates if g["result"] == "PARTIAL"]
    if partial:
        lines += [
            "",
            f"> ⚠️ **{len(partial)} gate(s) covered less than their target:** "
            f"{', '.join(g['gate'] for g in partial)}. Files the gate could not read are "
            f"listed under `detail`. This pack is not evidence of compliance for them.",
        ]
    lines += [
        "",
        "## Gate details",
        "```json",
        json.dumps([{k: g[k] for k in ('gate', 'result', 'detail')} for g in gates], indent=2),
        "```",
        "",
        "## Integrity",
        "",
        f"`sha256:{pack['integrity']['content_digest']}`",
        "",
        "Verify with `python scripts/generate_evidence_pack.py --verify evidence/evidence_pack.json`.",
        "This is a checksum, not a signature: it detects edits made after generation, not who made",
        "them. Bind it to a signed CI attestation if an auditor needs provenance.",
        "",
        "_This artifact was generated automatically by CI and reflects the state of the_",
        "_repository at the referenced commit. Retain per your evidence retention policy._",
    ]
    (out / "evidence_pack.md").write_text("\n".join(lines))

    print(f"Evidence pack written to {out}/ (overall: {overall})")
    print(f"  sha256: {pack['integrity']['content_digest']}")
    if pack["gates_not_run"]:
        print(f"  gates not run: {', '.join(pack['gates_not_run'])}")

    sys.exit(EXIT_VIOLATION if (args.fail_on_violation and overall != "PASS") else EXIT_OK)


if __name__ == "__main__":
    main()
