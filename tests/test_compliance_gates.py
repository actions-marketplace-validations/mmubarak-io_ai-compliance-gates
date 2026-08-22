"""Tests for the compliance gates."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from pii_scanner import PIIScanner, load_config  # noqa: E402
import model_card_validator as mcv  # noqa: E402


# ---------------------------------------------------------------------------
# PII scanner
# ---------------------------------------------------------------------------
class TestPIIScanner:
    def test_detects_emirates_id(self, tmp_path):
        f = tmp_path / "d.csv"
        f.write_text("id,doc\n1,784-1985-1234567-1\n")
        r = PIIScanner().scan_csv(f)
        assert r["pii_found"]
        assert any(x["entity"] == "AE_EMIRATES_ID" for x in r["findings"])

    def test_detects_uae_phone_and_iban(self, tmp_path):
        f = tmp_path / "d.csv"
        f.write_text("id,a,b\n1,+971-50-123-4567,AE07 033 1234567890123456\n")
        entities = {x["entity"] for x in PIIScanner().scan_csv(f)["findings"]}
        assert "AE_PHONE_NUMBER" in entities
        assert "AE_IBAN" in entities

    def test_clean_data_passes(self, tmp_path):
        f = tmp_path / "d.csv"
        f.write_text("customer_hash,amount,segment\nabc123,10.5,basic\n")
        r = PIIScanner().scan_csv(f)
        assert not r["pii_found"]
        assert r["risk_score"] == 0

    def test_column_name_heuristic(self, tmp_path):
        f = tmp_path / "d.csv"
        f.write_text("email,amount\nx,1\n")
        r = PIIScanner().scan_csv(f)
        assert any(x["engine"] == "heuristic" for x in r["findings"])

    def test_unreadable_file_fails_closed(self, tmp_path):
        r = PIIScanner().scan_csv(tmp_path / "does_not_exist.csv")
        assert r["pii_found"]
        assert r["risk_score"] == 100
        assert "error" in r

    def test_config_adds_custom_pattern(self, tmp_path):
        cfg = tmp_path / "compliance.config.yml"
        cfg.write_text(yaml.safe_dump({
            "pii_scan": {"custom_patterns": {
                "SA_NATIONAL_ID": {"regex": r"\b[12]\d{9}\b", "risk": 10, "description": "KSA ID"}
            }}
        }))
        c = load_config(str(cfg))
        f = tmp_path / "d.csv"
        f.write_text("id,doc\n1,1234567890\n")
        scanner = PIIScanner(patterns=c["patterns"], column_hints=c["column_hints"])
        assert any(x["entity"] == "SA_NATIONAL_ID" for x in scanner.scan_csv(f)["findings"])

    def test_config_disables_pattern(self, tmp_path):
        cfg = tmp_path / "compliance.config.yml"
        cfg.write_text(yaml.safe_dump({"pii_scan": {"disable_patterns": ["AE_IBAN"]}}))
        c = load_config(str(cfg))
        assert "AE_IBAN" not in c["patterns"]

    def test_examples_dirty_vs_clean(self):
        s = PIIScanner()
        assert s.scan_csv(REPO / "examples/sample_data/customers.csv")["pii_found"]
        assert not s.scan_csv(REPO / "examples/sample_data/customers_anonymized.csv")["pii_found"]


# ---------------------------------------------------------------------------
# Model card validator
# ---------------------------------------------------------------------------
class TestModelCardValidator:
    def test_compliant_example_passes(self):
        r = mcv.validate(REPO / "examples/model_cards/compliant/churn_model_v2_compliant.yml")
        assert r["valid"]
        assert r["score"] == 100

    def test_non_compliant_example_fails_with_basis(self):
        r = mcv.validate(REPO / "examples/model_cards/non_compliant/churn_model_v1.yml")
        assert not r["valid"]
        assert all("basis" in e for e in r["errors"] if "Missing" in e["issue"])
        assert any("AI Act" in e.get("basis", "") for e in r["errors"])

    def test_empty_card(self, tmp_path):
        f = tmp_path / "c.yml"
        f.write_text("")
        r = mcv.validate(f)
        assert not r["valid"]
        assert r["score"] == 0

    def test_custom_schema_via_config(self, tmp_path):
        cfg = tmp_path / "compliance.config.yml"
        cfg.write_text(yaml.safe_dump({
            "model_cards": {
                "required": {"meta": {"fields": ["owner"], "basis": "DOC-001"}},
                "recommended": {},
            }
        }))
        required, recommended = mcv.load_schema(str(cfg))
        card = tmp_path / "c.yml"
        card.write_text("meta:\n  owner: team-x\n")
        r = mcv.validate(card, required, recommended)
        assert r["valid"]


# ---------------------------------------------------------------------------
# Evidence pack (end-to-end via CLI)
# ---------------------------------------------------------------------------
class TestEvidencePack:
    def _run(self, cmd):
        return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)

    def test_end_to_end(self, tmp_path):
        reports = tmp_path / "reports"
        reports.mkdir()
        assert self._run([
            sys.executable, "scripts/pii_scanner.py",
            "--path", "examples/sample_data/customers_anonymized.csv",
            "--output-format", "json", "--output-file", str(reports / "pii.json"),
        ]).returncode == 0
        assert self._run([
            sys.executable, "scripts/model_card_validator.py",
            "--path", "examples/model_cards/compliant",
            "--output-format", "json", "--output-file", str(reports / "cards.json"),
        ]).returncode == 0

        out = tmp_path / "evidence"
        r = self._run([
            sys.executable, "scripts/generate_evidence_pack.py",
            "--pii-report", str(reports / "pii.json"),
            "--model-card-report", str(reports / "cards.json"),
            "--output-dir", str(out),
        ])
        assert r.returncode == 0, r.stderr
        pack = json.loads((out / "evidence_pack.json").read_text())
        assert pack["overall_result"] == "PASS"
        assert len(pack["gates"]) == 2
        assert pack["repository_state"]["commit_sha"] != "unknown"
        assert (out / "evidence_pack.md").exists()

    def test_failure_propagates(self, tmp_path):
        reports = tmp_path / "reports"
        reports.mkdir()
        self._run([
            sys.executable, "scripts/pii_scanner.py",
            "--path", "examples/sample_data/customers.csv",
            "--output-format", "json", "--output-file", str(reports / "pii.json"),
        ])
        out = tmp_path / "evidence"
        self._run([
            sys.executable, "scripts/generate_evidence_pack.py",
            "--pii-report", str(reports / "pii.json"),
            "--output-dir", str(out),
        ])
        pack = json.loads((out / "evidence_pack.json").read_text())
        assert pack["overall_result"] == "FAIL"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
