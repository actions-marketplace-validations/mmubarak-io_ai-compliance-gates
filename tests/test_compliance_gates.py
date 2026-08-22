"""Tests for the compliance gates.

Every fail-open bug fixed in this suite has a named regression test below:
a gate that reports success while checking nothing is worse than no gate,
because it produces an evidence pack that reads as proof of compliance.
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from pii_scanner import (  # noqa: E402
    EXIT_MISCONFIGURED, EXIT_OK, EXIT_VIOLATION, ConfigError, PIIScanner, load_config,
)
import model_card_validator as mcv  # noqa: E402


def run_script(script, *argv):
    return subprocess.run(
        [sys.executable, f"scripts/{script}", *argv], cwd=REPO, capture_output=True, text=True
    )


# ---------------------------------------------------------------------------
# PII scanner: detection
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

    def test_examples_dirty_vs_clean(self):
        s = PIIScanner()
        assert s.scan_csv(REPO / "examples/sample_data/customers.csv")["pii_found"]
        assert not s.scan_csv(REPO / "examples/sample_data/customers_anonymized.csv")["pii_found"]

    # -- regression: false positives ---------------------------------------
    @pytest.mark.parametrize("column", ["filename", "hostname", "renamed_at"])
    def test_column_hint_respects_token_boundaries(self, tmp_path, column):
        """'name' must not fire on 'filename'; substring matching over-flagged."""
        f = tmp_path / "d.csv"
        f.write_text(f"{column},amount\nreport.csv,1\n")
        heuristics = [x for x in PIIScanner().scan_csv(f)["findings"] if x["engine"] == "heuristic"]
        assert heuristics == []

    def test_phone_not_matched_inside_longer_digit_run(self, tmp_path):
        """A 12-digit order id must not read as a UAE phone number."""
        f = tmp_path / "d.csv"
        f.write_text("order_ref,amount\n990501234567,10\n")
        entities = {x["entity"] for x in PIIScanner().scan_csv(f)["findings"]}
        assert "AE_PHONE_NUMBER" not in entities

    def test_risk_not_double_counted_per_column(self, tmp_path):
        """A column caught by both its name and its values scores once."""
        f = tmp_path / "d.csv"
        f.write_text("email,amount\nuser@example.com,1\n")
        r = PIIScanner().scan_csv(f)
        assert r["risk_score"] == 9  # not 9 (name) + 9 (value)

    # -- regression: config handling ---------------------------------------
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
        # also recorded, so Presidio's own recognizers get suppressed too
        assert "AE_IBAN" in c["disabled"]

    def test_disabled_entity_suppressed_in_entity_list(self):
        """ENTITIES drives Presidio; a disabled built-in must not reappear there."""
        scanner = PIIScanner(disabled={"EMAIL_ADDRESS"})
        assert "EMAIL_ADDRESS" not in scanner.ENTITIES

    def test_custom_pattern_without_risk_gets_default(self, tmp_path):
        cfg = tmp_path / "c.yml"
        cfg.write_text(yaml.safe_dump({"pii_scan": {"custom_patterns": {"X": {"regex": "abc"}}}}))
        assert load_config(str(cfg))["patterns"]["X"]["risk"] == 5

    @pytest.mark.parametrize("bad,expect", [
        ({"custom_patterns": {"X": {"risk": 3}}}, "missing the required key 'regex'"),
        ({"custom_patterns": {"X": {"regex": "([unclosed"}}}, "not a valid regex"),
        ({"custom_patterns": {"X": {"regex": "a", "risk": 99}}}, "must be an integer 1-10"),
        ({"disable_patterns": "AE_IBAN"}, "must be a list"),
        ({"column_hints": {"x": "high"}}, "must be an integer 1-10"),
        ({"sample_rows": 0}, "must be a positive integer"),
    ])
    def test_invalid_config_raises_clear_error(self, tmp_path, bad, expect):
        cfg = tmp_path / "c.yml"
        cfg.write_text(yaml.safe_dump({"pii_scan": bad}))
        with pytest.raises(ConfigError) as exc:
            load_config(str(cfg))
        assert expect in str(exc.value)

    def test_missing_config_file_raises(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(str(tmp_path / "nope.yml"))


# ---------------------------------------------------------------------------
# PII scanner: CLI exit codes (the fail-open class)
# ---------------------------------------------------------------------------
class TestPIIScannerExitCodes:
    @pytest.mark.parametrize("fmt", ["json", "github", "pretty"])
    def test_dirty_data_blocks_in_every_format(self, fmt):
        """--output-format json used to exit 0 on PII, disarming the gate."""
        r = run_script("pii_scanner.py", "--path", "examples/sample_data/customers.csv",
                       "--output-format", fmt)
        assert r.returncode == EXIT_VIOLATION, r.stdout

    @pytest.mark.parametrize("fmt", ["json", "github", "pretty"])
    def test_clean_data_passes_in_every_format(self, fmt):
        r = run_script("pii_scanner.py", "--path", "examples/sample_data/customers_anonymized.csv",
                       "--output-format", fmt)
        assert r.returncode == EXIT_OK, r.stdout

    def test_empty_directory_is_misconfiguration(self, tmp_path):
        """Scanning zero files must not report success."""
        (tmp_path / "empty").mkdir()
        r = run_script("pii_scanner.py", "--path", str(tmp_path / "empty"))
        assert r.returncode == EXIT_MISCONFIGURED
        assert "No CSV files found" in r.stderr

    def test_empty_directory_allowed_with_flag(self, tmp_path):
        (tmp_path / "empty").mkdir()
        r = run_script("pii_scanner.py", "--path", str(tmp_path / "empty"), "--allow-empty")
        assert r.returncode == EXIT_OK

    def test_invalid_config_is_misconfiguration(self, tmp_path):
        cfg = tmp_path / "c.yml"
        cfg.write_text(yaml.safe_dump({"pii_scan": {"custom_patterns": {"X": {}}}}))
        r = run_script("pii_scanner.py", "--path", "examples/sample_data/customers_anonymized.csv",
                       "--config", str(cfg))
        assert r.returncode == EXIT_MISCONFIGURED
        assert "regex" in r.stderr

    def test_nested_csv_is_discovered(self, tmp_path):
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "d.csv").write_text("doc\n784-1985-1234567-1\n")
        r = run_script("pii_scanner.py", "--path", str(tmp_path))
        assert r.returncode == EXIT_VIOLATION


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

    def test_non_mapping_card_rejected(self, tmp_path):
        f = tmp_path / "c.yml"
        f.write_text("- just\n- a list\n")
        r = mcv.validate(f)
        assert not r["valid"]
        assert "mapping" in r["errors"][0]["issue"]

    def test_section_that_is_not_a_mapping_is_reported_not_crashed(self, tmp_path):
        f = tmp_path / "c.yml"
        f.write_text("model_details: just-a-string\n")
        r = mcv.validate(f)
        assert not r["valid"]
        assert any("model_details.name" in e["issue"] for e in r["errors"])

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
        assert mcv.validate(card, required, recommended)["valid"]

    @pytest.mark.parametrize("bad,expect", [
        ({"required": {"meta": {"fields": ["owner"]}}}, "basis must be a string"),
        ({"required": {"meta": {"basis": "DOC-1"}}}, "fields must be a list"),
        ({"recommended": {"a.b.c": "DOC-2"}}, "exactly 'section.field'"),
        ({"required": "nope"}, "must be a mapping"),
    ])
    def test_invalid_schema_raises_clear_error(self, tmp_path, bad, expect):
        cfg = tmp_path / "c.yml"
        cfg.write_text(yaml.safe_dump({"model_cards": bad}))
        with pytest.raises(mcv.ConfigError) as exc:
            mcv.load_schema(str(cfg))
        assert expect in str(exc.value)

    # -- regression: discovery ---------------------------------------------
    def test_nested_cards_are_discovered(self, tmp_path):
        """Non-recursive glob silently skipped nested model cards."""
        nested = tmp_path / "team" / "fraud"
        nested.mkdir(parents=True)
        (nested / "card.yml").write_text("model_details:\n  name: x\n")
        assert mcv.discover_files(tmp_path) == [nested / "card.yml"]


class TestModelCardExitCodes:
    def test_non_compliant_blocks(self):
        r = run_script("model_card_validator.py", "--path", "examples/model_cards/non_compliant",
                       "--output-format", "json")
        assert r.returncode == EXIT_VIOLATION

    def test_compliant_passes(self):
        r = run_script("model_card_validator.py", "--path", "examples/model_cards/compliant",
                       "--output-format", "json")
        assert r.returncode == EXIT_OK

    def test_empty_directory_is_misconfiguration(self, tmp_path):
        (tmp_path / "empty").mkdir()
        r = run_script("model_card_validator.py", "--path", str(tmp_path / "empty"))
        assert r.returncode == EXIT_MISCONFIGURED
        assert "No model cards" in r.stderr

    def test_empty_directory_allowed_with_flag(self, tmp_path):
        (tmp_path / "empty").mkdir()
        r = run_script("model_card_validator.py", "--path", str(tmp_path / "empty"), "--allow-empty")
        assert r.returncode == EXIT_OK


# ---------------------------------------------------------------------------
# Evidence pack (end-to-end via CLI)
# ---------------------------------------------------------------------------
class TestEvidencePack:
    def _pack(self, out):
        return json.loads((Path(out) / "evidence_pack.json").read_text())

    def test_end_to_end(self, tmp_path):
        reports = tmp_path / "reports"
        reports.mkdir()
        assert run_script("pii_scanner.py", "--path", "examples/sample_data/customers_anonymized.csv",
                          "--output-format", "json",
                          "--output-file", str(reports / "pii.json")).returncode == EXIT_OK
        assert run_script("model_card_validator.py", "--path", "examples/model_cards/compliant",
                          "--output-format", "json",
                          "--output-file", str(reports / "cards.json")).returncode == EXIT_OK

        out = tmp_path / "evidence"
        r = run_script("generate_evidence_pack.py",
                       "--pii-report", str(reports / "pii.json"),
                       "--model-card-report", str(reports / "cards.json"),
                       "--output-dir", str(out))
        assert r.returncode == 0, r.stderr
        pack = self._pack(out)
        assert pack["overall_result"] == "PASS"
        assert len(pack["gates"]) == 3  # every gate is listed, run or not
        assert pack["repository_state"]["commit_sha"] != "unknown"
        assert (out / "evidence_pack.md").exists()

    def test_failure_propagates(self, tmp_path):
        reports = tmp_path / "reports"
        reports.mkdir()
        run_script("pii_scanner.py", "--path", "examples/sample_data/customers.csv",
                   "--output-format", "json", "--output-file", str(reports / "pii.json"))
        out = tmp_path / "evidence"
        run_script("generate_evidence_pack.py", "--pii-report", str(reports / "pii.json"),
                   "--output-dir", str(out))
        assert self._pack(out)["overall_result"] == "FAIL"

    # -- regression: evidence integrity ------------------------------------
    def test_absent_gate_recorded_as_not_run(self, tmp_path):
        """A gate that never ran must be visible in the pack, not omitted."""
        out = tmp_path / "evidence"
        run_script("generate_evidence_pack.py", "--output-dir", str(out))
        pack = self._pack(out)
        assert set(pack["gates_not_run"]) == {g["gate"] for g in pack["gates"]}
        assert pack["overall_result"] == "FAIL"
        assert "did not run" in (out / "evidence_pack.md").read_text()

    def test_malformed_report_is_flagged(self, tmp_path):
        bad = tmp_path / "pii.json"
        bad.write_text("{not json")
        out = tmp_path / "evidence"
        run_script("generate_evidence_pack.py", "--pii-report", str(bad), "--output-dir", str(out))
        pii = next(g for g in self._pack(out)["gates"] if g["gate"] == "PII Scan")
        assert pii["result"] == "MALFORMED_REPORT"

    def test_zero_files_scanned_is_not_a_pass(self, tmp_path):
        report = tmp_path / "pii.json"
        report.write_text(json.dumps({"summary": {"files_scanned": 0, "files_with_pii": 0}}))
        out = tmp_path / "evidence"
        run_script("generate_evidence_pack.py", "--pii-report", str(report), "--output-dir", str(out))
        pack = self._pack(out)
        pii = next(g for g in pack["gates"] if g["gate"] == "PII Scan")
        assert pii["result"] == "NO_DATA"
        assert pack["overall_result"] == "FAIL"

    def test_fail_on_violation_flag(self, tmp_path):
        out = tmp_path / "evidence"
        r = run_script("generate_evidence_pack.py", "--output-dir", str(out), "--fail-on-violation")
        assert r.returncode == 1


# ---------------------------------------------------------------------------
# Policy register
# ---------------------------------------------------------------------------
class TestPolicyRegister:
    """templates/policy_mapping.yml calls itself the single source of truth,
    so a policy id that a gate can emit must actually be defined there. A
    build failing with an id the register does not contain is exactly the
    drift this file exists to prevent."""

    REGISTER = REPO / "templates/policy_mapping.yml"
    SCAN_DIRS = ["scripts", "policy", ".github", "templates"]
    ID_RE = re.compile(r"POL-[A-Z]+-\d+")

    def _defined(self):
        return {p["policy_id"] for p in yaml.safe_load(self.REGISTER.read_text())["policies"]}

    def _referenced(self):
        found = set()
        paths = [q for d in self.SCAN_DIRS for q in (REPO / d).rglob("*") if q.is_file()]
        # CHANGELOG.md is deliberately excluded: release notes that document a
        # renumbering have to name the retired ids, so scanning it would make
        # honest history fail the build.
        paths += [q for q in REPO.glob("*.md") if q.name != "CHANGELOG.md"]
        for q in paths:
            try:
                found |= set(self.ID_RE.findall(q.read_text(errors="ignore")))
            except OSError:
                continue
        return found

    def test_every_referenced_id_is_defined(self):
        undefined = self._referenced() - self._defined()
        assert not undefined, f"policy ids emitted but absent from the register: {sorted(undefined)}"

    def test_no_orphan_entries(self):
        orphans = self._defined() - self._referenced()
        assert not orphans, f"register entries nothing enforces: {sorted(orphans)}"

    def test_every_entry_has_the_full_schema(self):
        for entry in yaml.safe_load(self.REGISTER.read_text())["policies"]:
            for key in ("policy_id", "name", "regulation", "control", "enforced_by"):
                assert key in entry, f"{entry.get('policy_id')} is missing '{key}'"
            assert entry["regulation"], f"{entry['policy_id']} cites no regulation"
            assert entry["enforced_by"], f"{entry['policy_id']} names no enforcing check"


# ---------------------------------------------------------------------------
# Rego policy pack (requires conftest; the CI policy gate covers this too)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(shutil.which("conftest") is None, reason="conftest not installed")
class TestPolicyPack:
    def _run(self, *paths):
        return subprocess.run(
            ["conftest", "test", "--parser", "hcl2", "--combine", "-p", "policy", *paths],
            cwd=REPO, capture_output=True, text=True,
        )

    def test_compliant_infrastructure_passes(self):
        r = self._run("infrastructure/modules/ml-platform/main.tf",
                      "infrastructure/modules/ml-platform/variables.tf")
        assert r.returncode == 0, r.stdout

    def test_non_compliant_fixture_is_blocked(self):
        r = self._run("examples/terraform/non_compliant/main.tf",
                      "examples/terraform/non_compliant/variables.tf")
        assert r.returncode != 0
        for policy in ["POL-PRIV-001", "POL-PRIV-002", "POL-SEC-001", "POL-SEC-002", "POL-GOV-001"]:
            assert policy in r.stdout

    def test_cross_file_rules_fire(self):
        """POL-PRIV-003 lives in variables.tf and POL-PRIV-004 is an absence
        check. Both are only correct because conftest runs with --combine."""
        r = self._run("examples/terraform/non_compliant/main.tf",
                      "examples/terraform/non_compliant/variables.tf")
        assert "POL-PRIV-003" in r.stdout
        assert "POL-PRIV-004" in r.stdout


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
