# ============================================================
# Policy-as-Code: Terraform Compliance Rules
# ============================================================
# Machine-enforced version of templates/policy_mapping.yml.
# Run with:
#   conftest test --parser hcl2 --combine -p policy infrastructure/**/*.tf
#
# Every rule is tagged with its policy ID and the regulation
# it supports (UAE PDPL / GDPR / EU AI Act).
# ============================================================

package main

import rego.v1

# ------------------------------------------------------------
# Input normalization
# ------------------------------------------------------------
# The policy-check action runs conftest with --combine, so `input`
# arrives as a list of {path, contents} documents. Merging them here
# is what makes cross-file rules correct: a storage account declared
# in main.tf and its diagnostic setting in monitoring.tf must be
# judged together, not once per file. Without this, POL-PRIV-004
# fires a false positive on every file that lacks the setting, and
# POL-PRIV-003 silently passes whenever variables.tf isn't included.
#
# The fallback branch keeps the pack working when conftest is run
# without --combine (single document).
# ------------------------------------------------------------
_docs := input if is_array(input)

_docs := [{"path": "input", "contents": input}] if not is_array(input)

# resources[kind][name] -> resource body, merged across all documents
resources[kind][name] := cfg if {
	some doc in _docs
	some kind, named in doc.contents.resource
	some name, cfg in named
}

# variables[name] -> variable body, merged across all documents
variables[name] := cfg if {
	some doc in _docs
	some name, cfg in doc.contents.variable
}

# compliance_tags[key] -> value, merged across all documents
compliance_tags[key] := value if {
	some doc in _docs
	some key, value in doc.contents.locals.compliance_tags
}

_of_kind(kind) := object.get(resources, kind, {})

# ------------------------------------------------------------
# POL-PRIV-001: Data Protection in Transit
# UAE PDPL Art. 20 (security of processing) / GDPR Art. 32
# ------------------------------------------------------------
deny contains msg if {
	some name, sa in _of_kind("azurerm_storage_account")
	sa.min_tls_version != "TLS1_2"
	msg := sprintf("[POL-PRIV-001] Storage account '%s' must enforce TLS 1.2 (min_tls_version)", [name])
}

deny contains msg if {
	some name, sa in _of_kind("azurerm_storage_account")
	not sa.https_traffic_only_enabled == true
	msg := sprintf("[POL-PRIV-001] Storage account '%s' must enable HTTPS-only traffic", [name])
}

# ------------------------------------------------------------
# POL-PRIV-002: Data Retention
# UAE PDPL Art. 9 (retention limits) / GDPR Art. 5(1)(e)
# ------------------------------------------------------------
deny contains msg if {
	some name, sa in _of_kind("azurerm_storage_account")
	not sa.blob_properties.delete_retention_policy.days
	msg := sprintf("[POL-PRIV-002] Storage account '%s' must define a blob delete retention policy", [name])
}

deny contains msg if {
	some name, law in _of_kind("azurerm_log_analytics_workspace")
	law.retention_in_days < 90
	msg := sprintf("[POL-PRIV-002] Log Analytics workspace '%s' must retain audit logs >= 90 days", [name])
}

# ------------------------------------------------------------
# POL-PRIV-003: Data Residency (UAE)
# UAE PDPL Art. 22-23 (cross-border transfer restrictions)
# ------------------------------------------------------------
allowed_regions := {"uaenorth", "uaecentral"}

deny contains msg if {
	some name, v in variables
	name == "location"
	not allowed_regions[v["default"]]
	msg := sprintf("[POL-PRIV-003] Variable 'location' default '%s' violates UAE data residency (allowed: uaenorth, uaecentral)", [v["default"]])
}

# ------------------------------------------------------------
# POL-SEC-001: No Public Network Access
# UAE PDPL Art. 20 / GDPR Art. 32
# ------------------------------------------------------------
deny contains msg if {
	some name, sa in _of_kind("azurerm_storage_account")
	not sa.public_network_access_enabled == false
	msg := sprintf("[POL-SEC-001] Storage account '%s' must disable public network access", [name])
}

deny contains msg if {
	some name, kv in _of_kind("azurerm_key_vault")
	not kv.public_network_access_enabled == false
	msg := sprintf("[POL-SEC-001] Key Vault '%s' must disable public network access", [name])
}

deny contains msg if {
	some cname, c in _of_kind("azurerm_storage_container")
	c.container_access_type != "private"
	msg := sprintf("[POL-SEC-001] Storage container '%s' must be private", [cname])
}

# Defence in depth: public_network_access_enabled alone leaves the service
# reachable through network rules that default to Allow. Trivy AZU-0012 and
# AZU-0013 flagged this gap in the reference module; encoding it here means
# the policy pack catches it rather than an external scanner.
deny contains msg if {
	some name, sa in _of_kind("azurerm_storage_account")
	not sa.network_rules.default_action == "Deny"
	msg := sprintf("[POL-SEC-001] Storage account '%s' must set network_rules.default_action to Deny", [name])
}

deny contains msg if {
	some name, kv in _of_kind("azurerm_key_vault")
	not kv.network_acls.default_action == "Deny"
	msg := sprintf("[POL-SEC-001] Key Vault '%s' must set network_acls.default_action to Deny", [name])
}

# ------------------------------------------------------------
# POL-SEC-002: Access Control (RBAC, no shared keys)
# UAE PDPL Art. 20 / GDPR Art. 32
# ------------------------------------------------------------
deny contains msg if {
	some name, sa in _of_kind("azurerm_storage_account")
	not sa.shared_access_key_enabled == false
	msg := sprintf("[POL-SEC-002] Storage account '%s' must disable shared access keys (use RBAC/managed identity)", [name])
}

deny contains msg if {
	some name, kv in _of_kind("azurerm_key_vault")
	not kv.enable_rbac_authorization == true
	msg := sprintf("[POL-SEC-002] Key Vault '%s' must use RBAC authorization", [name])
}

# ------------------------------------------------------------
# POL-PRIV-004: Audit Logging
# UAE PDPL Art. 20 / GDPR Art. 30 (records of processing)
# ------------------------------------------------------------
# Cross-file rule: correct only because _docs merges every document.
deny contains msg if {
	count(_of_kind("azurerm_storage_account")) > 0
	count(_of_kind("azurerm_monitor_diagnostic_setting")) == 0
	msg := "[POL-PRIV-004] Storage resources require azurerm_monitor_diagnostic_setting for audit logging"
}

# ------------------------------------------------------------
# Governance metadata: compliance tags must be declared
# EU AI Act Art. 11 (technical documentation traceability)
# ------------------------------------------------------------
required_tags := {"DataClassification", "RetentionDays", "ContainsPII", "ComplianceFramework"}

deny contains msg if {
	count(compliance_tags) > 0
	some t in required_tags
	not compliance_tags[t]
	msg := sprintf("[POL-GOV-001] compliance_tags must declare '%s'", [t])
}
