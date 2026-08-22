# ============================================================
# Policy-as-Code: Terraform Compliance Rules
# ============================================================
# Machine-enforced version of templates/policy_mapping.yml.
# Run with:
#   conftest test --parser hcl2 -p policy infrastructure/modules/ml-platform/*.tf
#
# Every rule is tagged with its policy ID and the regulation
# it supports (UAE PDPL / GDPR / EU AI Act).
# ============================================================

package main

import rego.v1

# ------------------------------------------------------------
# POL-PRIV-001: Data Protection in Transit
# UAE PDPL Art. 20 (security of processing) / GDPR Art. 32
# ------------------------------------------------------------
deny contains msg if {
	some name
	sa := input.resource.azurerm_storage_account[name]
	sa.min_tls_version != "TLS1_2"
	msg := sprintf("[POL-PRIV-001] Storage account '%s' must enforce TLS 1.2 (min_tls_version)", [name])
}

deny contains msg if {
	some name
	sa := input.resource.azurerm_storage_account[name]
	not sa.https_traffic_only_enabled == true
	msg := sprintf("[POL-PRIV-001] Storage account '%s' must enable HTTPS-only traffic", [name])
}

# ------------------------------------------------------------
# POL-PRIV-006: Data Retention
# UAE PDPL Art. 9 (retention limits) / GDPR Art. 5(1)(e)
# ------------------------------------------------------------
deny contains msg if {
	some name
	sa := input.resource.azurerm_storage_account[name]
	not sa.blob_properties.delete_retention_policy.days
	msg := sprintf("[POL-PRIV-006] Storage account '%s' must define a blob delete retention policy", [name])
}

deny contains msg if {
	some name
	law := input.resource.azurerm_log_analytics_workspace[name]
	law.retention_in_days < 90
	msg := sprintf("[POL-PRIV-006] Log Analytics workspace '%s' must retain audit logs >= 90 days", [name])
}

# ------------------------------------------------------------
# POL-PRIV-007: Data Residency (UAE)
# UAE PDPL Art. 22-23 (cross-border transfer restrictions)
# ------------------------------------------------------------
allowed_regions := {"uaenorth", "uaecentral"}

deny contains msg if {
	some name
	v := input.variable[name]
	name == "location"
	not allowed_regions[v["default"]]
	msg := sprintf("[POL-PRIV-007] Variable 'location' default '%s' violates UAE data residency (allowed: uaenorth, uaecentral)", [v["default"]])
}

# ------------------------------------------------------------
# POL-SEC-001: No Public Network Access
# UAE PDPL Art. 20 / GDPR Art. 32
# ------------------------------------------------------------
deny contains msg if {
	some name
	sa := input.resource.azurerm_storage_account[name]
	not sa.public_network_access_enabled == false
	msg := sprintf("[POL-SEC-001] Storage account '%s' must disable public network access", [name])
}

deny contains msg if {
	some name
	kv := input.resource.azurerm_key_vault[name]
	not kv.public_network_access_enabled == false
	msg := sprintf("[POL-SEC-001] Key Vault '%s' must disable public network access", [name])
}

deny contains msg if {
	some cname
	c := input.resource.azurerm_storage_container[cname]
	c.container_access_type != "private"
	msg := sprintf("[POL-SEC-001] Storage container '%s' must be private", [cname])
}

# ------------------------------------------------------------
# POL-SEC-002: Access Control (RBAC, no shared keys)
# UAE PDPL Art. 20 / GDPR Art. 32
# ------------------------------------------------------------
deny contains msg if {
	some name
	sa := input.resource.azurerm_storage_account[name]
	not sa.shared_access_key_enabled == false
	msg := sprintf("[POL-SEC-002] Storage account '%s' must disable shared access keys (use RBAC/managed identity)", [name])
}

deny contains msg if {
	some name
	kv := input.resource.azurerm_key_vault[name]
	not kv.enable_rbac_authorization == true
	msg := sprintf("[POL-SEC-002] Key Vault '%s' must use RBAC authorization", [name])
}

# ------------------------------------------------------------
# POL-PRIV-010: Audit Logging
# UAE PDPL Art. 20 / GDPR Art. 30 (records of processing)
# ------------------------------------------------------------
deny contains msg if {
	count(input.resource.azurerm_storage_account) > 0
	not input.resource.azurerm_monitor_diagnostic_setting
	msg := "[POL-PRIV-010] Storage resources require azurerm_monitor_diagnostic_setting for audit logging"
}

# ------------------------------------------------------------
# Governance metadata: compliance tags must be declared
# EU AI Act Art. 11 (technical documentation traceability)
# ------------------------------------------------------------
required_tags := {"DataClassification", "RetentionDays", "ContainsPII", "ComplianceFramework"}

deny contains msg if {
	tags := input.locals.compliance_tags
	some t in required_tags
	not tags[t]
	msg := sprintf("[POL-GOV-001] compliance_tags must declare '%s'", [t])
}
