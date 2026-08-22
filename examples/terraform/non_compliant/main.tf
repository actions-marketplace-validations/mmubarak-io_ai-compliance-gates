# Deliberately non-compliant Terraform — the negative fixture for the
# policy gate. Every resource here violates at least one rule in
# policy/terraform_compliance.rego.
#
# Note there is no azurerm_monitor_diagnostic_setting anywhere in this
# directory: POL-PRIV-010 can only catch that when conftest runs with
# --combine, which is exactly what the policy-check action does.

locals {
  compliance_tags = {
    DataClassification = "Confidential"
    # RetentionDays, ContainsPII and ComplianceFramework are missing
    # on purpose -> POL-GOV-001
  }
}

resource "azurerm_storage_account" "bad" {
  name                = "stnoncompliant"
  resource_group_name = "rg-demo"
  location            = var.location

  account_tier             = "Standard"
  account_replication_type = "LRS"

  min_tls_version                 = "TLS1_0" # POL-PRIV-001
  https_traffic_only_enabled      = false    # POL-PRIV-001
  public_network_access_enabled   = true     # POL-SEC-001
  shared_access_key_enabled       = true     # POL-SEC-002
  allow_nested_items_to_be_public = true

  # no blob_properties.delete_retention_policy -> POL-PRIV-006
}

resource "azurerm_storage_container" "bad" {
  name                  = "public-datasets"
  storage_account_name  = azurerm_storage_account.bad.name
  container_access_type = "blob" # POL-SEC-001
}

resource "azurerm_key_vault" "bad" {
  name                          = "kv-noncompliant"
  resource_group_name           = "rg-demo"
  location                      = var.location
  tenant_id                     = "00000000-0000-0000-0000-000000000000"
  sku_name                      = "standard"
  enable_rbac_authorization     = false # POL-SEC-002
  public_network_access_enabled = true  # POL-SEC-001
}

resource "azurerm_log_analytics_workspace" "bad" {
  name                = "log-noncompliant"
  resource_group_name = "rg-demo"
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = 30 # POL-PRIV-006 (< 90)
}
