# ============================================
# Compliant ML Platform - Azure UAE (reference module)
# ============================================
# Synthetic reference material written from public sources: azurerm_*
# arguments from the Terraform AzureRM provider registry, uaenorth from
# Azure's published region list. It exists so the policy pack has a
# realistic target to run against. It carries no subscription, tenant or
# resource identifiers and describes no real environment.
#
# Policy Mappings:
# - POL-PRIV-001: Data Protection → TLS 1.2, Encryption
# - POL-PRIV-002: Data Retention → Lifecycle Policy
# - POL-PRIV-003: Data Residency → UAE North Region
# - POL-SEC-001: Security → Private Access Only
# - POL-SEC-002: Access Control → RBAC
# - POL-PRIV-004: Audit → Diagnostic Logging
# ============================================

locals {
  resource_prefix = "${var.project_name}${var.environment}"

  compliance_tags = {
    DataClassification  = var.data_classification
    RetentionDays       = var.retention_days
    ContainsPII         = var.contains_pii
    ComplianceFramework = "UAE-PDPL,GDPR,AI-ACT"
    ManagedBy           = "Terraform"
  }
}

# ============================================
# Resource Group - UAE Data Residency
# ============================================
resource "azurerm_resource_group" "ml" {
  name     = "rg-${local.resource_prefix}-ml"
  location = var.location # uaenorth
  tags     = local.compliance_tags
}

# ============================================
# Storage Account - Encrypted & Secure
# ============================================
resource "azurerm_storage_account" "ml_data" {
  name                = "st${local.resource_prefix}ml"
  resource_group_name = azurerm_resource_group.ml.name
  location            = azurerm_resource_group.ml.location

  account_tier             = "Standard"
  account_replication_type = "GRS"
  account_kind             = "StorageV2"

  # POL-SEC-001: Security Controls
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false
  shared_access_key_enabled       = false

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
  }

  # POL-SEC-001: default-deny at the network layer, not just the
  # public_network_access_enabled switch. Without this an allow-listed
  # VNet rule is the only thing standing between the data and the internet.
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.compliance_tags
}

# ============================================
# Blob Containers
# ============================================
resource "azurerm_storage_container" "ml_datasets" {
  name                  = "ml-datasets"
  storage_account_name  = azurerm_storage_account.ml_data.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "ml_models" {
  name                  = "ml-models"
  storage_account_name  = azurerm_storage_account.ml_data.name
  container_access_type = "private"
}

# ============================================
# Lifecycle Policy - Data Retention
# POL-PRIV-002: Auto-delete after 90 days
# ============================================
resource "azurerm_storage_management_policy" "retention" {
  storage_account_id = azurerm_storage_account.ml_data.id

  rule {
    name    = "data-retention-policy"
    enabled = true

    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["ml-datasets/"]
    }

    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = var.retention_days
      }
      snapshot {
        delete_after_days_since_creation_greater_than = 30
      }
    }
  }

  rule {
    name    = "model-archival-policy"
    enabled = true

    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["ml-models/"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 90
        tier_to_archive_after_days_since_modification_greater_than = 365
      }
    }
  }
}

# ============================================
# Log Analytics - Audit Logging
# POL-PRIV-004: Track all access
# ============================================
resource "azurerm_log_analytics_workspace" "ml" {
  count               = var.enable_audit_logs ? 1 : 0
  name                = "log-${local.resource_prefix}-ml"
  resource_group_name = azurerm_resource_group.ml.name
  location            = azurerm_resource_group.ml.location
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = local.compliance_tags
}

# ============================================
# Diagnostic Settings - Storage Audit
# ============================================
resource "azurerm_monitor_diagnostic_setting" "storage" {
  count                      = var.enable_audit_logs ? 1 : 0
  name                       = "diag-storage-audit"
  target_resource_id         = "${azurerm_storage_account.ml_data.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.ml[0].id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }
  metric {
    category = "Transaction"
    enabled  = true
  }
}

# ============================================
# Key Vault - Secrets Management
# ============================================
resource "azurerm_key_vault" "ml" {
  name                          = "kv-${local.resource_prefix}-ml"
  resource_group_name           = azurerm_resource_group.ml.name
  location                      = azurerm_resource_group.ml.location
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  soft_delete_retention_days    = 90
  purge_protection_enabled      = true
  enable_rbac_authorization     = true
  public_network_access_enabled = false
  tags                          = local.compliance_tags

  # POL-SEC-001: same default-deny posture for secrets.
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

data "azurerm_client_config" "current" {}
