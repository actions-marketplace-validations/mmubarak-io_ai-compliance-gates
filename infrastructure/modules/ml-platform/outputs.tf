output "resource_group_name" {
  value = azurerm_resource_group.ml.name
}

output "storage_account_name" {
  value = azurerm_storage_account.ml_data.name
}

output "key_vault_name" {
  value = azurerm_key_vault.ml.name
}

output "compliance_status" {
  value = {
    encryption_enabled    = true
    https_only            = true
    tls_version           = "1.2"
    public_access_blocked = true
    versioning_enabled    = true
    retention_days        = var.retention_days
    audit_logging         = var.enable_audit_logs
    data_residency        = "UAE North"
  }
}
