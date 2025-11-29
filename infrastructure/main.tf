module "ml_platform" {
  source = "./modules/ml-platform"

  project_name        = var.project_name
  location            = var.location
  environment         = var.environment
  data_classification = "confidential"
  retention_days      = 90
  contains_pii        = false
  enable_audit_logs   = true
}
