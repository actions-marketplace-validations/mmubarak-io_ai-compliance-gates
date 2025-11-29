variable "project_name" {
  type = string
}

variable "location" {
  type    = string
  default = "uaenorth"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "data_classification" {
  type = string
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Invalid classification."
  }
}

variable "retention_days" {
  type    = number
  default = 90
}

variable "contains_pii" {
  type    = bool
  default = false
}

variable "enable_audit_logs" {
  type    = bool
  default = true
}
