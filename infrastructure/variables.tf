variable "location" {
  description = "Azure region (UAE)"
  type        = string
  default     = "uaenorth"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "compliantml"
}

variable "environment" {
  type    = string
  default = "dev"
}
