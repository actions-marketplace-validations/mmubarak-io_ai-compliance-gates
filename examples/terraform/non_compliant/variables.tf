# Split out from main.tf on purpose: POL-PRIV-007 reads `variable`,
# which lives here, while the resource rules read `resource`, which
# lives in main.tf. Only a --combine run sees both.

variable "location" {
  type    = string
  default = "westeurope" # POL-PRIV-007: outside UAE data residency
}
