data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "akv" {
  name                         = "akv-${var.nameconv}"
  resource_group_name          = var.resource_group_name
  location                     = var.location
  enabled_for_disk_encryption  = false
  tenant_id                    = var.az_tenant_id
  # soft_delete_retention_days   = 7
  purge_protection_enabled     = false
  sku_name                     = "standard"
}

resource "azurerm_key_vault_access_policy" "spn" {
  key_vault_id = azurerm_key_vault.akv.id

  tenant_id = var.az_tenant_id
  object_id = data.azurerm_client_config.current.object_id

  secret_permissions = [
    "Get", "List", "Set", "Delete", "Purge", "Recover", "Restore"
  ]

  depends_on = [
    azurerm_key_vault.akv
  ]

}

# resource "azurerm_role_assignment" "tf_kvc" {
#   scope                = azurerm_key_vault.akv.id
#   role_definition_name = "Key Vault Contributor"
#   principal_id         = data.azurerm_client_config.current.object_id
#   depends_on = [
#     azurerm_key_vault_access_policy.spn
#   ]
# }

resource "azurerm_key_vault_secret" "shorturlfunckey" {
  name         = "short-url-func-key"
  value        = var.shorturlfunckey
  key_vault_id = azurerm_key_vault.akv.id
  content_type = "text/plain"
  depends_on = [
    azurerm_key_vault_access_policy.spn
  ]
}

resource "azurerm_key_vault_secret" "twitteraccesstoken" {
  name         = "twitteraccesstoken"
  value        = var.twitteraccesstoken
  key_vault_id = azurerm_key_vault.akv.id
  content_type = "text/plain"
  depends_on = [
    azurerm_key_vault_access_policy.spn
  ]
}

resource "azurerm_key_vault_secret" "twitteraccesstokensecret" {
  name         = "twitteraccesstokensecret"
  value        = var.twitteraccesstokensecret
  key_vault_id = azurerm_key_vault.akv.id
  content_type = "text/plain"
  depends_on = [
    azurerm_key_vault_access_policy.spn
  ]
}

resource "azurerm_key_vault_secret" "twitterapikey" {
  name         = "twitterapikey"
  value        = var.twitterapikey
  key_vault_id = azurerm_key_vault.akv.id
  content_type = "text/plain"
  depends_on = [
    azurerm_key_vault_access_policy.spn
  ]
}

resource "azurerm_key_vault_secret" "twitterapisecret" {
  name         = "twitterapisecret"
  value        = var.twitterapisecret
  key_vault_id = azurerm_key_vault.akv.id
  content_type = "text/plain"
  depends_on = [
    azurerm_key_vault_access_policy.spn
  ]
}