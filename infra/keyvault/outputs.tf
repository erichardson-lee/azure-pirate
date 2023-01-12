output "akv_id" {
  value     = azurerm_key_vault.akv.id
}

output "vault_uri" {
  value     = azurerm_key_vault.akv.vault_uri
}

output "vault_name" {
  value     = azurerm_key_vault.akv.name
}

output "shorturlfunckey" {
  value     = azurerm_key_vault_secret.shorturlfunckey.name
}

output "twitteraccesstoken" {
  value     = azurerm_key_vault_secret.twitteraccesstoken.name
}

output "twitteraccesstokensecret" {
  value     = azurerm_key_vault_secret.twitteraccesstokensecret.name
}

output "twitterapikey" {
  value     = azurerm_key_vault_secret.twitterapikey.name
}

output "twitterapisecret" {
  value     = azurerm_key_vault_secret.twitterapisecret.name
}