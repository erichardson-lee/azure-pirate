output "cosmosacc" {
  value     = azurerm_key_vault_secret.cosmosacc.name
}

output "db" {
  value     = azurerm_key_vault_secret.db.name
}

output "container" {
  value     = azurerm_key_vault_secret.container.name
}

output "key" {
  value     = azurerm_key_vault_secret.key.name
  sensitive = true
}