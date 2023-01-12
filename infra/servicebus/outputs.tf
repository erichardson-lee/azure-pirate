output "servicebus-queue-connstr" {
  value     = azurerm_key_vault_secret.queuekey.name
  sensitive = true
}

output "servicebus-namespace-connstr" {
  value     = azurerm_key_vault_secret.namespacekey.name
  sensitive = true
}

output "sbusqueue" {
  value     = azurerm_servicebus_queue.queue.name
}