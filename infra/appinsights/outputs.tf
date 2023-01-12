output "app_insights_cs" {
  sensitive = true
  value     = azurerm_application_insights.appinsights.connection_string
}

output "app_insights_key" {
  sensitive = true
  value     = azurerm_application_insights.appinsights.instrumentation_key
}

output "app_insights_api_application_id" {
  value = azurerm_application_insights_api_key.write-annotations.id
}

output "app_insights_api_key_write_annotations" {
  sensitive = true
  value     = azurerm_application_insights_api_key.write-annotations.api_key
}

output "app_insights_id" {
  value     = azurerm_application_insights.appinsights.id
  sensitive = true
}