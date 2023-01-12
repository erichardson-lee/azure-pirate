resource "azurerm_application_insights" "appinsights" {
  name                = "appinsights-${var.nameconv}"
  location            = var.location
  resource_group_name = var.resource_group_name
  application_type    = "web"
}

resource "azurerm_application_insights_api_key" "write-annotations" {
  name                    = "appinsights-write-annotations-api-key"
  application_insights_id = azurerm_application_insights.appinsights.id
  write_permissions       = ["annotations"]
}
