resource "random_id" "storage_account_name_unique" {
  byte_length = 4
}

# azptweetee361253a8e6.file.core.windows.net

resource "azurerm_storage_account" "storage" {
  name                     = "${var.abbr}${var.name}${random_id.storage_account_name_unique.hex}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = var.account_tier
  account_replication_type = var.account_replication_type
}

# forced time delay to allow storage account creation
resource "time_sleep" "storage_creation" {
  create_duration = "1m"

  triggers = {
    storage_creation = azurerm_storage_account.storage.primary_access_key
  }
}

resource "azurerm_service_plan" "asp" {
  name                = "${var.name}-app-service-plan"
  resource_group_name = var.resource_group_name
  location            = var.location
  os_type             = var.os_type
  sku_name            = var.sku_name
  depends_on = [
    time_sleep.storage_creation
  ]
}

resource "azurerm_linux_function_app" "function" {
  name                       = "${var.name}-${var.nameconv}"
  resource_group_name        = var.resource_group_name
  location                   = var.location
  storage_account_name       = azurerm_storage_account.storage.name
  storage_account_access_key = azurerm_storage_account.storage.primary_access_key
  service_plan_id            = azurerm_service_plan.asp.id
  https_only                 = true

  identity {
    type = "SystemAssigned"
  }

  site_config {
    http2_enabled     = true
    use_32_bit_worker = false
    always_on         = var.always_on
    application_stack {
      powershell_core_version = 7.2
    }
  }

  functions_extension_version = "~4"

  app_settings = merge(
    {
      # These are needed for the function app to be hooked up to the app insights
      "APPINSIGHTS_INSTRUMENTATIONKEY"             = var.app_insights_key
      "APPLICATIONINSIGHTS_CONNECTION_STRING"      = var.app_insights_cs
      "ApplicationInsightsAgent_EXTENSION_VERSION" = "~2"
    },
    var.app_settings
  )

  lifecycle {
    ignore_changes = [
      app_settings["WEBSITE_RUN_FROM_PACKAGE"]
    ]
  }

  depends_on = [
    time_sleep.storage_creation
  ]

}

# resource "null_resource" "ucf_fa" {
#   provisioner "local-exec" {
#     command = <<-EOT
#       az login --service-principal --username '348c7924-f672-41fa-8f77-5dde88631547' -p='Zfq8Q~d4UxF4n~LAtjzdmb8XJxgCnG0dXWhsnb.I' --tenant "a74bd6b6-c880-498d-95aa-9d01c3f42764"
      
#       az functionapp update --name ${azurerm_linux_function_app.function.name} --resource-group ${var.resource_group_name} --set siteConfig.powerShellVersion=~7
#     EOT
#   }
#   depends_on = [azurerm_linux_function_app.function]
#   triggers = {
#         build_number = "1"
#   }
# }

resource "azurerm_key_vault_access_policy" "funcapp" {
  key_vault_id = var.akv_id
  tenant_id    = var.az_tenant_id
  object_id    = azurerm_linux_function_app.function.identity[0].principal_id

  secret_permissions = [
    "Get", "List"
  ]

  depends_on = [
    azurerm_linux_function_app.function
  ]

}

data "azurerm_function_app_host_keys" "host_keys" {
  name                = azurerm_linux_function_app.function.name
  resource_group_name = var.resource_group_name
  depends_on = [
    azurerm_linux_function_app.function
  ]
}

resource "azurerm_key_vault_secret" "host_key" {
  name         = "${azurerm_linux_function_app.function.name}-key"
  value        = data.azurerm_function_app_host_keys.host_keys.primary_key
  key_vault_id = var.akv_id
  content_type = "text/plain"
  depends_on = [
    azurerm_storage_account.storage,
    azurerm_linux_function_app.function
  ]
}