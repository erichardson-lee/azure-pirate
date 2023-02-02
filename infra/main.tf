locals {
  nameconv        = "azpirate"
  abbr            = "azp"
  dbname          = "azurepiratedb"
  dbcontainername = "posts"
}

resource "azurerm_resource_group" "rsg" {
  name     = "rsg-uks-azpirate"
  location = var.location
}

module "keyvault" {
  source                   = "./keyvault"
  location                 = var.location
  resource_group_name      = azurerm_resource_group.rsg.name
  nameconv                 = local.nameconv
  az_tenant_id             = var.az_tenant_id
  shorturlfunckey          = var.shorturlfunckey
  twitteraccesstoken       = var.twitteraccesstoken
  twitteraccesstokensecret = var.twitteraccesstokensecret
  twitterapikey            = var.twitterapikey
  twitterapisecret         = var.twitterapisecret
}

module "cosmosdb" {
  source              = "./cosmosdb"
  location            = var.location
  resource_group_name = azurerm_resource_group.rsg.name
  nameconv            = local.nameconv
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"
  dbname              = local.dbname
  sql_container_name  = local.dbcontainername
  consistency_level   = "Session"
  max_throughput      = "400"
  partition_key_path  = "/date"
  indexing_mode       = "consistent"
  akv_id              = module.keyvault.akv_id
  depends_on = [
    module.keyvault
  ]
}

module "servicebus" {
  source              = "./servicebus"
  location            = var.location
  resource_group_name = azurerm_resource_group.rsg.name
  nameconv            = local.nameconv
  sku                 = "Basic"
  queue               = "tosend"
  akv_id              = module.keyvault.akv_id
  depends_on = [
    module.keyvault
  ]
}

module "appinsights" {
  source              = "./appinsights"
  location            = var.location
  resource_group_name = azurerm_resource_group.rsg.name
  nameconv            = local.nameconv
}

module "feeds-function-apps" {
  source                   = "./function-apps"
  name                     = "feed"
  nameconv                 = local.nameconv
  abbr                     = local.abbr
  location                 = var.location
  resource_group_name      = azurerm_resource_group.rsg.name
  account_tier             = "Standard"
  account_replication_type = "LRS"
  os_type                  = "Linux"
  sku_name                 = "Y1"
  app_insights_key         = module.appinsights.app_insights_key
  app_insights_cs          = module.appinsights.app_insights_cs
  az_tenant_id             = var.az_tenant_id
  akv_id                   = module.keyvault.akv_id
  vault_name               = module.keyvault.vault_name
  app_settings = {
    "FUNCTIONS_EXTENSION_VERSION" = "~4",
    "FUNCTIONS_WORKER_RUNTIME"    = "powershell"
    "FUNCTIONS_WORKER_RUNTIME_VERSION" = "~7"
    "powerShellVersion" = "~7"
    "hoursBack"                       = "-48",
    "localDataFile"                   = "////home////data////feeds.csv"
    "localTesting"                    = "false"
    "CosmosAccountName"               = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.cosmosdb.cosmosacc})",
    "CosmosDBName"                    = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.cosmosdb.db})",
    "CosmosCollectionName"            = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.cosmosdb.container})",
    "CosmosAccountKey"                = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.cosmosdb.key})",
    "ServiceBusQueueConnstr" = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.servicebus.servicebus-queue-connstr})",
    "ShortURLFuncKey"                 = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.keyvault.shorturlfunckey})"
  }
  depends_on = [
    module.keyvault,
    module.cosmosdb
  ]
}

module "tweet-function-apps" {
  source                   = "./function-apps"
  name                     = "tweet"
  nameconv                 = local.nameconv
  abbr                     = local.abbr
  location                 = var.location
  resource_group_name      = azurerm_resource_group.rsg.name
  account_tier             = "Standard"
  account_replication_type = "LRS"
  os_type                  = "Linux"
  sku_name                 = "Y1"
  app_insights_key         = module.appinsights.app_insights_key
  app_insights_cs          = module.appinsights.app_insights_cs
  az_tenant_id             = var.az_tenant_id
  akv_id                   = module.keyvault.akv_id
  vault_name               = module.keyvault.vault_name
  app_settings = {
    "FUNCTIONS_EXTENSION_VERSION" = "~4",
    "FUNCTIONS_WORKER_RUNTIME"    = "powershell"
    "FUNCTIONS_WORKER_RUNTIME_VERSION" = "~7"
    "powerShellVersion" = "~7"
    "localDataFile" = "////home////data////sddefault.jpg"
    "SbusConnStr" = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.servicebus.servicebus-queue-connstr})",
    "TwitterAccessToken" = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.keyvault.twitteraccesstoken})",
    "TwitterAccessTokensecret" = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.keyvault.twitteraccesstokensecret})",
    "TwitterApiKey" = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.keyvault.twitterapikey})",
    "TwitterApiSecret" = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.keyvault.twitterapisecret})"
  }
  depends_on = [
    module.keyvault,
    module.servicebus
  ]
}

module "apis-function-apps" {
  source                   = "./function-apps"
  name                     = "api"
  nameconv                 = local.nameconv
  abbr                     = local.abbr
  location                 = var.location
  resource_group_name      = azurerm_resource_group.rsg.name
  account_tier             = "Standard"
  account_replication_type = "LRS"
  os_type                  = "Linux"
  sku_name                 = "Y1"
  app_insights_key         = module.appinsights.app_insights_key
  app_insights_cs          = module.appinsights.app_insights_cs
  az_tenant_id             = var.az_tenant_id
  akv_id                   = module.keyvault.akv_id
  vault_name               = module.keyvault.vault_name
  app_settings = {
    "FUNCTIONS_EXTENSION_VERSION" = "~4",
    "FUNCTIONS_WORKER_RUNTIME"    = "powershell"
    "FUNCTIONS_WORKER_RUNTIME_VERSION" = "~7"
    "powerShellVersion" = "~7"
    "CosmosAccountName"               = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.cosmosdb.cosmosacc})",
    "CosmosDBName"                    = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.cosmosdb.db})",
    "CosmosCollectionName"            = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.cosmosdb.container})",
    "CosmosAccountKey"                = "@Microsoft.KeyVault(VaultName=${module.keyvault.vault_name};SecretName=${module.cosmosdb.key})",
  }
  depends_on = [
    module.keyvault,
    module.cosmosdb
  ]
}