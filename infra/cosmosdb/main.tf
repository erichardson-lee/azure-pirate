resource "azurerm_cosmosdb_account" "cosmosacc" {
  name                      = "cosmosdb-${var.nameconv}"
  location                  = var.location
  resource_group_name       = var.resource_group_name
  offer_type                = var.offer_type
  kind                      = var.kind
  enable_automatic_failover = false
  geo_location {
    location          = var.location
    failover_priority = 0
  }
  consistency_policy {
    consistency_level       = var.consistency_level
  }
}

resource "azurerm_cosmosdb_sql_database" "db" {
  name                = var.dbname
  resource_group_name = var.resource_group_name
  account_name        = azurerm_cosmosdb_account.cosmosacc.name
}

resource "azurerm_cosmosdb_sql_container" "container" {
  name                  = var.sql_container_name
  resource_group_name   = var.resource_group_name
  account_name          = azurerm_cosmosdb_account.cosmosacc.name
  database_name         = azurerm_cosmosdb_sql_database.db.name
  partition_key_path    = var.partition_key_path
  partition_key_version = 1
  throughput            = var.max_throughput

  indexing_policy {
    indexing_mode = var.indexing_mode

    included_path {
      path = "/*"
    }

    excluded_path {
      path = "/\"_etag\"/?"
    }
  }

}

resource "azurerm_key_vault_secret" "cosmosacc" {
  name         = "cosmos-acc-name"
  value        = azurerm_cosmosdb_account.cosmosacc.name
  key_vault_id = var.akv_id
  content_type = "text/plain"
}

resource "azurerm_key_vault_secret" "db" {
  name         = "cosmos-db-name"
  value        = var.dbname
  key_vault_id = var.akv_id
  content_type = "text/plain"
}

resource "azurerm_key_vault_secret" "container" {
  name         = "cosmos-cont-name"
  value        = var.sql_container_name
  key_vault_id = var.akv_id
  content_type = "text/plain"
}

resource "azurerm_key_vault_secret" "key" {
  name         = "cosmos-key"
  value        = azurerm_cosmosdb_account.cosmosacc.primary_key
  key_vault_id = var.akv_id
  content_type = "text/plain"
}