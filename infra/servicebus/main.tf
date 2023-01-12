resource "azurerm_servicebus_namespace" "namespace" {
  name                = "servicebus-${var.nameconv}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = var.sku
}

resource "azurerm_servicebus_queue" "queue" {
  name         = var.queue
  namespace_id = azurerm_servicebus_namespace.namespace.id
  enable_partitioning = true
  max_delivery_count = 20
  lock_duration = "PT1M" # 5 mins is the max
}

# queue specific
resource "azurerm_servicebus_queue_authorization_rule" "queuekey" {
  name     = "prim"
  queue_id = azurerm_servicebus_queue.queue.id
  listen = true
  send   = true
  manage = true
}

resource "azurerm_key_vault_secret" "queuekey" {
  name         = "servicebus-queue-connstr"
  value        = azurerm_servicebus_queue_authorization_rule.queuekey.primary_connection_string
  key_vault_id = var.akv_id
  content_type = "text/plain"
}

# namespace specific
resource "azurerm_servicebus_namespace_authorization_rule" "namespacekey" {
  name     = "prim"
  namespace_id = azurerm_servicebus_namespace.namespace.id
  listen = true
  send   = true
  manage = true
}

resource "azurerm_key_vault_secret" "namespacekey" {
  name         = "servicebus-namespace-connstr"
  value        = azurerm_servicebus_namespace_authorization_rule.namespacekey.primary_connection_string
  key_vault_id = var.akv_id
  content_type = "text/plain"
}