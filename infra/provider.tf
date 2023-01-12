terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "=3.38.0"
    }
  }

  backend "azurerm" {
    # Below are populated via the workflow
    resource_group_name  = "tf_state"
    storage_account_name = "dmcloughlin666tf"
    container_name       = "tfstate"
    key                  = "azurepirate.tfstate"
  }

}

# Used for the infra deployments
provider "azurerm" {
  subscription_id = var.subscription_id
  tenant_id       = var.az_tenant_id
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

provider "random" {}