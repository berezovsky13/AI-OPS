terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# ==================== Variables ====================
variable "candidate_name" {
  description = "Candidate identifier"
  type        = string
  default     = "x"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "East US"
}

# ==================== Locals ====================
locals {
  resource_prefix     = "chatbot-${var.candidate_name}"
  resource_group_name = "platform_candidate_${var.candidate_name}"
}

# ==================== Resource Group ====================
data "azurerm_resource_group" "main" {
  name = local.resource_group_name
}

# ==================== Networking ====================
resource "azurerm_virtual_network" "main" {
  name                = "${local.resource_prefix}-vnet"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "aks" {
  name                 = "aks-subnet"
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "redis" {
  name                 = "redis-subnet"
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

# ==================== AKS ====================
resource "azurerm_kubernetes_cluster" "main" {
  name                = "${local.resource_prefix}-aks"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  dns_prefix          = "${local.resource_prefix}-aks"

  default_node_pool {
    name                 = "default"
    vm_size              = "Standard_D2s_v3"
    vnet_subnet_id       = azurerm_subnet.aks.id
    auto_scaling_enabled = true
    min_count            = 2
    max_count            = 5
    node_count           = 2
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin    = "azure"
    load_balancer_sku = "standard"
    service_cidr      = "10.1.0.0/16"
    dns_service_ip    = "10.1.0.10"
  }
}

# ==================== Redis Cache ====================
resource "azurerm_redis_cache" "main" {
  name                = "${local.resource_prefix}-redis"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"

  non_ssl_port_enabled = false
  minimum_tls_version  = "1.2"

  redis_configuration {
    authentication_enabled = "true"
  }
}

# ==================== Azure OpenAI ====================
resource "azurerm_cognitive_account" "openai" {
  name                = "${local.resource_prefix}-openai"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  kind                = "OpenAI"
  sku_name            = "S0"

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_cognitive_deployment" "gpt4" {
  name                 = "gpt-4o-mini"
  cognitive_account_id = azurerm_cognitive_account.openai.id

  model {
    format  = "OpenAI"
    name    = "gpt-4o-mini"
    version = "2024-07-18"
  }

  sku {
    name     = "Standard"
    capacity = 1
  }
}

# ==================== Key Vault ====================
data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                       = "${local.resource_prefix}-kv-${substr(md5(data.azurerm_resource_group.main.id), 0, 6)}"
  location                   = data.azurerm_resource_group.main.location
  resource_group_name        = data.azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
}

# Key Vault access for AKS
resource "azurerm_key_vault_access_policy" "aks" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id

  secret_permissions = [
    "Get",
    "List"
  ]
}

# Store Redis password
resource "azurerm_key_vault_secret" "redis_password" {
  name         = "redis-password"
  value        = azurerm_redis_cache.main.primary_access_key
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [
    azurerm_key_vault_access_policy.aks
  ]
}

# ==================== RBAC ====================
resource "azurerm_role_assignment" "aks_openai" {
  principal_id         = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
  role_definition_name = "Cognitive Services User"
  scope                = azurerm_cognitive_account.openai.id
}

# ==================== Outputs ====================
output "resource_group_name" {
  value = data.azurerm_resource_group.main.name
}

output "aks_cluster_name" {
  value = azurerm_kubernetes_cluster.main.name
}

output "redis_hostname" {
  value = azurerm_redis_cache.main.hostname
}

output "openai_endpoint" {
  value = azurerm_cognitive_account.openai.endpoint
}

output "key_vault_name" {
  value = azurerm_key_vault.main.name
}

output "kube_config" {
  value     = azurerm_kubernetes_cluster.main.kube_config_raw
  sensitive = true
}