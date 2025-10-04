terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
  
  # Backend for state management
  backend "azurerm" {
    resource_group_name  = "terraform-state"
    storage_account_name = "tfstatechatbot"
    container_name      = "tfstate"
    key                = "chatbot.terraform.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

provider "kubernetes" {
  host                   = azurerm_kubernetes_cluster.main.kube_config[0].host
  client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_certificate)
  client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_key)
  cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].cluster_ca_certificate)
}

provider "helm" {
  kubernetes {
    host                   = azurerm_kubernetes_cluster.main.kube_config[0].host
    client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_certificate)
    client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_key)
    cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].cluster_ca_certificate)
  }
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

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

# ==================== Locals ====================
locals {
  resource_prefix     = "chatbot-${var.candidate_name}"
  resource_group_name = "platform_candidate_${var.candidate_name}"
  
  tags = {
    Environment = var.environment
    Project     = "Chatbot"
    Candidate   = var.candidate_name
    ManagedBy   = "Terraform"
  }
}

# ==================== Data Sources ====================
data "azurerm_resource_group" "main" {
  name = local.resource_group_name
}

data "azurerm_client_config" "current" {}

# ==================== Networking ====================
resource "azurerm_virtual_network" "main" {
  name                = "${local.resource_prefix}-vnet"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  address_space       = ["10.0.0.0/16"]
  
  tags = local.tags
}

# Subnet for Application Gateway
resource "azurerm_subnet" "appgw" {
  name                 = "appgw-subnet"
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.0.0/24"]
}

# Subnet for AKS
resource "azurerm_subnet" "aks" {
  name                 = "aks-subnet"
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/23"]  # Larger subnet for more pods
  
  delegation {
    name = "aks-delegation"
    service_delegation {
      name = "Microsoft.ContainerService/managedClusters"
    }
  }
}

# Subnet for Redis with Private Endpoint
resource "azurerm_subnet" "redis" {
  name                 = "redis-subnet"
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.3.0/24"]
  
  private_endpoint_network_policies_enabled = false
}

# Subnet for Azure OpenAI Private Endpoint
resource "azurerm_subnet" "openai" {
  name                 = "openai-subnet"
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.4.0/24"]
  
  private_endpoint_network_policies_enabled = false
}

# Subnet for Azure Firewall
resource "azurerm_subnet" "firewall" {
  name                 = "AzureFirewallSubnet"  # Must be exactly this name
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.5.0/24"]
}

# ==================== Network Security Groups ====================
resource "azurerm_network_security_group" "appgw" {
  name                = "${local.resource_prefix}-appgw-nsg"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  
  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
  
  security_rule {
    name                       = "AllowHTTP"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
  
  security_rule {
    name                       = "AllowGatewayManager"
    priority                   = 102
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "65200-65535"
    source_address_prefix      = "GatewayManager"
    destination_address_prefix = "*"
  }
  
  tags = local.tags
}

resource "azurerm_subnet_network_security_group_association" "appgw" {
  subnet_id                 = azurerm_subnet.appgw.id
  network_security_group_id = azurerm_network_security_group.appgw.id
}

resource "azurerm_network_security_group" "aks" {
  name                = "${local.resource_prefix}-aks-nsg"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  
  tags = local.tags
}

resource "azurerm_subnet_network_security_group_association" "aks" {
  subnet_id                 = azurerm_subnet.aks.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

# ==================== Azure Firewall ====================
resource "azurerm_public_ip" "firewall" {
  name                = "${local.resource_prefix}-fw-pip"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
  
  tags = local.tags
}

resource "azurerm_firewall" "main" {
  name                = "${local.resource_prefix}-fw"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  zones               = ["1", "2", "3"]
  
  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.firewall.id
    public_ip_address_id = azurerm_public_ip.firewall.id
  }
  
  tags = local.tags
}

# ==================== Application Gateway with WAF ====================
resource "azurerm_public_ip" "appgw" {
  name                = "${local.resource_prefix}-appgw-pip"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
  
  tags = local.tags
}

resource "azurerm_web_application_firewall_policy" "main" {
  name                = "${local.resource_prefix}-waf-policy"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  
  policy_settings {
    enabled                     = true
    mode                        = "Prevention"
    request_body_check          = true
    file_upload_limit_in_mb     = 100
    max_request_body_size_in_kb = 128
  }
  
  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
  }
  
  tags = local.tags
}

resource "azurerm_application_gateway" "main" {
  name                = "${local.resource_prefix}-appgw"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  zones               = ["1", "2", "3"]
  
  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
  }
  
  autoscale_configuration {
    min_capacity = 10
    max_capacity = 125  # Maximum for handling millions of requests
  }
  
  gateway_ip_configuration {
    name      = "gateway-ip-config"
    subnet_id = azurerm_subnet.appgw.id
  }
  
  frontend_port {
    name = "http-port"
    port = 80
  }
  
  frontend_port {
    name = "https-port"
    port = 443
  }
  
  frontend_ip_configuration {
    name                 = "frontend-ip"
    public_ip_address_id = azurerm_public_ip.appgw.id
  }
  
  backend_address_pool {
    name = "aks-backend-pool"
  }
  
  backend_http_settings {
    name                  = "backend-http-settings"
    cookie_based_affinity = "Enabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 60
    probe_name            = "health-probe"
    
    connection_draining {
      enabled           = true
      drain_timeout_sec = 60
    }
  }
  
  probe {
    name                = "health-probe"
    protocol            = "Http"
    path                = "/health"
    interval            = 30
    timeout             = 30
    unhealthy_threshold = 3
    host                = "127.0.0.1"
  }
  
  http_listener {
    name                           = "http-listener"
    frontend_ip_configuration_name = "frontend-ip"
    frontend_port_name             = "http-port"
    protocol                       = "Http"
  }
  
  request_routing_rule {
    name                       = "http-rule"
    rule_type                  = "Basic"
    http_listener_name         = "http-listener"
    backend_address_pool_name  = "aks-backend-pool"
    backend_http_settings_name = "backend-http-settings"
    priority                   = 100
  }
  
  firewall_policy_id = azurerm_web_application_firewall_policy.main.id
  
  tags = local.tags
}

# ==================== AKS Cluster ====================
resource "azurerm_kubernetes_cluster" "main" {
  name                = "${local.resource_prefix}-aks"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  dns_prefix          = "${local.resource_prefix}-aks"
  kubernetes_version  = "1.28.5"
  
  default_node_pool {
    name                 = "system"
    vm_size              = "Standard_D4s_v5"
    vnet_subnet_id       = azurerm_subnet.aks.id
    enable_auto_scaling  = true
    min_count            = 3
    max_count            = 10
    node_count           = 3
    zones                = ["1", "2", "3"]
    os_disk_size_gb      = 100
    type                 = "VirtualMachineScaleSets"
    
    node_labels = {
      "nodepool-type" = "system"
      "environment"   = var.environment
    }
    
    tags = local.tags
  }
  
  # Additional node pool for application workloads
  identity {
    type = "SystemAssigned"
  }
  
  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
    service_cidr      = "10.1.0.0/16"
    dns_service_ip    = "10.1.0.10"
  }
  
  addon_profile {
    oms_agent {
      enabled                    = true
      log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
    }
    
    azure_policy {
      enabled = true
    }
    
    ingress_application_gateway {
      enabled      = true
      gateway_id   = azurerm_application_gateway.main.id
    }
  }
  
  auto_scaler_profile {
    balance_similar_node_groups      = true
    max_graceful_termination_sec     = 600
    scale_down_delay_after_add       = "10m"
    scale_down_delay_after_delete    = "10s"
    scale_down_delay_after_failure   = "3m"
    scan_interval                     = "10s"
    scale_down_unneeded               = "10m"
    scale_down_unready                = "20m"
    scale_down_utilization_threshold = "0.5"
  }
  
  tags = local.tags
}

# Application node pool for high performance
resource "azurerm_kubernetes_cluster_node_pool" "app" {
  name                  = "app"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size              = "Standard_D8s_v5"
  vnet_subnet_id       = azurerm_subnet.aks.id
  enable_auto_scaling  = true
  min_count            = 10
  max_count            = 100
  node_count           = 10
  zones                = ["1", "2", "3"]
  os_disk_size_gb      = 200
  
  node_labels = {
    "nodepool-type" = "application"
    "workload"      = "chatbot"
    "environment"   = var.environment
  }
  
  node_taints = [
    "workload=chatbot:NoSchedule"
  ]
  
  tags = local.tags
}

# ==================== Redis Cache Premium ====================
resource "azurerm_redis_cache" "main" {
  name                = "${local.resource_prefix}-redis"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  capacity            = 3
  family              = "P"
  sku_name            = "Premium"
  
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"
  zones               = ["1", "2", "3"]
  
  redis_configuration {
    enable_authentication = true
    maxmemory_reserved    = 20
    maxmemory_delta       = 20
    maxmemory_policy      = "allkeys-lru"
    
    # Enable clustering for high throughput
    cluster_enabled = true
  }
  
  # Patch schedule for maintenance
  patch_schedule {
    day_of_week    = "Sunday"
    start_hour_utc = 2
  }
  
  tags = local.tags
}

# Private Endpoint for Redis
resource "azurerm_private_endpoint" "redis" {
  name                = "${local.resource_prefix}-redis-pe"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.redis.id
  
  private_service_connection {
    name                           = "redis-connection"
    private_connection_resource_id = azurerm_redis_cache.main.id
    subresource_names             = ["redisCache"]
    is_manual_connection          = false
  }
  
  tags = local.tags
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
  
  network_acls {
    default_action = "Deny"
    ip_rules       = []
    
    virtual_network_rules {
      subnet_id = azurerm_subnet.aks.id
    }
  }
  
  tags = local.tags
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
    capacity = 100  # Increased capacity for high load
  }
}

# Private Endpoint for OpenAI
resource "azurerm_private_endpoint" "openai" {
  name                = "${local.resource_prefix}-openai-pe"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.openai.id
  
  private_service_connection {
    name                           = "openai-connection"
    private_connection_resource_id = azurerm_cognitive_account.openai.id
    subresource_names             = ["account"]
    is_manual_connection          = false
  }
  
  tags = local.tags
}

# ==================== Container Registry ====================
resource "azurerm_container_registry" "main" {
  name                = "${replace(local.resource_prefix, "-", "")}acr"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  sku                 = "Premium"
  admin_enabled       = false
  
  georeplications {
    location                = "West US"
    zone_redundancy_enabled = true
    tags                    = local.tags
  }
  
  network_rule_set {
    default_action = "Deny"
    
    virtual_network {
      action    = "Allow"
      subnet_id = azurerm_subnet.aks.id
    }
  }
  
  tags = local.tags
}

# Assign AcrPull role to AKS
resource "azurerm_role_assignment" "aks_acr_pull" {
  principal_id                     = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
  role_definition_name             = "AcrPull"
  scope                            = azurerm_container_registry.main.id
  skip_service_principal_aad_check = true
}

# ==================== Key Vault ====================
resource "azurerm_key_vault" "main" {
  name                       = "${local.resource_prefix}-kv-${substr(md5(data.azurerm_resource_group.main.id), 0, 6)}"
  location                   = data.azurerm_resource_group.main.location
  resource_group_name        = data.azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "premium"  # Premium for HSM support
  soft_delete_retention_days = 90
  purge_protection_enabled   = true
  
  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    virtual_network_subnet_ids = [azurerm_subnet.aks.id]
  }
  
  tags = local.tags
}

# Key Vault access policies
resource "azurerm_key_vault_access_policy" "terraform" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id
  
  key_permissions = [
    "Create", "Get", "List", "Update", "Delete", "Purge", "Recover"
  ]
  
  secret_permissions = [
    "Set", "Get", "List", "Delete", "Purge", "Recover"
  ]
  
  certificate_permissions = [
    "Create", "Get", "List", "Update", "Delete", "Purge", "Recover"
  ]
}

resource "azurerm_key_vault_access_policy" "aks" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
  
  secret_permissions = [
    "Get", "List"
  ]
}

# Store secrets in Key Vault
resource "azurerm_key_vault_secret" "redis_connection" {
  name         = "redis-connection-string"
  value        = "${azurerm_redis_cache.main.hostname}:6380,password=${azurerm_redis_cache.main.primary_access_key},ssl=True,abortConnect=False"
  key_vault_id = azurerm_key_vault.main.id
  
  depends_on = [
    azurerm_key_vault_access_policy.terraform
  ]
}

resource "azurerm_key_vault_secret" "openai_key" {
  name         = "openai-api-key"
  value        = azurerm_cognitive_account.openai.primary_access_key
  key_vault_id = azurerm_key_vault.main.id
  
  depends_on = [
    azurerm_key_vault_access_policy.terraform
  ]
}

resource "azurerm_key_vault_secret" "openai_endpoint" {
  name         = "openai-endpoint"
  value        = azurerm_cognitive_account.openai.endpoint
  key_vault_id = azurerm_key_vault.main.id
  
  depends_on = [
    azurerm_key_vault_access_policy.terraform
  ]
}

# ==================== Monitoring ====================
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${local.resource_prefix}-law"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  
  tags = local.tags
}

resource "azurerm_application_insights" "main" {
  name                = "${local.resource_prefix}-appinsights"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  
  tags = local.tags
}

# ==================== API Management (Optional for rate limiting) ====================
resource "azurerm_api_management" "main" {
  name                = "${local.resource_prefix}-apim"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  publisher_name      = "KPMG"
  publisher_email     = "admin@kpmg.com"
  sku_name            = "Premium_1"
  zones               = ["1", "2", "3"]
  
  identity {
    type = "SystemAssigned"
  }
  
  virtual_network_configuration {
    subnet_id = azurerm_subnet.appgw.id
  }
  
  tags = local.tags
}

# ==================== Outputs ====================
output "resource_group_name" {
  value = data.azurerm_resource_group.main.name
}

output "aks_cluster_name" {
  value = azurerm_kubernetes_cluster.main.name
}

output "acr_login_server" {
  value = azurerm_container_registry.main.login_server
}

output "redis_hostname" {
  value     = azurerm_redis_cache.main.hostname
  sensitive = true
}

output "openai_endpoint" {
  value     = azurerm_cognitive_account.openai.endpoint
  sensitive = true
}

output "key_vault_name" {
  value = azurerm_key_vault.main.name
}

output "app_insights_instrumentation_key" {
  value     = azurerm_application_insights.main.instrumentation_key
  sensitive = true
}

output "application_gateway_public_ip" {
  value = azurerm_public_ip.appgw.ip_address
}

output "api_management_gateway_url" {
  value = azurerm_api_management.main.gateway_url
}

output "kube_config" {
  value     = azurerm_kubernetes_cluster.main.kube_config_raw
  sensitive = true
}
