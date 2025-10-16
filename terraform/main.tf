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
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }
}

# ==================== Variables ====================
variable "candidate_name" {
  description = "Candidate identifier used for resource naming"
  type        = string
  default     = "7"
}

variable "location" {
  description = "Azure region for resource deployment"
  type        = string
  default     = "East US"
}

variable "environment" {
  description = "Environment name (e.g., production, staging, development)"
  type        = string
  default     = "production"
}

variable "allowed_ip_ranges" {
  description = "List of IP CIDR ranges allowed to access Key Vault"
  type        = list(string)
  default     = ["141.226.88.60/32"]
}

variable "kubernetes_version" {
  description = "Kubernetes version for AKS cluster"
  type        = string
  default     = "1.29"
}

variable "aks_vm_size" {
  description = "VM size for AKS default node pool"
  type        = string
  default     = "Standard_D2s_v3"
}

variable "aks_min_count" {
  description = "Minimum number of nodes in AKS node pool"
  type        = number
  default     = 2
}

variable "aks_max_count" {
  description = "Maximum number of nodes in AKS node pool"
  type        = number
  default     = 5
}

variable "vnet_address_space" {
  description = "Address space for the virtual network"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "aks_subnet_prefix" {
  description = "Address prefix for AKS subnet"
  type        = list(string)
  default     = ["10.0.1.0/24"]
}

variable "redis_subnet_prefix" {
  description = "Address prefix for Redis subnet"
  type        = list(string)
  default     = ["10.0.2.0/24"]
}

variable "pe_subnet_prefix" {
  description = "Address prefix for private endpoints subnet"
  type        = list(string)
  default     = ["10.0.3.0/24"]
}

variable "appgw_subnet_prefix" {
  description = "Address prefix for Application Gateway subnet"
  type        = list(string)
  default     = ["10.0.4.0/24"]
}

variable "aks_service_cidr" {
  description = "CIDR for Kubernetes services"
  type        = string
  default     = "10.2.0.0/16"
}

variable "aks_dns_service_ip" {
  description = "IP address for Kubernetes DNS service"
  type        = string
  default     = "10.2.0.10"
}

variable "redis_capacity" {
  description = "Redis cache capacity (1, 2, 3, 4)"
  type        = number
  default     = 1
}

variable "redis_family" {
  description = "Redis cache family (C for Basic/Standard, P for Premium)"
  type        = string
  default     = "P"
}

variable "redis_sku_name" {
  description = "Redis cache SKU name (Basic, Standard, Premium)"
  type        = string
  default     = "Premium"
}

variable "log_retention_days" {
  description = "Number of days to retain logs in Log Analytics"
  type        = number
  default     = 30
}

variable "openai_model_name" {
  description = "OpenAI model name to deploy"
  type        = string
  default     = "gpt-4o-mini"
}

variable "openai_model_version" {
  description = "OpenAI model version"
  type        = string
  default     = "2024-07-18"
}

variable "openai_capacity" {
  description = "OpenAI deployment capacity (TPM in thousands)"
  type        = number
  default     = 10
}

# ==================== Locals ====================
locals {
  resource_prefix     = "chatbot-${var.candidate_name}"
  resource_group_name = "platform_candidate_${var.candidate_name}"
  
  common_tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
    Project     = "Chatbot"
    Owner       = var.candidate_name
  }
}

# ==================== Resource Group ====================
data "azurerm_resource_group" "main" {
  name = local.resource_group_name
}

# ==================== Log Analytics ====================
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${local.resource_prefix}-logs"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = local.common_tags
}

# ==================== Networking ====================
resource "azurerm_virtual_network" "main" {
  name                = "${local.resource_prefix}-vnet"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  address_space       = var.vnet_address_space

  tags = local.common_tags

  lifecycle {
    ignore_changes = [subnet, tags]
  }
}

resource "azurerm_subnet" "aks" {
  name                 = "aks-subnet"
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = var.aks_subnet_prefix
  
  service_endpoints = ["Microsoft.KeyVault", "Microsoft.CognitiveServices"]

  lifecycle {
    ignore_changes = [delegation, service_endpoints]
  }
}

resource "azurerm_subnet" "redis" {
  name                 = "redis-subnet"
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = var.redis_subnet_prefix

  lifecycle {
    ignore_changes = [delegation]
  }
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "private-endpoints-subnet"
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = var.pe_subnet_prefix

  lifecycle {
    ignore_changes = [delegation]
  }
}

resource "azurerm_subnet" "appgw" {
  name                 = "appgw-subnet"
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = var.appgw_subnet_prefix

  lifecycle {
    ignore_changes = [delegation]
  }
}

resource "azurerm_network_security_group" "aks" {
  name                = "${local.resource_prefix}-aks-nsg"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name

  tags = local.common_tags

  lifecycle {
    ignore_changes = [tags]
  }
}

# NSG Rules for AKS
resource "azurerm_network_security_rule" "aks_inbound_https" {
  name                        = "AllowHTTPS"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = data.azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.aks.name
}

resource "azurerm_network_security_rule" "aks_inbound_http" {
  name                        = "AllowHTTP"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "80"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = data.azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.aks.name
}

resource "azurerm_network_security_rule" "aks_outbound_https" {
  name                        = "AllowHTTPSOutbound"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "10.0.1.0/24"
  destination_address_prefix  = "Internet"
  resource_group_name         = data.azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.aks.name
}

resource "azurerm_network_security_rule" "aks_outbound_dns" {
  name                        = "AllowDNSOutbound"
  priority                    = 110
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_range      = "53"
  source_address_prefix       = "10.0.1.0/24"
  destination_address_prefix  = "Internet"
  resource_group_name         = data.azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.aks.name
}

resource "azurerm_network_security_rule" "aks_outbound_ntp" {
  name                        = "AllowNTPOutbound"
  priority                    = 120
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_range      = "123"
  source_address_prefix       = "10.0.1.0/24"
  destination_address_prefix  = "Internet"
  resource_group_name         = data.azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.aks.name
}

resource "azurerm_subnet_network_security_group_association" "aks" {
  subnet_id                 = azurerm_subnet.aks.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

# ==================== Application Gateway ====================
resource "azurerm_public_ip" "appgw" {
  name                = "${local.resource_prefix}-appgw-pip"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]

  tags = local.common_tags
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

  tags = local.common_tags
}

resource "azurerm_user_assigned_identity" "appgw" {
  name                = "${local.resource_prefix}-appgw-identity"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name

  tags = local.common_tags
}

resource "azurerm_application_gateway" "main" {
  name                = "${local.resource_prefix}-appgw"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  enable_http2        = true
  zones               = ["1", "2", "3"]
  firewall_policy_id  = azurerm_web_application_firewall_policy.main.id

  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.appgw.id]
  }

  gateway_ip_configuration {
    name      = "appgw-ip-config"
    subnet_id = azurerm_subnet.appgw.id
  }

  frontend_port {
    name = "frontend-port-80"
    port = 80
  }

  frontend_port {
    name = "frontend-port-443"
    port = 443
  }

  frontend_ip_configuration {
    name                 = "frontend-ip-config"
    public_ip_address_id = azurerm_public_ip.appgw.id
  }

  backend_address_pool {
    name = "aks-backend-pool"
  }

  backend_http_settings {
    name                  = "backend-http-settings"
    cookie_based_affinity = "Disabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 60
    probe_name            = "health-probe"
  }

  http_listener {
    name                           = "http-listener"
    frontend_ip_configuration_name = "frontend-ip-config"
    frontend_port_name             = "frontend-port-80"
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = "routing-rule-http"
    rule_type                  = "Basic"
    http_listener_name         = "http-listener"
    backend_address_pool_name  = "aks-backend-pool"
    backend_http_settings_name = "backend-http-settings"
    priority                   = 100
  }

  probe {
    name                                      = "health-probe"
    protocol                                  = "Http"
    path                                      = "/health"
    interval                                  = 30
    timeout                                   = 30
    unhealthy_threshold                       = 3
    pick_host_name_from_backend_http_settings = false
    host                                      = "127.0.0.1"
    
    match {
      status_code = ["200-399"]
    }
  }

  tags = local.common_tags

  lifecycle {
    ignore_changes = [
      backend_address_pool,
      backend_http_settings,
      http_listener,
      probe,
      request_routing_rule,
      tags
    ]
  }

  depends_on = [
    azurerm_public_ip.appgw,
    azurerm_subnet.appgw
  ]
}

resource "azurerm_monitor_diagnostic_setting" "appgw" {
  name                       = "${local.resource_prefix}-appgw-diag"
  target_resource_id         = azurerm_application_gateway.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "ApplicationGatewayAccessLog"
  }

  enabled_log {
    category = "ApplicationGatewayPerformanceLog"
  }

  enabled_log {
    category = "ApplicationGatewayFirewallLog"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

# ==================== AKS ====================
resource "azurerm_kubernetes_cluster" "main" {
  name                = "${local.resource_prefix}-aks"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  dns_prefix          = "${local.resource_prefix}-aks"
  
  kubernetes_version        = var.kubernetes_version
  automatic_upgrade_channel = "patch"
  sku_tier                  = "Standard"

  default_node_pool {
    name                 = "default"
    vm_size              = var.aks_vm_size
    vnet_subnet_id       = azurerm_subnet.aks.id
    auto_scaling_enabled = true
    min_count            = var.aks_min_count
    max_count            = var.aks_max_count
    zones                = ["1", "2", "3"]
    
    upgrade_settings {
      max_surge = "33%"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin     = "azure"
    network_policy     = "azure"
    load_balancer_sku  = "standard"
    service_cidr       = var.aks_service_cidr
    dns_service_ip     = var.aks_dns_service_ip
    outbound_type      = "loadBalancer"
  }

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }

  azure_policy_enabled = true

  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2h"
  }

  ingress_application_gateway {
    gateway_id = azurerm_application_gateway.main.id
  }

  tags = local.common_tags

  lifecycle {
    ignore_changes = [
      default_node_pool[0].node_count,
      tags,
      kubernetes_version
    ]
  }

  depends_on = [
    azurerm_application_gateway.main
  ]
}

resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                       = "${local.resource_prefix}-aks-diag"
  target_resource_id         = azurerm_kubernetes_cluster.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "kube-apiserver"
  }

  enabled_log {
    category = "kube-controller-manager"
  }

  enabled_log {
    category = "kube-scheduler"
  }

  enabled_log {
    category = "kube-audit"
  }

  enabled_log {
    category = "cluster-autoscaler"
  }

  enabled_log {
    category = "guard"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

# ==================== Redis Cache ====================
resource "azurerm_redis_cache" "main" {
  name                = "${local.resource_prefix}-redis"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  capacity            = var.redis_capacity
  family              = var.redis_family
  sku_name            = var.redis_sku_name
  
  zones                         = ["1", "2", "3"]
  subnet_id                     = azurerm_subnet.redis.id
  public_network_access_enabled = false
  
  non_ssl_port_enabled = false
  minimum_tls_version  = "1.2"

  redis_configuration {
    maxmemory_policy = "allkeys-lru"
  }

  tags = local.common_tags

  lifecycle {
    ignore_changes = [redis_configuration, tags, zones]
  }
}

resource "azurerm_monitor_diagnostic_setting" "redis" {
  name                       = "${local.resource_prefix}-redis-diag"
  target_resource_id         = azurerm_redis_cache.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "ConnectedClientList"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

# ==================== Azure OpenAI ====================
resource "azurerm_cognitive_account" "openai" {
  name                          = "${local.resource_prefix}-openai"
  location                      = data.azurerm_resource_group.main.location
  resource_group_name           = data.azurerm_resource_group.main.name
  kind                          = "OpenAI"
  sku_name                      = "S0"
  custom_subdomain_name         = "${local.resource_prefix}-openai"
  public_network_access_enabled = false

  identity {
    type = "SystemAssigned"
  }

  network_acls {
    default_action = "Deny"
    virtual_network_rules {
      subnet_id = azurerm_subnet.aks.id
    }
  }

  tags = local.common_tags

  lifecycle {
    ignore_changes = [tags]
  }
}

resource "azurerm_cognitive_deployment" "gpt4" {
  name                 = var.openai_model_name
  cognitive_account_id = azurerm_cognitive_account.openai.id

  model {
    format  = "OpenAI"
    name    = var.openai_model_name
    version = var.openai_model_version
  }

  sku {
    name     = "Standard"
    capacity = var.openai_capacity
  }

  lifecycle {
    ignore_changes = [model, sku]
  }
}

resource "azurerm_monitor_diagnostic_setting" "openai" {
  name                       = "${local.resource_prefix}-openai-diag"
  target_resource_id         = azurerm_cognitive_account.openai.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "Audit"
  }

  enabled_log {
    category = "RequestResponse"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

# ==================== Private Endpoint for OpenAI ====================
resource "azurerm_private_endpoint" "openai" {
  name                = "${local.resource_prefix}-openai-pe"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "${local.resource_prefix}-openai-psc"
    private_connection_resource_id = azurerm_cognitive_account.openai.id
    is_manual_connection           = false
    subresource_names              = ["account"]
  }

  tags = local.common_tags
}

resource "azurerm_private_dns_zone" "openai" {
  name                = "privatelink.openai.azure.com"
  resource_group_name = data.azurerm_resource_group.main.name

  tags = local.common_tags

  lifecycle {
    ignore_changes = [tags]
  }
}

resource "azurerm_private_dns_zone_virtual_network_link" "openai" {
  name                  = "${local.resource_prefix}-openai-dns-link"
  resource_group_name   = data.azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.openai.name
  virtual_network_id    = azurerm_virtual_network.main.id

  tags = local.common_tags
}

resource "azurerm_private_dns_a_record" "openai" {
  name                = azurerm_cognitive_account.openai.name
  zone_name           = azurerm_private_dns_zone.openai.name
  resource_group_name = data.azurerm_resource_group.main.name
  ttl                 = 300
  records             = [azurerm_private_endpoint.openai.private_service_connection[0].private_ip_address]

  tags = local.common_tags
}

# ==================== Key Vault ====================
data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                       = "${local.resource_prefix}-kv-${substr(md5(data.azurerm_resource_group.main.id), 0, 6)}"
  location                   = data.azurerm_resource_group.main.location
  resource_group_name        = data.azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 90
  purge_protection_enabled   = true
  
  rbac_authorization_enabled = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.allowed_ip_ranges
    virtual_network_subnet_ids = [
      azurerm_subnet.aks.id
    ]
  }

  tags = local.common_tags

  lifecycle {
    ignore_changes = [soft_delete_retention_days, purge_protection_enabled, tags]
  }
}

resource "azurerm_key_vault_access_policy" "deployer" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions = [
    "Get",
    "List",
    "Set",
    "Delete",
    "Recover",
    "Backup",
    "Restore",
    "Purge"
  ]

  key_permissions = [
    "Get",
    "List",
    "Create",
    "Delete",
    "Recover",
    "Backup",
    "Restore",
    "Purge"
  ]

  certificate_permissions = [
    "Get",
    "List",
    "Create",
    "Delete",
    "Recover",
    "Backup",
    "Restore",
    "Purge"
  ]
}

resource "azurerm_key_vault_access_policy" "aks" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id

  secret_permissions = [
    "Get",
    "List"
  ]
}

resource "azurerm_key_vault_access_policy" "aks_secrets_provider" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_kubernetes_cluster.main.key_vault_secrets_provider[0].secret_identity[0].object_id

  secret_permissions = [
    "Get",
    "List"
  ]
}

resource "azurerm_key_vault_secret" "redis_password" {
  name         = "redis-password"
  value        = azurerm_redis_cache.main.primary_access_key
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [
    azurerm_key_vault_access_policy.deployer
  ]
}

resource "azurerm_key_vault_secret" "redis_connection_string" {
  name         = "redis-connection-string"
  value        = "${azurerm_redis_cache.main.hostname}:${azurerm_redis_cache.main.ssl_port},password=${azurerm_redis_cache.main.primary_access_key},ssl=True,abortConnect=False"
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [
    azurerm_key_vault_access_policy.deployer
  ]
}

resource "azurerm_key_vault_secret" "openai_endpoint" {
  name         = "openai-endpoint"
  value        = azurerm_cognitive_account.openai.endpoint
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [
    azurerm_key_vault_access_policy.deployer
  ]
}

resource "azurerm_key_vault_secret" "openai_key" {
  name         = "openai-api-key"
  value        = azurerm_cognitive_account.openai.primary_access_key
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [
    azurerm_key_vault_access_policy.deployer
  ]
}

resource "azurerm_monitor_diagnostic_setting" "keyvault" {
  name                       = "${local.resource_prefix}-kv-diag"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "AuditEvent"
  }

  enabled_log {
    category = "AzurePolicyEvaluationDetails"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

# ==================== Monitoring Alerts ====================
resource "azurerm_monitor_action_group" "main" {
  name                = "${local.resource_prefix}-action-group"
  resource_group_name = data.azurerm_resource_group.main.name
  short_name          = "chatbot"

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "aks_cpu" {
  name                = "${local.resource_prefix}-aks-cpu-alert"
  resource_group_name = data.azurerm_resource_group.main.name
  scopes              = [azurerm_kubernetes_cluster.main.id]
  description         = "Alert when AKS CPU usage exceeds 80%"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"

  criteria {
    metric_namespace = "Microsoft.ContainerService/managedClusters"
    metric_name      = "node_cpu_usage_percentage"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 80
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "aks_memory" {
  name                = "${local.resource_prefix}-aks-memory-alert"
  resource_group_name = data.azurerm_resource_group.main.name
  scopes              = [azurerm_kubernetes_cluster.main.id]
  description         = "Alert when AKS memory usage exceeds 85%"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"

  criteria {
    metric_namespace = "Microsoft.ContainerService/managedClusters"
    metric_name      = "node_memory_working_set_percentage"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 85
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "redis_cpu" {
  name                = "${local.resource_prefix}-redis-cpu-alert"
  resource_group_name = data.azurerm_resource_group.main.name
  scopes              = [azurerm_redis_cache.main.id]
  description         = "Alert when Redis CPU usage exceeds 80%"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"

  criteria {
    metric_namespace = "Microsoft.Cache/redis"
    metric_name      = "percentProcessorTime"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 80
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "redis_memory" {
  name                = "${local.resource_prefix}-redis-memory-alert"
  resource_group_name = data.azurerm_resource_group.main.name
  scopes              = [azurerm_redis_cache.main.id]
  description         = "Alert when Redis memory usage exceeds 90%"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"

  criteria {
    metric_namespace = "Microsoft.Cache/redis"
    metric_name      = "usedmemorypercentage"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 90
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "openai_throttling" {
  name                = "${local.resource_prefix}-openai-throttling-alert"
  resource_group_name = data.azurerm_resource_group.main.name
  scopes              = [azurerm_cognitive_account.openai.id]
  description         = "Alert when OpenAI requests are being throttled"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"

  criteria {
    metric_namespace = "Microsoft.CognitiveServices/accounts"
    metric_name      = "TokenTransaction"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 1000000
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id
  }

  tags = local.common_tags
}

# ==================== Outputs ====================
output "resource_group_name" {
  value       = data.azurerm_resource_group.main.name
  description = "Name of the resource group"
}

output "aks_cluster_name" {
  value       = azurerm_kubernetes_cluster.main.name
  description = "Name of the AKS cluster"
}

output "aks_cluster_fqdn" {
  value       = azurerm_kubernetes_cluster.main.fqdn
  description = "FQDN of the AKS cluster"
}

output "redis_hostname" {
  value       = azurerm_redis_cache.main.hostname
  description = "Redis cache hostname"
  sensitive   = true
}

output "redis_ssl_port" {
  value       = azurerm_redis_cache.main.ssl_port
  description = "Redis cache SSL port"
}

output "openai_endpoint" {
  value       = azurerm_cognitive_account.openai.endpoint
  description = "Azure OpenAI endpoint"
  sensitive   = true
}

output "openai_deployment_name" {
  value       = azurerm_cognitive_deployment.gpt4.name
  description = "Azure OpenAI deployment name"
}

output "key_vault_name" {
  value       = azurerm_key_vault.main.name
  description = "Name of the Key Vault"
}

output "key_vault_uri" {
  value       = azurerm_key_vault.main.vault_uri
  description = "URI of the Key Vault"
}

output "log_analytics_workspace_id" {
  value       = azurerm_log_analytics_workspace.main.id
  description = "Log Analytics workspace ID"
}

output "log_analytics_workspace_name" {
  value       = azurerm_log_analytics_workspace.main.name
  description = "Log Analytics workspace name"
}

output "vnet_id" {
  value       = azurerm_virtual_network.main.id
  description = "Virtual Network ID"
}

output "aks_subnet_id" {
  value       = azurerm_subnet.aks.id
  description = "AKS subnet ID"
}

output "kube_config" {
  value       = azurerm_kubernetes_cluster.main.kube_config_raw
  sensitive   = true
  description = "Kubernetes config for AKS cluster"
}

output "aks_identity_principal_id" {
  value       = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
  description = "AKS managed identity principal ID"
}

output "aks_secrets_provider_identity" {
  value       = azurerm_kubernetes_cluster.main.key_vault_secrets_provider[0].secret_identity[0].object_id
  description = "AKS Key Vault Secrets Provider identity"
}

output "appgw_public_ip" {
  value       = azurerm_public_ip.appgw.ip_address
  description = "Application Gateway public IP address"
}

output "appgw_name" {
  value       = azurerm_application_gateway.main.name
  description = "Application Gateway name"
}

output "waf_policy_id" {
  value       = azurerm_web_application_firewall_policy.main.id
  description = "WAF Policy ID"
}