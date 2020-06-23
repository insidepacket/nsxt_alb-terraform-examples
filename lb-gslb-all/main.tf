# For example, restrict template version in 0.1.x
provider "avi" {
  avi_username = "admin"
  avi_tenant = "admin"
  avi_password = "password"
  avi_controller= var.site1controller
}

provider "avi" {
  avi_username = "admin"
  avi_tenant = "admin"
  alias = "site02"
  avi_password = "password"
  avi_controller= var.site2controller
}

data "avi_tenant" "default_tenant" {
  name = "admin"
}

data "avi_cloud" "default_cloud" {
  name = "Default-Cloud"
}

data "avi_tenant" "site02_default_tenant" {
  provider = avi.site02
  name = "admin"
}

data "avi_cloud" "site02_default_cloud" {
  provider = avi.site02
  name = "Default-Cloud"
}

data "avi_serviceenginegroup" "se_group" {
  name      = "Default-Group"
  cloud_ref = data.avi_cloud.default_cloud.id
}

data "avi_gslb" "gslb_demo" {
  name = "Default"
}

data "avi_virtualservice" "site01_vs01" {
  name = "gslb_site01_vs01"
}

data "avi_virtualservice" "site02_vs01" {
  name = "gslb_site02_vs01"
}

data "avi_applicationprofile" "site01_system_https_profile" {
  name = "System-Secure-HTTP"
}

data "avi_applicationprofile" "site02_system_https_profile" {
  provider = avi.site02
  name = "System-Secure-HTTP"
}

### Start of Site01 setup
resource "avi_sslprofile" "site01_sslprofile" {
    name = "site01_sslprofile"
    ssl_session_timeout = 86400
    tenant_ref = data.avi_tenant.default_tenant.id
    accepted_ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES256-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"
    prefer_client_cipher_ordering = false
    enable_ssl_session_reuse = true
    accepted_versions {
      type = "SSL_VERSION_TLS1_1"
    }
    accepted_versions {
      type = "SSL_VERSION_TLS1_2"
    }
    cipher_enums = [
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"]
    send_close_notify = true
    type = "SSL_PROFILE_TYPE_APPLICATION"
    enable_early_data = false
    ssl_rating {
      compatibility_rating = "SSL_SCORE_EXCELLENT"
      security_score = 100.0
      performance_rating = "SSL_SCORE_EXCELLENT"
    }
  }

resource "avi_applicationpersistenceprofile" "site01_applicationpersistenceprofile" {
  name  = "site01_app-pers-profile"
  tenant_ref = data.avi_tenant.default_tenant.id
  is_federated = false
  persistence_type = "PERSISTENCE_TYPE_HTTP_COOKIE"
  http_cookie_persistence_profile {
    cookie_name = "sddc01-vs01-cookie01"
    always_send_cookie = false
    timeout = 15
  }
}

resource "avi_vsvip" "site01_vs01_vip" {
  name = "site01_vs01_vip"
  tenant_ref = data.avi_tenant.default_tenant.id
  cloud_ref  = data.avi_cloud.default_cloud.id
  vip {
    vip_id = "0"
    ip_address {
      type = "V4"
      addr = var.gslb_site01_vs01_vip
    }
  }
}

resource "avi_sslkeyandcertificate" "site01_cert1000" {
    name = "site01_cert1000"
    tenant_ref = data.avi_tenant.default_tenant.id
    certificate {
        certificate = file("${path.module}/www.sddc.vmconaws.link.crt")
        }
    key = file("${path.module}/www.sddc.vmconaws.link.key")
    type= "SSL_CERTIFICATE_TYPE_VIRTUALSERVICE"
}

resource "avi_virtualservice" "gslb_site01_vs01" {
  name = "gslb_site01_vs01"
  tenant_ref = data.avi_tenant.default_tenant.id
  cloud_ref  = data.avi_cloud.default_cloud.id
  pool_group_ref = avi_poolgroup.site01_pg-1.id
  vsvip_ref  = avi_vsvip.site01_vs01_vip.id
  application_profile_ref = data.avi_applicationprofile.site01_system_https_profile.id
  services {
        port = 443
        enable_ssl = true
        port_range_end = 443
        }
  cloud_type                   = "CLOUD_VCENTER"
  ssl_key_and_certificate_refs = [avi_sslkeyandcertificate.site01_cert1000.id]
  ssl_profile_ref = avi_sslprofile.site01_sslprofile.id
}

resource "avi_healthmonitor" "site01_hm_1" {
  name = "site01_monitor"
  type = "HEALTH_MONITOR_HTTP"
  tenant_ref = data.avi_tenant.default_tenant.id
  receive_timeout = "4"
  is_federated = false
  failed_checks = "3"
  send_interval = "10"
  http_monitor {
        exact_http_request = false
        http_request = "HEAD / HTTP/1.0"
        http_response_code = ["HTTP_2XX","HTTP_3XX","HTTP_4XX"]
        }
  successful_checks = "3"
}

resource "avi_pool" "site01_pool-1" {
  name = "site01_pool-1"
  health_monitor_refs = [avi_healthmonitor.site01_hm_1.id]
  tenant_ref = data.avi_tenant.default_tenant.id
  cloud_ref  = data.avi_cloud.default_cloud.id
  application_persistence_profile_ref = avi_applicationpersistenceprofile.site01_applicationpersistenceprofile.id
  fail_action {
    type = "FAIL_ACTION_CLOSE_CONN"
  }
  lb_algorithm = "LB_ALGORITHM_LEAST_CONNECTIONS"
}

resource "avi_pool" "site01_pool-2" {
  name = "site01_pool-2"
  tenant_ref = data.avi_tenant.default_tenant.id
  cloud_ref = data.avi_cloud.default_cloud.id
  application_persistence_profile_ref = avi_applicationpersistenceprofile.site01_applicationpersistenceprofile.id
  fail_action {
    type = "FAIL_ACTION_CLOSE_CONN"
  }
  ignore_servers = true
}

resource "avi_poolgroup" "site01_pg-1" {
  name = "site01_pg-1"
  tenant_ref = data.avi_tenant.default_tenant.id
  cloud_ref = data.avi_cloud.default_cloud.id
  members {
    pool_ref = avi_pool.site01_pool-1.id
    ratio = 100
    deployment_state = "IN_SERVICE"
  }
  members {
    pool_ref = avi_pool.site01_pool-2.id
    ratio = 0
    deployment_state = "OUT_OF_SERVICE"
  }
}

resource "avi_server" "site01_server_web11" {
  ip       = var.avi_site01_server_web11
  port     = "80"
  pool_ref = avi_pool.site01_pool-1.id
  hostname = "server_web11"
}

resource "avi_server" "site01_server_web12" {
  ip       = var.avi_site01_server_web12
  port     = "80"
  pool_ref = avi_pool.site01_pool-1.id
  hostname = "server_web12"
}

resource "avi_server" "site01_server_web13" {
  ip       = var.avi_site01_server_web13
  port     = "80"
  pool_ref = avi_pool.site01_pool-2.id
  hostname = "server_webv13"
}

resource "avi_server" "site01_server_web14" {
  ip       = var.avi_site01_server_web14
  port     = "80"
  pool_ref = avi_pool.site01_pool-2.id
  hostname = "server_web14"
}

resource "avi_server" "site01_server_web15" {
  ip = var.avi_site01_server_web15
  port = "80"
  pool_ref = avi_pool.site01_pool-2.id
  hostname = "server_web15"
}

### End of Site01 setup ###
### Start of Site02 setup ###
resource "avi_sslprofile" "site02_sslprofile" {
    provider = avi.site02
    name = "site02_sslprofile"
    ssl_session_timeout = 86400
    tenant_ref = data.avi_tenant.default_tenant.id
    accepted_ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES256-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"
    prefer_client_cipher_ordering = false
    enable_ssl_session_reuse = true
    accepted_versions {
      type = "SSL_VERSION_TLS1_1"
    }
    accepted_versions {
      type = "SSL_VERSION_TLS1_2"
    }
    cipher_enums = [
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"]
    send_close_notify = true
    type = "SSL_PROFILE_TYPE_APPLICATION"
    enable_early_data = false
    ssl_rating {
      compatibility_rating = "SSL_SCORE_EXCELLENT"
      security_score = 100.0
      performance_rating = "SSL_SCORE_EXCELLENT"
    }
  }


resource "avi_applicationpersistenceprofile" "site02_applicationpersistenceprofile" {
  provider = avi.site02
  tenant_ref = data.avi_tenant.site02_default_tenant.id
  name  = "site02_app-pers-profile"
  is_federated = false
  persistence_type = "PERSISTENCE_TYPE_HTTP_COOKIE"
  http_cookie_persistence_profile {
    cookie_name = "sddc01-vs01-cookie01"
    always_send_cookie = false
    timeout = 15
  }
}

resource "avi_vsvip" "site02_vs01_vip" {
  provider = avi.site02
  cloud_ref = data.avi_cloud.site02_default_cloud.id
  tenant_ref = data.avi_tenant.site02_default_tenant.id
  name = "site02_vs01_vip"
  vip {
    vip_id = "0"
    ip_address {
      type = "V4"
      addr = var.gslb_site02_vs01_vip
    }
  }
}

resource "avi_sslkeyandcertificate" "site02_cert1000" {
  provider = avi.site02
  tenant_ref = data.avi_tenant.site02_default_tenant.id
  name = "site02_cert1000"
  certificate {
      certificate = file("${path.module}/www.sddc.vmconaws.link.crt")
      }
  key = file("${path.module}/www.sddc.vmconaws.link.key")
  type= "SSL_CERTIFICATE_TYPE_VIRTUALSERVICE"
}

resource "avi_virtualservice" "gslb_site02_vs01" {
  provider = avi.site02
  cloud_ref = data.avi_cloud.site02_default_cloud.id
  tenant_ref = data.avi_tenant.site02_default_tenant.id
  name = "gslb_site02_vs01"
  pool_group_ref = avi_poolgroup.site02_pg-1.id
  vsvip_ref  = avi_vsvip.site02_vs01_vip.id
  application_profile_ref = data.avi_applicationprofile.site02_system_https_profile.id
  services {
        port = 443
        enable_ssl = true
        port_range_end = 443
        }
  cloud_type = "CLOUD_VCENTER"
  ssl_key_and_certificate_refs = [avi_sslkeyandcertificate.site02_cert1000.id]
  ssl_profile_ref = avi_sslprofile.site02_sslprofile.id
}

resource "avi_healthmonitor" "site02_hm_1" {
  provider = avi.site02
  tenant_ref = data.avi_tenant.site02_default_tenant.id
  name = "site02_monitor"
  type  = "HEALTH_MONITOR_HTTP"
  receive_timeout = "4"
  is_federated = false
  failed_checks = "3"
  send_interval = "10"
  http_monitor {
        exact_http_request = false
        http_request = "HEAD / HTTP/1.0"
        http_response_code = ["HTTP_2XX","HTTP_3XX","HTTP_4XX"]
        }
  successful_checks = "3"
}

resource "avi_pool" "site02_pool-1" {
  provider = avi.site02
  cloud_ref = data.avi_cloud.site02_default_cloud.id
  tenant_ref = data.avi_tenant.site02_default_tenant.id
  name = "site02_pool-1"
  health_monitor_refs = [avi_healthmonitor.site02_hm_1.id]
  application_persistence_profile_ref = avi_applicationpersistenceprofile.site02_applicationpersistenceprofile.id
  fail_action {
    type = "FAIL_ACTION_CLOSE_CONN"
  }
  lb_algorithm = "LB_ALGORITHM_LEAST_CONNECTIONS"
}

resource "avi_pool" "site02_pool-2" {
  provider = avi.site02
  cloud_ref = data.avi_cloud.site02_default_cloud.id
  tenant_ref = data.avi_tenant.site02_default_tenant.id
  name = "site02_pool-2"
  application_persistence_profile_ref = avi_applicationpersistenceprofile.site02_applicationpersistenceprofile.id
  fail_action {
    type = "FAIL_ACTION_CLOSE_CONN"
  }
  ignore_servers = true
}

resource "avi_poolgroup" "site02_pg-1" {
  provider = avi.site02
  cloud_ref = data.avi_cloud.site02_default_cloud.id
  tenant_ref = data.avi_tenant.site02_default_tenant.id
  name = "site02_pg-1"
  members {
    pool_ref = avi_pool.site02_pool-1.id
    ratio = 100
    deployment_state = "IN_SERVICE"
  }
  members {
    pool_ref = avi_pool.site02_pool-2.id
    ratio = 0
    deployment_state = "OUT_OF_SERVICE"
  }
}

### avi_server doesn't support tenant_ref and cloud_ref
resource "avi_server" "site02_server_web21" {
  provider = avi.site02
  ip = var.avi_site02_server_web21
  port = "80"
  pool_ref = avi_pool.site02_pool-1.id
  hostname = "serverp_web21"
}

resource "avi_server" "site02_server_web22" {
  provider = avi.site02
  ip = var.avi_site02_server_web22
  port = "80"
  pool_ref = avi_pool.site02_pool-1.id
  hostname = "server_web22"
}


resource "avi_server" "site02_server_web23" {
  provider = avi.site02
  ip = var.avi_site02_server_web23
  port = "80"
  pool_ref = avi_pool.site02_pool-2.id
  hostname = "server_web23"
}

resource "avi_server" "site02_server_web24" {
  provider = avi.site02
  ip = var.avi_site02_server_web24
  port = "80"
  pool_ref = avi_pool.site02_pool-2.id
  hostname = "server_web24"
}

resource "avi_server" "site02_server_web25" {
  provider = avi.site02
  ip = var.avi_site02_server_web25
  port = "80"
  pool_ref = avi_pool.site02_pool-2.id
  hostname = "server_web25"
}

### END of Site02 Setting ###

### Start of GSLB setup ###

# Only one federated PKI Profile is required for one site or DC
resource "avi_pkiprofile" "terraform_gslb_pki" {
    name = "terraform_gslb_pki"
    tenant_ref = data.avi_tenant.default_tenant.id
    crl_check = false
    is_federated = true
    ignore_peer_chain = false
    validate_only_leaf_crl = true
    ca_certs {
      certificate = file("${path.module}/ca-bundle.crt")
    }
}

resource "avi_applicationpersistenceprofile" "terraform_gslbsite_pesistence" {
  name = "terraform_gslbsite_pesistence"
  tenant_ref = data.avi_tenant.default_tenant.id
  is_federated = true
  persistence_type = "PERSISTENCE_TYPE_GSLB_SITE"
  http_cookie_persistence_profile {
    cookie_name = "sddc01-vs01-cookie01"
    always_send_cookie = false
    timeout = 15
  }
}

resource "avi_healthmonitor" "terraform_gslbsite_hm01" {
  name = "terraform_gslbsite_hm01"
  #type = "HEALTH_MONITOR_HTTP"
  type = "HEALTH_MONITOR_PING"
  tenant_ref = data.avi_tenant.default_tenant.id
  #receive_timeout = "4"
  is_federated = true
  #monitor_port = 80
  failed_checks = "3"
  send_interval = "10"
  #http_monitor {
  #      exact_http_request = false
  #      http_request = "HEAD / HTTP/1.0"
  #      http_response_code = ["HTTP_2XX","HTTP_3XX","HTTP_4XX"]
  #     }
  successful_checks = "3"
}

resource "avi_gslbservice" "terraform_gslb-01" {
  name = "terraform_gslb-01"
  tenant_ref = data.avi_tenant.default_tenant.id
  domain_names = [var.gslb_dns]
  depends_on = [
    avi_pkiprofile.terraform_gslb_pki
  ]
  wildcard_match = false
  application_persistence_profile_ref = avi_applicationpersistenceprofile.terraform_gslbsite_pesistence.id
  health_monitor_refs = [avi_healthmonitor.terraform_gslbsite_hm01.id]
  site_persistence_enabled = true
  is_federated = false
  use_edns_client_subnet= true
  enabled = true
  groups { 
      priority = 10
      consistent_hash_mask=31
      consistent_hash_mask6=31
      members {
        ip {
           type = "V4"
           addr = var.gslb_site01_vs01_vip
        }
        vs_uuid = avi_virtualservice.gslb_site01_vs01.uuid
        cluster_uuid = element(data.avi_gslb.gslb_demo.sites.*.cluster_uuid, index(data.avi_gslb.gslb_demo.sites.*.name,var.site01_name))
        ratio = 1
        enabled = true
      }
     members {
        ip {
           type = "V4"
           addr = var.gslb_site02_vs01_vip
        }
        vs_uuid = avi_virtualservice.gslb_site02_vs01.uuid
        cluster_uuid = element(data.avi_gslb.gslb_demo.sites.*.cluster_uuid, index(data.avi_gslb.gslb_demo.sites.*.name,var.site02_name))
        ratio = 1
        enabled = true
      }
      name = "${var.gslb_dns}-pool"
      algorithm = "GSLB_ALGORITHM_ROUND_ROBIN"      
    }
}
### Output ###
output "gslb-site01_site_number" {
  value = "${index(data.avi_gslb.gslb_demo.sites.*.name,var.site01_name)}"
  description = "gslb-site01_site_number"
}

output "gslb-site02_site_number" {
  value = "${index(data.avi_gslb.gslb_demo.sites.*.name,var.site02_name)}"
  description = "gslb-site02_site_number"
}

output "gslb_site01" {
  value = "${element(data.avi_gslb.gslb_demo.sites.*.cluster_uuid,0)}"
  description = "gslb_site01"
}

output "gslb_site02" {
  value = "${element(data.avi_gslb.gslb_demo.sites.*.cluster_uuid,1)}"
  description = "gslb_site02"
}

output "gslb_service" {
  value = avi_gslbservice.terraform_gslb-01.groups
  description = "gslb_service"
}

output "site01_vs01" {
  value = avi_virtualservice.gslb_site01_vs01
  description = "site01_vs01"
}

output "site02_vs01" {
  value = avi_virtualservice.gslb_site02_vs01
  description = "site02_vs01"
}
