variable "avi_password" {
  type    = string
  default = "admin"
}

variable "site1controller" {
  type    = string
  default = "10.1.1.250"
}

variable "site2controller" {
  type    = string
  default = "10.1.1.170"
}

variable "site01_name" {
  type = string
  default = "gslb-site01"
}

variable "site02_name" {
  type = string
  default = "gslb-site02"
}

variable "gslb_site01_vs01_vip" {
  type = string
  default = "10.1.1.247"
}

variable "gslb_site02_vs01_vip" {
  type = string
  default = "10.1.1.176"
}

variable "gslb_dns" {
  type = string
  default = "www.sddc.vmconaws.link"
}

variable "gslb_site1_vs01_name" {
  type = string
  default = "gslb_site01_vs01"
}

variable "gslb_site02_vs01_name" {
  type = string
  default = "gslb_site02_vs01"
}

variable "avi_site01_server_web11" {
  type = string
  default = "192.168.101.10"
}

variable "avi_site01_server_web12" {
  type = string
  default = "192.168.101.20"
}

variable "avi_site01_server_web13" {
  type = string
  default = "192.168.101.30"
}

variable "avi_site01_server_web14" {
  type = string
  default = "192.168.101.40"
}

variable "avi_site01_server_web15" {
  type = string
  default = "192.168.101.50"
}

variable "avi_site02_server_web21" {
  type = string
  default = "192.168.202.10"
}

variable "avi_site02_server_web22" {
  type = string
  default = "192.168.202.20"
}

variable "avi_site02_server_web23" {
  type = string
  default = "192.168.202.30"
}

variable "avi_site02_server_web24" {
  type = string
  default = "192.168.202.40"
}

variable "avi_site02_server_web25" {
  type = string
  default = "192.168.202.50"
}

