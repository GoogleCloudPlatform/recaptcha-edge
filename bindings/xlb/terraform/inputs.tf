variable "project_id" {
  type = string
}

variable "region" {
    type = string
}

variable "lb_frontend" {
    type = string
}

variable "load_balancing_scheme" {
    type = string
}

variable "extension_cel_match" {
    type = string
}

variable "waf_container" {
    type = string
}

variable "source_root" {
    type = string
    default = ""
}

variable "callout_config" {
    type = object({
        project_number          = number
        api_key                 = string
        action_site_key         = optional(string, "")
        express_site_key        = optional(string, "")
        challenge_page_site_key = optional(string, "")
        enterprise_site_key     = optional(string, "")
        recaptcha_endpoint      = optional(string, "https://public-preview-recaptchaenterprise.googleapis.com")
        session_js_inject_path  = optional(string, "")
        session_site_sey        = optional(string, "")
    })
}