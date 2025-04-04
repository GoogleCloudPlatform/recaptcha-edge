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

variable "edge_container" {
    type = string
}

variable "source_root" {
    type = string
    default = ""
}

variable "callout_config" {
    type = object({
        project_number           = number
        api_key                  = string
        action_site_key          = optional(string, null)
        express_site_key         = optional(string, null)
        challenge_page_site_key  = optional(string, null)
        enterprise_site_key      = optional(string, null)
        recaptcha_endpoint       = optional(string, "https://public-preview-recaptchaenterprise.googleapis.com")
        session_js_install_path  = optional(string, null)
        session_site_sey         = optional(string, null)
        debug                    = optional(bool, false)
    })
}