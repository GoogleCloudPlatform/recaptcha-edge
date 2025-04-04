/**
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
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
        action_site_key          = optional(string)
        express_site_key         = optional(string)
        challenge_page_site_key  = optional(string)
        enterprise_site_key      = optional(string)
        recaptcha_endpoint       = optional(string, "https://public-preview-recaptchaenterprise.googleapis.com")
        session_js_install_path  = optional(string)
        session_site_sey         = optional(string)
        debug                    = optional(bool, false)
    })
}