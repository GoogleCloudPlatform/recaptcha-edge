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
 
provider "google" {
    project = var.project_id
}

provider "google-beta" {
    project = var.project_id
}

data "google_iam_policy" "noauth" {
  binding {
    role = "roles/run.invoker"
    members = [
      "allUsers",
    ]
  }
}

resource "google_cloud_run_service" "edge" {
  name     = "recaptcha-edge"
  location = var.region

  template {
    spec {
      containers {
        image = var.edge_container
        env {
          name  = "PROJECT_NUMBER"
          value = var.callout_config.project_number
        }
        env {
          name  = "API_KEY"
          value = var.callout_config.api_key
        }
        env {
          name  = "ACTION_SITE_KEY"
          value = var.callout_config.action_site_key
        }
        env {
          name  = "EXPRESS_SITE_KEY"
          value = var.callout_config.express_site_key
        }
        env {
          name  = "SESSION_SITE_KEY"
          value = var.callout_config.session_site_sey
        }
        env {
          name  = "CHALLENGE_PAGE_SITE_KEY"
          value = var.callout_config.challenge_page_site_key
        }
        env {
          name  = "ENTERPRISE_SITE_KEY"
          value = var.callout_config.enterprise_site_key
        }
        env {
          name  = "RECAPTCHA_ENDPOINT"
          value = var.callout_config.recaptcha_endpoint
        }
        env {
          name  = "SESSION_JS_INSTALL_PATH"
          value = var.callout_config.session_js_install_path
        }
        env {
          name  = "DEBUG"
          value = var.callout_config.debug
        }
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }
}

resource "google_cloud_run_service_iam_policy" "noauth" {
  location    = google_cloud_run_service.edge.location
  project     = google_cloud_run_service.edge.project
  service     = google_cloud_run_service.edge.name

  policy_data = data.google_iam_policy.noauth.policy_data
}

resource "google_compute_region_network_endpoint_group" "serverless_neg" {
  provider              = google-beta
  name                  = "serverless-neg"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  cloud_run {
    service = google_cloud_run_service.edge.name
  }
}

resource "google_compute_region_backend_service" "callouts_backend" {
  name                  = "l7-recaptcha-callouts-backend"
  region                = var.region
  load_balancing_scheme = var.load_balancing_scheme
  port_name             = null

  backend {
    group           = google_compute_region_network_endpoint_group.serverless_neg.id
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }
}

resource "google_network_services_lb_traffic_extension" "default" {
  name        = "recaptcha-traffic-ext"
  description = "Implements reCAPTCHA Edge Compute capabilities"
  location    = var.region

  load_balancing_scheme = var.load_balancing_scheme
  forwarding_rules      = [var.lb_frontend]

  extension_chains {
      name = "chain1"

      match_condition {
          cel_expression = var.extension_cel_match
      }

      extensions {
          name      = "recaptcha-edge"
          authority = "recaptcha-edge"
          service   = google_compute_region_backend_service.callouts_backend.self_link
          timeout   = "0.5s"
          fail_open = true

          supported_events = ["REQUEST_HEADERS", "REQUEST_BODY", "RESPONSE_HEADERS", "RESPONSE_BODY"]
      }
  }

  labels = {
  }
}