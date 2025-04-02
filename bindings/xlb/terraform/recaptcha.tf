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

resource "google_cloud_run_service" "waf" {
  name     = "recaptcha-waf"
  location = var.region

  template {
    spec {
      containers {
        image = var.waf_container
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
          name  = "SESSION_JS_INJECT_PATH"
          value = var.callout_config.session_js_inject_path
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
  location    = google_cloud_run_service.waf.location
  project     = google_cloud_run_service.waf.project
  service     = google_cloud_run_service.waf.name

  policy_data = data.google_iam_policy.noauth.policy_data
}

resource "google_compute_region_network_endpoint_group" "serverless_neg" {
  provider              = google-beta
  name                  = "serverless-neg"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  cloud_run {
    service = google_cloud_run_service.waf.name
  }
}

resource "google_compute_region_backend_service" "callouts_backend" {
  name                  = "l7-ilb-callouts-backend"
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
          name      = "recaptcha-waf"
          authority = "recaptcha-waf"
          service   = google_compute_region_backend_service.callouts_backend.self_link
          timeout   = "0.5s"
          fail_open = true

          supported_events = ["REQUEST_HEADERS", "REQUEST_BODY", "RESPONSE_HEADERS", "RESPONSE_BODY"]
      }
  }

  labels = {
  }
}