variable "project_id" {
    type = string
}

variable "project_number" {
    type = number
}

variable "image_label" {
    type = string
}

variable "api_key" {
    type = string
}

variable "action_site_key" {
    type = string
}

variable "challenge_page_site_key" {
    type = string
}

variable "session_site_key" {
    type = string
}

locals {
    region         = "us-central1"
}


# Deploy the recaptcha load balancer extension.
module "recaptcha_lb_extension" {
    # The module source. This can be local or github.
    source              = "../terraform"

    # Basic deployment information.
    project_id          = var.project_id
    region              = local.region

    # Identify the type of load balancer we're attaching to. This will likely come from an existing
    # tf resource.
    load_balancing_scheme = "EXTERNAL_MANAGED"

    # Hardcoded for now but in a real tf deployment this would be taken from an output from a terraform resource.
    lb_frontend         = "https://www.googleapis.com/compute/v1/projects/${var.project_number}/regions/us-central1/forwardingRules/hello-fe"

    # The match condition that causes traffic to be forwareded to the waf callout.
    # A reasonable thing to do might be to filter on content type (i.e. only forward when content type is html)
    extension_cel_match = "request.path.startsWith('/callout')"

    # Callout server configs
    edge_container        = "us-central1-docker.pkg.dev/jordan-waf-lb/recaptcha-waf-repo/recaptcha-waf:${var.image_label}"
    callout_config      = {
        project_number          = var.project_number
        api_key                 = var.api_key
        action_site_key         = var.action_site_key
        challenge_page_site_key = var.challenge_page_site_key
        session_site_sey        = var.session_site_key
        
        # This could probably be a list for usability.
        # e.g.
        # session_js_inject_paths = ["*", "/*", ..]
        session_js_install_path  = "/callout/session;/blah2"
        debug                    = true
    }
}