# reCAPTCHA Google Cloud Load Balancing Callouts Library

A library to access reCAPTCHA Enterprise via [Google Cloud Load Balancing Callouts](https://cloud.google.com/service-extensions/docs/callouts-overview).

## Usage
This project is a full implementation of an [Envoy External Processing server](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto) for use with Google Cloud Load Balancing callouts and reCAPTCHA.

### Building and hosting a container image
Callouts supports serveral backend service types and typical service deployment will rely on building and hosting a container image. For this purpose, this respository contains the following files:
- [xlb.Dockerfile](../../xlb.Dockerfile)
- [xlb.cloudbuild.yaml](../../xlb.cloudbuild.yaml)

Deploying a container image to the Google Cloud Artifact Registry may be done with the following command from the repository root:

```
gcloud builds submit --region={region} --config xlb.cloudbuild.yaml
```

Running this command will, by default, create an image in this location: `{region}-docker.pkg.dev/{my-project}/recaptcha-waf-repo/recaptcha-waf:latest`

### Manually deploying to Google Cloud Load Balancer
Your load balancer can be configured with the reCAPTCHA External Processing server image by following the [Callouts documentation](https://cloud.google.com/service-extensions/docs/configure-callout-backend-service).

### Deploying to Google Cloud Load Balancer with Terraform
Terraform may also be used to deploy the cloud resources requried to configure the load balancer callout. A simple [terraform module](./terraform/) which deploys the Callout backend on Cloud Run and configures the Load Balancer has been provided for this purpose.

<b>Usage Example:</b>
```
module "recaptcha_lb_extension" {
    # The module source. This can be local or github.
    source              = "path/to/terraform/module"

    # Basic deployment information.
    project_id          = "my-project-id"
    region              = "us-central1"

    # Identify the type of load balancer we're attaching to.
    load_balancing_scheme = "EXTERNAL_MANAGED"

    # Identify the load balancer front end
    lb_frontend         = "https://www.googleapis.com/compute/v1/projects/my-project-id/regions/us-central1/forwardingRules/my-lb-frontend"

    # The match condition that causes traffic to be forwareded to the recaptcha edge callout.
    extension_cel_match = "request.path.startsWith('/callout')"

    # Callout server configs
    edge_container        = "us-central1-docker.pkg.dev/my-project-id/recaptcha-waf-repo/recaptcha-waf:label"

    callout_config      = {
        project_number          = 123456789
        api_key                 = "my-api-key"
        action_site_key         = "my-action-site-key"
        challenge_page_site_key = "my-challenge-site-key"
        session_site_sey        = "my-session-site-key"

        session_js_install_path  = "/callout/session;/blah2"
        debug                    = true
    }
}
```

### Callout server configuration
The callout server needs several pieces of information in order to interact with the reCAPTCHA. These are configured via environment variables (ex. [Cloud Run](https://cloud.google.com/run/docs/configuring/services/environment-variables.)) and convieniently in the terraform module noted above.

- `API_KEY`: The Google Cloud API key you created for authentication.
- `PROJECT_NUMBER`: Your Google Cloud project number.
- `EXPRESS_SITE_KEY`: The express key if you are using reCAPTCHA express.
- `SESSION_SITE_KEY`: The session-token key if you are using reCAPTCHA session-token.
- `ACTION_SITE_KEY`: The action-token key if you are using reCAPTCHA action-token.
- `CHALLENGE_SITE_KEY`: The challenge-page key if you are using reCAPTCHA challenge page.
- `SESSION_JS_INSTALL_PATH`: URLs of the pages where you want the Callouts server to install the reCAPTCHA JavaScript using the session-token key. Specify the paths as a glob pattern and use ; as the delimiter. This option is available only for reCAPTCHA session-token. Note that Javascript injection cannot be injected on pages larger than 128KB (see [docs](https://cloud.google.com/service-extensions/docs/callouts-overview)).

## Contribution

Please see our [Contribution](https://github.com/GoogleCloudPlatform/recaptcha-edge/blob/main/CONTRIBUTING.md) guidelines.

## Issues and Support

For technical issues, please see the [reCAPTCHA Enterprise Support Documentation](https://cloud.google.com/recaptcha/docs/getting-support).

For bugs or issues specifically with this codebase, please open a new [Github issue](https://github.com/GoogleCloudPlatform/recaptcha-edge/issues) in this project.
