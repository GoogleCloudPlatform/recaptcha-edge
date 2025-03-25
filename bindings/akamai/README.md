❗ Please contact [reCAPTCHA sales](https://cloud.google.com/contact/form?e=0) if you wish to use our Akamai integration.

# reCAPTCHA Akamai Edge Worker Library

[![Build and Test Akamai Binding](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_akamai.yml/badge.svg)](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_akamai.yml)

A library to access reCAPTCHA Enterprise via [Akamai Edge Workers](https://techdocs.akamai.com/edgeworkers/docs/welcome-to-edgeworkers).

## Usage
This project is intended to be used in one of two ways:

1. Using a prebuilt package uploaded to your Akamai project.
2. or imported as an NPM package for advanced use-cases.

### Prebuilt Package

Check the [Releases](https://github.com/GoogleCloudPlatform/recaptcha-edge/releases) page for the most recent build for Akamai.

This package is intended to be used in concert with [reCAPTCHA Firewall Policies](https://cloud.google.com/recaptcha/docs/firewall-policies-overview).

Each Firewall Policy rule has a path, a condition and a set of actions. 
* Paths are written as [glob](https://man7.org/linux/man-pages/man7/glob.7.html) patterns matching an incoming request.
  * Examples: "/login.html", "/pages/\*.php", "/static/\*\*/\*"
* Conditions are written using [CEL expression language](https://cel.dev/) with variables populated from the incoming Request and reCAPTCHA evaluation.
  * Examples: "recaptcha.score >= 0.7", "!recaptcha.token.valid", "http.ip.startsWith("192.168.0")"
* Actions may be Allow, Block, Show a reCAPTCHA Challenge Page, Substitute a different page, Set a Request Header on the Request to the origin backend.

The following actions are valid:

* For an 'Allow' action, the request will continue to the origin backend.
  * This is used for normal traffic. 
* For a 'Block' action, a 403 will be returned to the user. The origin is never called.
  * This may be used to block expected bot traffic. 
* For a 'Redirect' action, a synthetic page with a reCAPTCHA challenge will be returned. The origin is never called.
  * This may be used to add friction to expected bot traffic, or gain further confidence in human traffic.
* For a 'SetHeader' action, a request header will be added to the origin request. This can be used to communicate information to the backend or trigger application specific protections.

The policy logic to decide the action to take is approximately as demonstrated below:
```python
def decideActions(request, policies):
  for policy in policies:
    if policy.path.matches(request.path) and
       policy.condition.evaluateOn(request) == True:
      return policy.actions
  return [new AllowAction()]
```

When deployed as a Akamai Edge Worker, this package will cache a list of your configured Firewall Policies. When an incoming request is received, first the requested path
will be checked against the list of all policies. 

If no policy paths match, reCAPTCHA will be bypassed and the request will be forwarded to the origin (the Allow action). 

If any policy paths match the incoming request,
the reCAPTCHA CreateAssessment API will be called. reCAPTCHA will evaluate the policies as per the above logic and a list of actions will be returned to the Edge worker. The Edge worker
will execute the actions.


To integrate this package with an existing Akamai account:
* Create the appropriate reCAPTCHA Site Keys in [Google Cloud reCAPTCHA Console](https://console.cloud.google.com/security/recaptcha).
* Upload the package to Akamai with the [`akamai ew upload`](https://techdocs.akamai.com/edgeworkers/docs/deploy-hello-world-3) CLI command or in the '[Edge Workers](https://control.akamai.com/apps/edgeworkers)' section of the Akamai Control Center.
  * If using the Akamai CLI, please configure the relevant site keys and variables in `wrangler.toml` before deploying.
  * Create an Akamai "Property" for your site. Configure the relevant site keys as property variables and create a rule to forward traffic to the new Edge Worker.
* Create a set of Firewall Policies to protect sensative pages or actions.
* Activate the Edge Worker with the `akamai ew activate` command or in the Edge Workers page of the Akamai Control Center.
* Activate the Akamai "Property" in the Akamai Control Center UI.

Please see the [reCAPTCHA Google Cloud Documentation](https://cloud.google.com/recaptcha/docs) for more details on each step.

### As a Library
This package has not yet been added to the NPM package repository, and must be manually imported.

## Contribution

Please see our [Contribution](https://github.com/GoogleCloudPlatform/recaptcha-edge/blob/main/CONTRIBUTING.md) guidelines.

## Issues and Support

For technical issues, please see the [reCAPTCHA Enterprise Support Documentation](https://cloud.google.com/recaptcha/docs/getting-support).

For bugs or issues specifically with this codebase, please open a new [Github issue](https://github.com/GoogleCloudPlatform/recaptcha-edge/issues) in this project.
