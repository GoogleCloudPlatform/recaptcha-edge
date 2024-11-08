# reCAPTCHA WAF (Edge Compute) Library

[![Build and Test](https://github.com/GoogleCloudPlatform/recaptcha-waf/actions/workflows/node.js.yml/badge.svg)](https://github.com/GoogleCloudPlatform/recaptcha-waf/actions/workflows/node.js.yml)

A library to access reCAPTCHA Enterprise via various edge compute platforms. The currently supported platforms are:

* [Akamai](https://github.com/GoogleCloudPlatform/recaptcha-waf/tree/main/bindings/akamai)
* [Cloudflare](https://github.com/GoogleCloudPlatform/recaptcha-waf/tree/main/bindings/cloudflare)
* [Fastly](https://github.com/GoogleCloudPlatform/recaptcha-waf/tree/main/bindings/fastly)

## Usage
This project is intended to be used in one of two ways:

1. Using a prebuilt package uploaded to your edge compute platform of choice.
2. or imported as an NPM package for advanced use-cases.

### Prebuilt Package
Check the [Releases](https://github.com/GoogleCloudPlatform/recaptcha-waf/releases) page for the most recent build for your edge compute platform of choice. 
The prebuilt packages are intended to be used with the [reCAPTCHA Firewall Policies](https://cloud.google.com/recaptcha/docs/firewall-policies-overview) feature.

Typically, this involves:
* Create the appropriate reCAPTCHA Site Keys in [Google Cloud reCAPTCHA Console](https://console.cloud.google.com/security/recaptcha).
* Upload the package to your edge compute platform.
* Configure the package to use the created reCAPTCHA Site Keys.
* Create a set of Firewall Policies to protect sensative pages or actions.

Please see the [reCAPTCHA Google Cloud Documentation](https://cloud.google.com/recaptcha/docs) for more details on each step.

### As a Library
This package has not yet been added to the NPM package repository, and must be manually imported.

Please see the examples for each binding in the [bindings](https://github.com/GoogleCloudPlatform/recaptcha-waf/tree/main/bindings) directory of choice.

## Contribution

Please see our [Contribution](https://github.com/GoogleCloudPlatform/recaptcha-waf/blob/main/CONTRIBUTING.md) guidelines.

## Issues and Support

For technical issues, please see the [reCAPTCHA Enterprise Support Documentation](https://cloud.google.com/recaptcha/docs/getting-support).

For bugs or issues specifically with this codebase, please open a new [Github issue](https://github.com/GoogleCloudPlatform/recaptcha-waf/issues) in this project.
