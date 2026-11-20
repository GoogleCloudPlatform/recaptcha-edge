> [!WARNING]
> ### Deprecated and Archived Repository
>
> [![status: inactive](https://img.shields.io/badge/status-inactive-red.svg)](https://github.com/GoogleCloudPlatform/recaptcha-edge)
>
> This repository and its associated npm packages (`@google-cloud/recaptcha-edge`, `@google-cloud/recaptcha-cloudflare`, `@google-cloud/recaptcha-fastly`) are **deprecated and archived**. They are no longer actively developed, supported, or maintained by Google.
>
> **Workflow Impact:**
> * **"Prebuilt Package" Workflow (Invalid):** The prebuilt bundles rely on the reCAPTCHA Enterprise firewall policies feature and the `processRequest` handler. Because the firewall policies feature has been retired, **this workflow is non-functional and invalid**.
> * **"As a Library" Workflow (Unsupported):** Using the package directly in your edge workers to invoke API wrapper methods (such as `createAssessment`) should continue to function for standard assessment calls. However, this workflow is **unsupported**, will not receive new reCAPTCHA features, bug fixes, or security patches.
>
> For recommended integrations and long-term support, please migrate to official [reCAPTCHA Enterprise SDKs and APIs](https://cloud.google.com/recaptcha-enterprise/docs).

# reCAPTCHA Edge Compute Library

[![Build and Test Core Library](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_core.yml/badge.svg)](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_core.yml)
[![Build and Test Akamai Binding](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_akamai.yml/badge.svg)](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_akamai.yml)
[![Build and Test Cloudflare Binding](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_cloudflare.yml/badge.svg)](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_cloudflare.yml)
[![Build and Test Fastly Binding](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_fastly.yml/badge.svg)](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_fastly.yml)

A library to access reCAPTCHA Enterprise via various edge compute platforms. The currently supported platforms are:

* [Cloudflare](https://github.com/GoogleCloudPlatform/recaptcha-edge/tree/main/bindings/cloudflare)
* [Fastly](https://github.com/GoogleCloudPlatform/recaptcha-edge/tree/main/bindings/fastly)

## Usage
This project is intended to be used in one of two ways:

1. or imported as an NPM package for advanced use-cases.
2. Using a prebuilt package uploaded to your edge compute platform of choice.

### As a Library
> [!WARNING]
> **this workflow is unsupported and will not receive new reCAPTCHA features, bug fixes, or security patches.**
Each platform has their own NPM package. Bindings that are hosted on NPM include:
* [@google-cloud/recaptcha-cloudflare](https://www.npmjs.com/package/@google-cloud/recaptcha-cloudflare?activeTab=readme)
* [@google-cloud/recaptcha-fastly](https://www.npmjs.com/package/@google-cloud/recaptcha-fastly?activeTab=readme)

Bindings that are not yet hosted on NPM should be [downloaded and installed locally](https://docs.npmjs.com/downloading-and-installing-packages-locally).

The base package is available on NPM as [@google-cloud/recaptcha-edge](https://www.npmjs.com/package/@google-cloud/recaptcha-edge) and is intended as an abstraction layer for implementing additional platforms. Platform-specific packages should be used if possible.

Please see the examples and documentation for each binding in the [bindings](https://github.com/GoogleCloudPlatform/recaptcha-edge/tree/main/bindings) directory of choice.


### Prebuilt Package
> [!WARNING]
> **this workflow is fully deprecated and must not be used.**
Check the [Releases](https://github.com/GoogleCloudPlatform/recaptcha-edge/releases) page for the most recent build for your edge compute platform of choice. 
The prebuilt packages are intended to be used with the [reCAPTCHA Firewall Policies](https://cloud.google.com/recaptcha/docs/firewall-policies-overview) feature.

Typically, this involves:
* Create the appropriate reCAPTCHA Site Keys in [Google Cloud reCAPTCHA Console](https://console.cloud.google.com/security/recaptcha).
* Upload and install the package to your edge compute platform.
* Configure the package to use the created reCAPTCHA Site Keys.
* Create a set of Firewall Policies to protect sensitive pages or actions.

Please see the [reCAPTCHA Google Cloud Documentation](https://cloud.google.com/recaptcha/docs) for more details on each step.

## Contribution

Please see our [Contribution](https://github.com/GoogleCloudPlatform/recaptcha-edge/blob/main/CONTRIBUTING.md) guidelines.

## Issues and Support

For technical issues, please see the [reCAPTCHA Enterprise Support Documentation](https://cloud.google.com/recaptcha/docs/getting-support).

For bugs or issues specifically with this codebase, please open a new [Github issue](https://github.com/GoogleCloudPlatform/recaptcha-edge/issues) in this project.
