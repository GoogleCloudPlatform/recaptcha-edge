# reCAPTCHA Cloudflare Worker Library

[![Build and Test Cloudflare Binding](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_cloudflare.yml/badge.svg)](https://github.com/GoogleCloudPlatform/recaptcha-edge/actions/workflows/build_cloudflare.yml)

A library to access reCAPTCHA Enterprise via [Cloudflare Workers](https://developers.cloudflare.com/workers/).

## Usage
This project is intended to be used in one of two ways:

1. Using a prebuilt package uploaded to your Cloudflare project.
2. or imported as an NPM package for advanced use-cases.

### Prebuilt Package

Check the [Releases](https://github.com/GoogleCloudPlatform/recaptcha-edge/releases) page for the most recent build for Cloudflare.

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

When deployed as a Cloudflare Worker, this package will cache a list of your configured Firewall Policies. When an incoming request is received, first the requested path
will be checked against the list of all policies. 

If no policy paths match, reCAPTCHA will be bypassed and the request will be forwarded to the origin (the Allow action). 

If any policy paths match the incoming request,
the reCAPTCHA CreateAssessment API will be called. reCAPTCHA will evaluate the policies as per the above logic and a list of actions will be returned to the Cloudflare worker. The Cloudflare worker
will execute the actions.


To integrate this package with an existing Cloudflare account:
* Create the appropriate reCAPTCHA Site Keys in [Google Cloud reCAPTCHA Console](https://console.cloud.google.com/security/recaptcha).
* Upload the package to Cloudflare with the [`wrangler deploy`](https://developers.cloudflare.com/workers/wrangler/commands/#deploy) CLI command or in the 'Workers and Pages' section of the Cloudflare UI.
  * If using the Wrangler CLI, please configure the relevant site keys and variables in `wrangler.toml` before deploying.
  * If using the Cloudflare web UI, add the relevant site keys and variables in the "Settings > Variables and Secrets" section of the new worker.
* Create a set of Firewall Policies to protect sensative pages or actions.
* In the "Workers Routes" section of the Cloudflare web UI, create a rule to for the worker to intercept traffic.

Please see the [reCAPTCHA Google Cloud Documentation](https://cloud.google.com/recaptcha/docs) for more details on each step.

### As a Library
This package has been added to the NPM package repo as [@google-cloud/recaptcha-cloudflare](https://www.npmjs.com/package/@google-cloud/recaptcha-cloudflare?activeTab=readme).

This library supports a standard reCAPTCHA v2 or v3 workflow, and is intended to be used on the [Cloudflare Worker](https://developers.cloudflare.com/workers/) edge compute platform. To use this library, first create a `CloudflareContext` object. This object
can be initialized with [Cloudflare Environment Variables](https://developers.cloudflare.com/workers/configuration/environment-variables/) or
inline constants:
```js
import {
  CloudflareContext,
  recaptchaConfigFromEnv,
  createAssessment
} from "@google-cloud/recaptcha-cloudflare";

export default {
  async fetch(request, env, ctx): Promise<Response> {
    // initialized from Cloudflare Environment
    const rcctx = new CloudflareContext(env, ctx, recaptchaConfigFromEnv(env));
    // OR: initialized inline
    const rcctx = new CloudflareContext(env, ctx, {projectNumber: 12345, apiKey: "abcd", enterpriseSiteKey: "6Labcdefg"});

    ... // do further processing
  },
} satisfies ExportedHandler<Env>;
```

This context can then be used to call reCAPTCHA's `CreateAssessment` on the incoming Request:
```js
    ...
    const assessment = await createAssessment(rcctx, request);
    ...
```

Most common request data expected in [`CreateAssessment`](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments/create) will be automatically populated when calling the `createAssessment` function, including:
* userAgent
* userIpAddress
* requestedUri
* ja3 or ja4
* headers

The Project number and API Key set when creating the `CloudflareContext` will be used to form the correct `CreateAssessment` endpoint URL.
The `enterpriseSiteKey` set when creating the `CloudflareContext` will be used to populate the Assessment event. 

The user's reCAPTCHA token may be automatically extracted from the incoming request body under the following conditions:
* The incoming requests uses a POST HTTP method
* The content type is `application/json` or `application/x-www-form-urlencoded` or `multipart/form-data`
* The token is expected to reside in the `g-recaptcha-response` field.

If all of these cases are true, simply call createAssessment:
```js
  ...
  const assessment = await createAssessment(rcctx, request);
  ...
```

If one or more of the token format cases are false, the token must be manually extracted and passed as an additional parameter:
```js
  ...
  const token = manuallyExtractToken(request); // You must define this function.
  const assessment = await createAssessment(rcctx, request, {token});
  ...
```

The `expectedAction` parameter is not automatically populated, and should be populated if applicable.
```js
    const assessment = await createAssessment(rcctx, request, {expectedAction: "login"});
```
See the official documentation on [action names](https://cloud.google.com/recaptcha/docs/actions-website).

It is important that createAssessment is only called on paths where you expect a user to pass a token. 
```js
  import {
    CloudflareContext,
    createAssessment,
    pathMatch,
  } from "@google-cloud/recaptcha-cloudflare";

  ...
  if (pathMatch(request, "/login", "POST")) {
    const assessment = await createAssessment(rcctx, request, {expectedAction: "login"});
    ... // check assessment results, such as score.
  }
    ...
```
This will avoid the added latency from the CreateAssessment RPC, and reduce billing events.

For complete end-to-end examples, see the [examples](https://github.com/GoogleCloudPlatform/recaptcha-edge/tree/main/bindings/cloudflare/examples) directory.

## Contribution

Please see our [Contribution](https://github.com/GoogleCloudPlatform/recaptcha-edge/blob/main/CONTRIBUTING.md) guidelines.

## Issues and Support

For technical issues, please see the [reCAPTCHA Enterprise Support Documentation](https://cloud.google.com/recaptcha/docs/getting-support).

For bugs or issues specifically with this codebase, please open a new [Github issue](https://github.com/GoogleCloudPlatform/recaptcha-edge/issues) in this project.
