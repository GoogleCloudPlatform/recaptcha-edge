/**
 * Copyright 2024 Google LLC
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

/**
 * An example on how to use the reCAPTCHA Cloudflare library to
 * make decisions based on AccountDefender assessment.
 */

import {
  CloudflareContext,
  recaptchaConfigFromEnv,
  createAssessment,
  RecaptchaError,
  pathMatch,
} from "@google-cloud/recaptcha-cloudflare";

/**
 * A function that will call recaptcha's CreateAssessment with all appropriate
 * data extracted from the incoming request and registered config context. An
 * Allow/Block verdict will be made based on the accountDefenderAssessment.
 * 
 * This function is intended to be used on form submission POST requests with reCAPTCHA V3 integration and
 * Account Defender enabled in the sitekey. 
 * see: https://cloud.google.com/recaptcha/docs/account-defender#integration-workflow
 * The client integration should put the token in the 'g-recaptcha-response' form field.
 * The user's username is expected in the 'username' form field. 
 * @param rcctx A recaptcha.CloudflareContext object.
 * @param request The incoming Cloudflare Request.
 * @returns "allow" or "block".
 */
async function recaptchaLoginAccountVerdict(rcctx: CloudflareContext, request: Request): Promise<"allow" | "block"> {
  try {
    // Read the username from the incoming request form data.
    // We clone the request so the body can be read again elsewhere.
    const bodyText = await request.clone().text();
    const formData = new URLSearchParams(bodyText);
    const username = formData.get("username");
    // If the token or username is not found, block.
    if (!username) {
      return "block";
    }
    // The token will be automatically extracted from the g-recaptcha-response form data.
    const assessment = await createAssessment(rcctx, request, {userInfo: {accountId: username}});
    // Block all requests that Account Defender identifies as 'suspicious login activity'.
    if ((assessment.accountDefenderAssessment?.labels ?? []).includes("SUSPICIOUS_LOGIN_ACTIVITY")) {
      return "block";
    }
  } catch (e) {
    if (e instanceof RecaptchaError) {
      // a RecaptchaError can occur due to misconfiguration, network issues or parsing errors.
      // Depending on the cause, each RecaptchaError has a recommended action of {allow | block}.
      return e.recommended_action_enum();
    }
    // The recaptcha library should always wrap errors in the RecaptchaError type. 
    // An uncaught error should be from body JSON parsing. In this case, if the request is
    // not valid JSON (this includes an empty body), don't bother forwarding the call to the origin.
    return "block";
  }
  return "allow";
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const rcctx = new CloudflareContext(env, ctx, recaptchaConfigFromEnv(env));
    if (pathMatch(request, "/login", "POST") && (await recaptchaLoginAccountVerdict(rcctx, request)) == "block") {
      // Or: we could return a templated HTML page.
      return new Response("This request has been blocked for security reasons.", { status: 403 });
    }
    // forward the request to the origin, and return the response.
    return fetch(request);
  },
} satisfies ExportedHandler<Env>;
