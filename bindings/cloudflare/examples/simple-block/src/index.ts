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
 * A simple example on how to use the reCAPTCHA Cloudflare library to
 * make decisions based on score.
 *
 * This example calls Create assessment based on configuration context from CloudFlare's Env,
 * and automatically extracted information from the incoming request.
 */

import {
  CloudflareContext,
  recaptchaConfigFromEnv,
  createAssessment,
  RecaptchaError,
} from "@google-cloud/recaptcha-cloudflare";

/**
 * A basic function that will call recaptcha's CreateAssessment with all appropriate
 * data extracted from the incoming request and registered config context. A simple
 * Allow/Block verdict will be made based on the risk score in the Assessment.
 * @param request The incoming Cloudflare Request.
 * @param rcctx A recaptcha.CloudflareContext object.
 * @returns "allow" or "block".
 */
async function recaptchaRiskVerdict(rcctx: CloudflareContext, request: Request): Promise<"allow" | "block"> {
  const DEFAULT_SCORE = 0.7;
  try {
    const assessment = await createAssessment(rcctx, request);
    // A score should always be in the assessment, but in the event of an error we will use
    // a default score.
    let score = assessment?.riskAnalysis?.score ?? DEFAULT_SCORE;
    if (score <= 0.3) {
      return "block";
    }
  } catch (e) {
    if (e instanceof RecaptchaError) {
      // a RecaptchaError can occur due to misconfiguration, network issues or parsing errors.
      // Depending on the cause, each RecaptchaError has a recommended action of {allow | block}.
      return e.recommended_action_enum();
    }
    // The recaptcha library should always wrap errors in the RecaptchaError type. In the event of
    // an uncaught error, allow to avoid blocking customers.
    return "allow";
  }
  return "allow";
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const rcctx = new CloudflareContext(env, ctx, recaptchaConfigFromEnv(env));

    if ((await recaptchaRiskVerdict(rcctx, request)) == "block") {
      // Or: we could return a templated HTML page.
      return new Response("This request has been blocked for security reasons.", { status: 403 });
    }
    // forward the request to the origin, and return the response.
    return fetch(request);
  },
} satisfies ExportedHandler<Env>;
