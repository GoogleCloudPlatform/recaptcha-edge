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
  try {
    const assessment = await createAssessment(rcctx, request);
    let score = assessment?.riskAnalysis?.score ?? 0.1;
    if (score <= 0.3) {
      return "block";
    }
  } catch (e) {
    if (e instanceof RecaptchaError) {
    // a RecaptchaError can occur due to misconfiguration, network issues or parsing errors.
    // Depending on the cause, each RecaptchaError has a recommended action of {allow | block}.
      return e.recommended_action_enum();
    }
    throw e;
  }
  return "allow";
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const rcctx = new CloudflareContext(env, ctx, recaptchaConfigFromEnv(env));

    if ((await recaptchaRiskVerdict(rcctx, request)) == "block") {
      // Or return a templated HTML page.
      return new Response("This request has been blocked for security reasons.");
    }
    return fetch(request);
  },
} satisfies ExportedHandler<Env>;
