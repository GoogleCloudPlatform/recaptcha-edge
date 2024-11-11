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
  callCreateAssessment,
  RecaptchaError
} from "@google-cloud/recaptcha-cloudflare";

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const cfctx = new CloudflareContext(env, ctx, recaptchaConfigFromEnv(env));
    let block = false;
    try {
      // TODO: check validity of token.
      const assessment = await callCreateAssessment(cfctx, request);
      if ((assessment.riskAnalysis?.score  ?? 0) <= 0.3) {
        block = true;
      }
    } catch (e) {
      if (e instanceof RecaptchaError) {
        if ((e.recommendedAction?.type ?? "block") === "block") {
          block = true;
        }
      }
    }
    if (block) {
      // Or return a templated HTML page.
      return new Response(
        "This request has been blocked for security reasons.",
      );
    } else {
      return fetch(request);
    }
  },
} satisfies ExportedHandler<Env>;
