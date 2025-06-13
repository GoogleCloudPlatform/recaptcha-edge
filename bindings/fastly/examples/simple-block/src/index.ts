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
 * A simple example on how to use the reCAPTCHA Fastly library to
 * make decisions based on score.
 *
 * This example calls Create assessment based on configuration context from Fastly's Env,
 * and automatically extracted information from the incoming request.
 */

import {
  FastlyContext,
  recaptchaConfigFromConfigStore,
  createAssessment,
  RecaptchaError,
} from "@google-cloud/recaptcha-fastly";

/**
 * A basic function that will call recaptcha's CreateAssessment with all appropriate
 * data extracted from the incoming request and registered config context. A simple
 * Allow/Block verdict will be made based on the risk score in the Assessment.
 * @param request The incoming Fastly Request.
 * @param rcctx A recaptcha.FastlyContext object.
 * @returns "allow" or "block".
 */
async function recaptchaRiskVerdict(rcctx: FastlyContext, request: Request): Promise<"allow" | "block"> {
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

// The entry point for your application.
//
// Use this fetch event listener to define your main request handling logic. It
// could be used to route based on the request properties (such as method or
// path), send the request to a backend, make completely new requests, and/or
// generate synthetic responses.
addEventListener("fetch", (event) => event.respondWith(handleRequest(event)));

async function handleRequest(event: FetchEvent): Promise<Response> {
    const rcctx = new FastlyContext(event, recaptchaConfigFromConfigStore("recaptcha"));

    if ((await recaptchaRiskVerdict(rcctx, event.request)) == "block") {
      // Or: we could return a templated HTML page.
      return new Response("This request has been blocked for security reasons.", { status: 403 });
    }
    // forward the request to the origin, and return the response.
    return fetch(event.request, { backend: "origin" });
}
