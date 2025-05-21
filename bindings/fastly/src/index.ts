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

export {
  NetworkError,
  ParseError,
  RecaptchaConfig,
  RecaptchaError,
  pathMatch,
  testing,
} from "@google-cloud/recaptcha-edge";

export { FastlyContext, recaptchaConfigFromConfigStore } from "./context";
export { processRequest, createAssessment, listFirewallPolicies } from "./wrappers";

import { FastlyContext, recaptchaConfigFromConfigStore } from "./context";
import { processRequest } from "./wrappers";

// The entry point for your application.
//
// Use this fetch event listener to define your main request handling logic. It
// could be used to route based on the request properties (such as method or
// path), send the request to a backend, make completely new requests, and/or
// generate synthetic responses.
addEventListener("fetch", (event) => event.respondWith(handleRequest(event)));

async function handleRequest(event: FetchEvent): Promise<Response> {
  try {
    const config = recaptchaConfigFromConfigStore("recaptcha");
    const fastly_ctx = new FastlyContext(event, config);
    fastly_ctx.log("debug", "Fastly client JA3MD5: " + event.client.tlsJA3MD5);
    fastly_ctx.log("debug", "Fastly client address " + event.client.address);
    return processRequest(fastly_ctx, event.request);
    // eslint-disable-next-line  @typescript-eslint/no-unused-vars
  } catch (e) {
    // Default just fetch from origin...
    return fetch(event.request, { backend: "origin" });
  }
}
