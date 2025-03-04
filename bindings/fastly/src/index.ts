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

/// <reference types="@fastly/js-compute" />
import { ConfigStore } from "fastly:config-store";
import { Dictionary } from "fastly:dictionary";
import { CacheOverride } from "fastly:cache-override";
import { SimpleCache } from "fastly:cache";

const RECAPTCHA_JS = "https://www.google.com/recaptcha/enterprise.js";
// Firewall Policies API is currently only available in the public preview.
const DEFAULT_RECAPTCHA_ENDPOINT = "https://public-preview-recaptchaenterprise.googleapis.com";

import {
  processRequest,
  RecaptchaConfig,
  RecaptchaContext,
  LogLevel,
  InitError,
  EdgeResponse,
  EdgeRequest,
  FetchApiResponse,
  FetchApiRequest,
  EdgeResponseInit,
  Event,
} from "@google-cloud/recaptcha";
import pkg from "../package.json";

const streamReplace = (
  inputStream: ReadableStream<Uint8Array>,
  targetStr: string,
  replacementStr: string,
): ReadableStream<Uint8Array> => {
  let buffer = "";
  const decoder = new TextDecoder("utf-8");
  const encoder = new TextEncoder();
  const inputReader = inputStream.getReader();
  let found = false; // Flag to track if replacement has been made.

  const outputStream = new ReadableStream<Uint8Array>({
    start() {
      buffer = "";
      found = false;
    },
    async pull(controller) {
      const { value: chunk, done: readerDone } = await inputReader.read();

      if (chunk) {
        buffer += decoder.decode(chunk);
      }

      if (!found) {
        // Only perform replacement if not already found.
        let targetIndex = buffer.indexOf(targetStr);
        if (targetIndex !== -1) {
          const beforeTarget = buffer.slice(0, targetIndex);
          const afterTarget = buffer.slice(targetIndex + targetStr.length);
          controller.enqueue(encoder.encode(beforeTarget + replacementStr));
          buffer = afterTarget;
          targetIndex = -1;
          found = true;
        }
      }

      if (readerDone) {
        controller.enqueue(encoder.encode(buffer));
        controller.close();
      } else if (buffer.length > targetStr.length && !found) {
        const safeChunk = buffer.slice(0, buffer.length - targetStr.length);
        controller.enqueue(encoder.encode(safeChunk));
        buffer = buffer.slice(buffer.length - targetStr.length);
      }
    },
    cancel() {
      inputReader.cancel();
    },
  });

  return outputStream;
};

// Mock responses (same as before)
const mockAssessmentsResponse = {
  assessments: [
    { id: "123", name: "Assessment 1" },
    { id: "2223", name: "Assessment 2" },
  ],
};

const mockFirewallPoliciesResponse = {
  policies: [
    { id: "A12", name: "Policy A" },
    { id: "B12", name: "Policy B" },
  ],
};

export {
  callCreateAssessment,
  callListFirewallPolicies,
  NetworkError,
  ParseError,
  processRequest,
  RecaptchaConfig,
  RecaptchaError,
} from "@google-cloud/recaptcha";

export class FastlyContext extends RecaptchaContext {
  readonly sessionPageCookie = "recaptcha-fastly-t";
  readonly challengePageCookie = "recaptcha-fastly-e";
  readonly environment: [string, string] = [pkg.name, pkg.version];
  start_time: number;

  constructor(
    private event: FetchEvent,
    cfg: RecaptchaConfig,
  ) {
    super(cfg);
    this.start_time = performance.now();
  }

  /**
   * Log performance debug information.
   *
   * This method should conditionally log performance only if the
   * config.debug flag is set to true.
   */
  log_performance_debug(event: string) {
    if (true) {
      this.debug_trace.performance_counters.push([event, performance.now() - this.start_time]);
    }
  }

  async buildEvent(req: EdgeRequest): Promise<Event> {
    return {
      // extracting common signals
      userIpAddress: this.event.client.address ?? undefined,
      headers: Array.from(req.getHeaders().entries()).map(([k, v]) => `${k}:${v}`),
      ja3: this.event.client.tlsJA3MD5 ?? undefined,
      requestedUri: req.url,
      userAgent: req.getHeader("user-agent") ?? undefined,
    };
  }

  async injectRecaptchaJs(resp: EdgeResponse): Promise<EdgeResponse> {
    let base_resp = (resp as FetchApiResponse).asResponse();
    const sessionKey = this.config.sessionSiteKey;
    const RECAPTCHA_JS_SCRIPT = `<script src="${RECAPTCHA_JS}?render=${sessionKey}&waf=session" async defer></script>`;
    // rewrite the response
    if (resp.getHeader("Content-Type")?.startsWith("text/html")) {
      const newRespStream = streamReplace(base_resp.body!, "</head>", RECAPTCHA_JS_SCRIPT + "</head>");
      resp = new FetchApiResponse(new Response(newRespStream, base_resp));
    }
    return Promise.resolve(resp);
  }

  log(level: LogLevel, msg: string) {
    console.log(msg);
    super.log(level, msg);
  }

  createRequest(url: string, options: any): EdgeRequest {
    return new FetchApiRequest(new Request(url, options));
  }

  createResponse(body: string, options?: EdgeResponseInit): EdgeResponse {
    return new FetchApiResponse(body, options);
  }

  async fetch(req: EdgeRequest, options?: RequestInit): Promise<EdgeResponse> {
    let base_req = req as FetchApiRequest;
    return fetch(base_req.asRequest(), options).then((v) => {
      return new FetchApiResponse(v);
    });
  }

  /**
   * Fetch from the customer's origin.
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_origin(req: EdgeRequest): Promise<EdgeResponse> {
    return this.fetch(req, { backend: "origin" });
  }

  /**
   * Call fetch for ListFirewallPolicies.
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_list_firewall_policies(req: EdgeRequest): Promise<EdgeResponse> {
    return this.fetch(req, {
      backend: "recaptcha",
      // cacheOverride: new CacheOverride("override", { ttl: 600, swr: 300 }),
    });

    // 2
    // const url = new URL(req.url);
    // const path = url.pathname; // Use the full path as the cache key

    // const content = await SimpleCache.getOrSet(path, async () => {
    //   // Fetch from the origin (recaptcha backend in this case)
    //   const originResponse = await this.fetch(req, { backend: "recaptcha" });
    //   const body = await originResponse.text();

    //   // Extract headers you want to cache
    //   const headers = originResponse.getHeaders();
    //   return {
    //     value: JSON.stringify({ body, headers }), // Store both body and headers
    //     ttl: 600, // Cache for 10 minutes (as in your example)
    //   };
    // });

    // // Reconstruct the response from the cached data
    // const response = new FetchApiResponse(await content.text(), {
    //   status: 200, // Or get the status from the cached headers if needed
    //   headers: {'content-type': 'text/plain;charset=UTF-8'},
    // });

    // this.log_performance_debug("[content] listFirewallPolicies " + JSON.stringify(response));

    // return response;

    // 3
    // return this.fetch(req, {
    //   backend: "recaptcha",
    //   cacheOverride: new CacheOverride({
    //     afterSend(resp) {
    //       // Don't cache in the browser
    //       resp.headers.set("Cache-Control", "max-age=1200");
    //       console.log("info", resp.cached);
    //       // indicates how long since the response generated by the origin
    //       // const age = parseInt(resp.headers.get("Age") || "0", 10);
    //       resp.ttl = 3600; // Ensure ttl is not negative
    //       return {
    //         // Cache in edge (Fastly worker)
    //         cache: false,
    //       };
    //     },
    //   }),
    // });
  }

  /**
   * Call fetch for CreateAssessment
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_create_assessment(req: EdgeRequest): Promise<EdgeResponse> {
    return this.fetch(req, { backend: "recaptcha" });
  }

  /**
   * Call fetch for getting the ChallengePage
   * @param path: the URL to fetch the challenge page from.
   * @param soz_base64: the base64 encoded soz.
   */
  async fetch_challenge_page(req: EdgeRequest): Promise<EdgeResponse> {
    return this.fetch(req, {
      backend: "google",
    });
  }
}

export function recaptchaConfigFromConfigStore(name: string): RecaptchaConfig {
  let cfg: Dictionary | ConfigStore;
  try {
    cfg = new ConfigStore(name);
  } catch (e) {
    // eslint-disable-line  @typescript-eslint/no-unused-vars
    try {
      // Backup. Try dictionary.
      cfg = new Dictionary(name);
    } catch (e) {
      throw new InitError('Failed to open Fastly config store: "' + name + '". ' + JSON.stringify(e));
    }
  }
  return {
    projectNumber: Number(cfg.get("project_number")),
    apiKey: cfg.get("api_key") ?? "",
    actionSiteKey: cfg.get("action_site_key") ?? undefined,
    expressSiteKey: cfg.get("express_site_key") ?? undefined,
    sessionSiteKey: cfg.get("session_site_key") ?? undefined,
    challengePageSiteKey: cfg.get("challengepage_site_key") ?? undefined,
    enterpriseSiteKey: cfg.get("enterprise_site_key") ?? undefined,
    recaptchaEndpoint: cfg.get("recaptcha_endpoint") ?? DEFAULT_RECAPTCHA_ENDPOINT,
    sessionJsInjectPath: cfg.get("session_js_install_path") ?? undefined,
    debug: (cfg.get("debug") ?? "true") == "true",
    unsafe_debug_dump_logs: (cfg.get("unsafe_debug_dump_logs") ?? "false") == "true",
  };
}

// The entry point for your application.
//
// Use this fetch event listener to define your main request handling logic. It
// could be used to route based on the request properties (such as method or
// path), send the request to a backend, make completely new requests, and/or
// generate synthetic responses.

addEventListener("fetch", (event) => event.respondWith(handleRequest(event)));

function createMockResponse(body: string, options?: EdgeResponseInit): Response {
  return new Response(body, options);
}

async function handleRequest(event: FetchEvent): Promise<Response> {
  const req = event.request;

  const url = new URL(req.url);
  if (url.pathname.includes("/assessments/")) {
    return createMockResponse(JSON.stringify(mockAssessmentsResponse), {
      status: 200,
      headers: { "Content-Type": "application/json", "Surrogate-Control": "public, max-age=3600" },
    });
  } else if (url.pathname.includes("/firewallpolicies/")) {
    return createMockResponse(JSON.stringify(mockFirewallPoliciesResponse), {
      status: 200,
      headers: { "Content-Type": "application/json", "Surrogate-Control": "public, max-age=3600" },
    });
  }

  try {
    const config = recaptchaConfigFromConfigStore("recaptcha");
    const fastly_ctx = new FastlyContext(event, config);
    fastly_ctx.log("debug", "Fastly client JA3MD5: " + event.client.tlsJA3MD5);
    fastly_ctx.log("debug", "Fastly client address " + event.client.address);
    return processRequest(fastly_ctx, new FetchApiRequest(event.request)).then((v) =>
      (v as FetchApiResponse).asResponse(),
    );
    // eslint-disable-next-line  @typescript-eslint/no-unused-vars
  } catch (e) {
    // Default just fetch from origin...
    return fetch(event.request, { backend: "origin" });
  }
}
