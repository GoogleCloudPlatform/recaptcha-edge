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

const RECAPTCHA_JS = "https://www.google.com/recaptcha/enterprise.js";
// Firewall Policies API is currently only available in the public preview.
const DEFAULT_RECAPTCHA_ENDPOINT =
  "https://public-preview-recaptchaenterprise.googleapis.com";

import {
  processRequest,
  RecaptchaConfig,
  RecaptchaContext,
  LogLevel,
  InitError,
} from "@google-cloud/recaptcha";
import { HTMLRewriter } from "@worker-tools/html-rewriter";
import pkg from "../package.json";

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
  readonly httpGetCachingEnabled = true;
  start_time: number;
  performance_counters: Array<[string, number]> = [];

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
    if (this.config.debug) {
      this.performance_counters.push([
        event,
        performance.now() - this.start_time,
      ]);
    }
  }

  buildEvent(req: Request): object {
    return {
      // extracting common signals
      userIpAddress: req.headers.get("Fastly-Client-IP") ?? undefined,
      headers: Array.from(req.headers.entries()).map(([k, v]) => `${k}:${v}`),
      ja3: this.event.client.tlsJA3MD5 ?? undefined,
      requestedUri: req.url,
      userAgent: req.headers.get("user-agent") ?? undefined,
    };
  }

  injectRecaptchaJs(resp: Response): Promise<Response> {
    const sessionKey = this.config.sessionSiteKey;
    const RECAPTCHA_JS_SCRIPT = `<script src="${RECAPTCHA_JS}?render=${sessionKey}&waf=session" async defer></script>`;
    return Promise.resolve(
      new HTMLRewriter()
        .on("head", {
          element(element: any) {
            element.append(RECAPTCHA_JS_SCRIPT, { html: true });
          },
        })
        .transform(new Response(resp.body, resp)),
    );
  }

  log(level: LogLevel, msg: string) {
    console.log(msg);
    super.log(level, msg);
  }

  /**
   * Fetch from the customer's origin.
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_origin(
    req: RequestInfo,
    options?: RequestInit,
  ): Promise<Response> {
    return this.fetch(req, { ...options, backend: "origin" });
  }

  /**
   * Call fetch for ListFirewallPolicies.
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_list_firewall_policies(
    req: RequestInfo,
    options?: RequestInit,
  ): Promise<Response> {
    return this.fetch(req, { ...options, backend: "recaptcha" });
  }

  /**
   * Call fetch for CreateAssessment
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_create_assessment(
    req: RequestInfo,
    options?: RequestInit,
  ): Promise<Response> {
    return this.fetch(req, { ...options, backend: "recaptcha" });
  }

  /**
   * Call fetch for getting the ChallengePage
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_challenge_page(
    req: RequestInfo,
    options?: RequestInit,
  ): Promise<Response> {
    return this.fetch(req, { ...options, backend: "google" });
  }
}

export function recaptchaConfigFromConfigStore(name: string): RecaptchaConfig {
  let cfg: Dictionary | ConfigStore;
  try {
    cfg = new ConfigStore(name);
  } catch (e) {
    try {    
      // Backup. Try dictionary.
      cfg = new Dictionary(name);
    } catch (e) {
      throw new InitError("Failed to open Fastly config store: \"" + name + "\". " + JSON.stringify(e));
    }
  } 
  return {
    projectNumber: Number(cfg.get("project_number")),
    apiKey: cfg.get("api_key") ?? "",
    actionSiteKey: cfg.get("action_site_key") ?? undefined,
    expressSiteKey: cfg.get("express_site_key") ?? undefined,
    sessionSiteKey: cfg.get("session_site_key") ?? undefined,
    challengePageSiteKey: cfg.get("challengepage_site_key") ?? undefined,
    recaptchaEndpoint:
      cfg.get("recaptcha_endpoint") ?? DEFAULT_RECAPTCHA_ENDPOINT,
    sessionJsInjectPath: cfg.get("session_js_install_path") ?? undefined,
    debug: Boolean(cfg.get("debug") ?? false),
    dump_logs: Boolean(cfg.get("unsafe_debug_dump_logs") ?? false)
  };
}

// The entry point for your application.
//
// Use this fetch event listener to define your main request handling logic. It
// could be used to route based on the request properties (such as method or
// path), send the request to a backend, make completely new requests, and/or
// generate synthetic responses.

addEventListener("fetch", (event) => event.respondWith(handleRequest(event)));

async function handleRequest(event: FetchEvent) {
  try {
    let config = recaptchaConfigFromConfigStore("recaptcha");
    const fastly_ctx = new FastlyContext(
      event,
      config
    );
    let resp = processRequest(fastly_ctx, event.request);
    if (config.dump_logs) {
      await resp;
      return new Response(JSON.stringify({logs: fastly_ctx.log_messages, exceptions: fastly_ctx.exceptions}, null, 2));
    }
    return resp;
  } catch(e)  {
    // Default just fetch from origin...
    return fetch(event.request, { backend: "origin" });
  }
}
