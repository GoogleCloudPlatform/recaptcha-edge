/**
 * @fileoverview reCAPTCHA Enterprise Library for Akamai Edge Workers.
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

import { RecaptchaConfig, RecaptchaContext, EdgeRequest, EdgeRequestInfo, EdgeResponse } from "@google-cloud/recaptcha";
import { HtmlRewritingStream } from "html-rewriter";
import { httpRequest } from "http-request";
import { createResponse as akamaiCreateResponse } from "create-response";
import { logger } from "log";
import { ReadableStream } from "streams";
import pkg from "../package.json";

function headersGuard(
  headers: Headers | Record<string, string | readonly string[]> | string[][] | undefined,
): Record<string, string | string[]> {
  if (headers === undefined) {
    return {};
  }

  // We have Headers
  if (headers instanceof Headers) {
    const headerObj: Record<string, string> = {};
    headers.forEach((value, key) => {
      headerObj[key] = value;
    });
    return headerObj;
  }

  // We have string[][]
  if (Array.isArray(headers)) {
    const headerMap: Record<string, string | string[]> = {};

    headers.forEach(([key, ...values]) => {
      headerMap[key] = values.length === 1 ? values[0] : values;
    });

    return headerMap;
  }

  // We have Record<string, string | readonly string[]>
  // remove readonly attribute
  const headerMap: Record<string, string | string[]> = {};
  for (const key in headers) {
    const value = headers[key];
    headerMap[key] = value.length === 1 ? value[0] : [...value];
  }

  return headerMap;
}

function bodyGuard(body: any | null): string | ReadableStream | undefined {
  if (body === null) {
    return undefined;
  }
  if (typeof body === "string" || body instanceof ReadableStream) {
    return body as string | ReadableStream;
  }
  throw "Invalid request body";
}

const RECAPTCHA_JS = "https://www.google.com/recaptcha/enterprise.js";
// Firewall Policies API is currently only available in the public preview.
const DEFAULT_RECAPTCHA_ENDPOINT = "https://public-preview-recaptchaenterprise.googleapis.com";

// Some headers aren't safe to forward from the origin response through an
// EdgeWorker on to the client For more information see the tech doc on
// create-response: https://techdocs.akamai.com/edgeworkers/docs/create-response
const UNSAFE_RESPONSE_HEADERS = new Set([
  "content-length",
  "transfer-encoding",
  "connection",
  "vary",
  "accept-encoding",
  "content-encoding",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "upgrade",
]);

export {
  callCreateAssessment,
  callListFirewallPolicies,
  NetworkError,
  ParseError,
  processRequest,
  RecaptchaConfig,
  RecaptchaError,
} from "@google-cloud/recaptcha";

export class AkamaiContext extends RecaptchaContext {
  // eslint-disable-next-line  @typescript-eslint/no-unused-vars
  static injectRecaptchaJs(inputResponse: object) {
    throw new Error("Method not implemented.");
  }
  readonly sessionPageCookie = "recaptcha-akam-t";
  readonly challengePageCookie = "recaptcha-akam-e";
  readonly environment: [string, string] = [pkg.name, pkg.version];
  readonly httpGetCachingEnabled = true;
  start_time: number;
  performance_counters: Array<[string, number]> = [];

  constructor(cfg: RecaptchaConfig) {
    super(cfg);
    this.start_time = Date.now();
  }

  /**
   * Log performance debug information.
   *
   * This method should conditionally log performance only if the
   * config.debug flag is set to true.
   */
  log_performance_debug(event: string) {
    if (this.config.debug) {
      this.performance_counters.push([event, Date.now() - this.start_time]);
    }
  }

  buildEvent(req: EdgeRequest): object {
    return {
      // extracting common signals
      userIpAddress: req.headers.get("True-Client-IP"),
      headers: Array.from(req.headers.entries()).map(([k, v]) => `${k}:${v}`),
      ja3: (req as any)?.akamai?.bot_management?.ja3_hash ?? undefined,
      requestedUri: req.url,
      userAgent: req.headers.get("user-agent"),
    };
  }

  createResponse(body: string, options?: ResponseInit): EdgeResponse {
    return akamaiCreateResponse(options?.status || 200, options?.headers, body);
  }

  async fetch(req: EdgeRequestInfo, options?: RequestInit): Promise<EdgeResponse> {
    // Convert RequestInfo to string if it's not already
    const url = typeof req === "string" ? req : req.url;
    return httpRequest(url, {
      method: options?.method ?? undefined,
      headers: headersGuard(options?.headers),
      body: bodyGuard(options?.body ?? null),
      /* there is no timeout in a Fetch API request. Consider making it a member of the Context */
    });
  }

  getSafeResponseHeaders(headers: any) {
    for (const [headerKey] of Object.entries(headers)) {
      if (UNSAFE_RESPONSE_HEADERS.has(headerKey)) {
        headers.delete(headerKey);
      }
    }

    return headers;
  }

  injectRecaptchaJs(resp: Response): Promise<Response> {
    const sessionKey = this.config.sessionSiteKey;
    const RECAPTCHA_JS_SCRIPT = `<script src="${RECAPTCHA_JS}?render=${sessionKey}&waf=session" async defer></script>`;

    const rewriter = new HtmlRewritingStream();

    // Adds a <script> tag to the <head>
    rewriter.onElement("head", (el) => {
      el.append(`${RECAPTCHA_JS_SCRIPT}`);
    });

    let readableBody: ReadableStream<Uint8Array>;
    if (resp.body) {
      // Double check why it's NULL
      const reader = resp.body.getReader();
      readableBody = new ReadableStream({
        async pull(controller) {
          const { done, value } = await reader.read();
          if (done) {
            controller.close();
          } else {
            controller.enqueue(value);
          }
        },
      });
    } else {
      // Create an empty ReadableStream if resp.body is null
      logger.log("Request body is NULL");
      readableBody = new ReadableStream();
    }

    return Promise.resolve(
      new Response(readableBody.pipeThrough(rewriter) as any, {
        status: resp.status,
        headers: this.getSafeResponseHeaders(resp.headers),
      }),
    );
  }

  // Fetch the firewall lists.
  // TODO: Cache the firewall policies.
  // https://techdocs.akamai.com/api-definitions/docs/caching
  // https://techdocs.akamai.com/property-mgr/docs/caching-2#how-it-works
  async fetch_list_firewall_policies(req: EdgeRequestInfo, options?: RequestInit): Promise<EdgeResponse> {
    return this.fetch(req, {
      ...options,
    });
  }
}

export function recaptchaConfigFromRequest(request: EW.IngressClientRequest): RecaptchaConfig {
  logger.log(request.getVariable("PMUSER_RECAPTCHAACTIONSITEKEY") || "");
  return {
    projectNumber: parseInt(request.getVariable("PMUSER_GCPPROJECTNUMBER") || "0", 10),
    apiKey: request.getVariable("PMUSER_GCPAPIKEY") || "",
    actionSiteKey: request.getVariable("PMUSER_RECAPTCHAACTIONSITEKEY") || "",
    expressSiteKey: request.getVariable("PMUSER_RECAPTCHAEXPRESSSITEKEY") || "",
    sessionSiteKey: request.getVariable("PMUSER_RECAPTCHASESSIONSITEKEY") || "",
    challengePageSiteKey: request.getVariable("PMUSER_RECAPTCHACHALLENGESITEKEY") || "",
    recaptchaEndpoint: request.getVariable("PMUSER_RECAPTCHAENDPOINT") || DEFAULT_RECAPTCHA_ENDPOINT,
    debug: request.getVariable("PMUSER_DEBUG") === "true",
    unsafe_debug_dump_logs: request.getVariable("PMUSER_UNSAFE_DEBUG_DUMP_LOGS") === "true",
  };
}
