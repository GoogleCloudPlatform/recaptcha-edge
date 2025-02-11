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

import {
  RecaptchaConfig,
  RecaptchaContext,
  EdgeRequest,
  EdgeResponse,
  LogLevel,
  EdgeResponseInit,
  EdgeRequestInit,
} from "@google-cloud/recaptcha";
import { httpRequest, HttpResponse } from "http-request";
import { createResponse } from "create-response";
import { logger } from "log";
import { ReadableStream } from "streams";
import pkg from "../package.json";
import URL from "url-parse";

function streamReplace(
  inputStream: ReadableStream<Uint8Array>,
  targetStr: string,
  replacementStr: string,
): ReadableStream<Uint8Array> {
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
}

async function readStream(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let result = await reader.read();
  let out = "";
  while (!result.done) {
    out += decoder.decode(new Uint8Array(result.value).buffer);
    result = await reader.read();
  }
  return out;
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

type AkamaiRequestInit = {
  method?: string;
  headers?: Record<string, string | string[]>;
  body?: string;
  timeout?: number;
};

export class AkamaiRequest implements EdgeRequest {
  req?: EW.ResponseProviderRequest;
  method_: string;
  url_: string;
  body_?: string;
  headers: Map<string, string>;

  constructor(req: EW.ResponseProviderRequest | string, options?: AkamaiRequestInit) {
    if (typeof req === "string") {
      this.url_ = req;
      this.method_ = options?.method ?? "GET";
      this.body_ = options?.body ?? "";
      this.headers = new Map();
      for (const [key, value] of Object.entries(options?.headers ?? {})) {
        if (typeof value === "string") {
          this.headers.set(key.toLowerCase(), value);
        } else {
          this.headers.set(key.toLowerCase(), value.join(","));
        }
      }
    } else {
      this.req = req;
      this.url_ = `${this.req.scheme}://${this.req.host}${this.req.path}`;
      this.method_ = this.req.method;
      this.headers = new Map();
      let headers = req.getHeaders();
      for (const [key, value] of Object.entries(headers)) {
        this.headers.set(key.toLowerCase(), value.join(","));
      }
    }
  }

  get url() {
    return this.url_;
  }

  set url(url: string) {
    this.url_ = url;
  }

  get method() {
    return this.method_;
  }

  addHeader(key: string, value: string): void {
    this.headers.set(key.toLowerCase(), value);
  }

  getHeader(key: string): string | null {
    return this.headers.get(key.toLowerCase()) ?? null;
  }

  getHeaders(): Map<string, string> {
    return this.headers;
  }

  getBodyText(): Promise<string> {
    if (this.req) {
      return this.req.text();
    }
    return Promise.resolve(this.body_ || "");
  }
  getBodyJson(): Promise<any> {
    if (this.req) {
      return this.req.json();
    }
    return Promise.resolve(JSON.parse(this.body_ || "{}"));
  }
}

export class AkamaiResponse implements EdgeResponse {
  //resp?: HttpResponse;
  _body?: string | ReadableStream<Uint8Array>;
  _status: number;
  headers: Map<string, string[]>;

  constructor(base: string | HttpResponse, status?: number, headers?: Record<string, string>) {
    if (typeof base === "string") {
      this._body = base;
      this._status = status ?? 200;
      this.headers = new Map();
      for (const [key, value] of Object.entries(headers ?? {})) {
        if (Array.isArray(value)) {
          this.headers.set(key.toLowerCase(), value);
        } else {
          this.headers.set(key.toLowerCase(), [value]);
        }
      }
    } else {
      // base type is HttpResponse
      this._body = base.body;
      this._status = status ?? base.status;
      this.headers = new Map();
      let rh = base.getHeaders();
      for (const key in rh) {
        this.headers.set(key.toLowerCase(), rh[key]);
      }
    }
  }

  get status(): number {
    return this._status;
  }

  get body(): ReadableStream<Uint8Array> | string {
    return this._body ?? "";
  }

  set body(new_body: ReadableStream<Uint8Array> | string) {
    this._body = new_body;
  }

  text(): Promise<string> {
    if (!this._body) {
      return Promise.resolve("");
    }
    if (typeof this._body === "string") {
      return Promise.resolve(this._body);
    }
    return readStream(this._body);
  }

  async json(): Promise<unknown> {
    return Promise.resolve(JSON.parse(await this.text()));
  }

  addHeader(key: string, value: string): void {
    let v = this.headers.get(key.toLowerCase()) ?? [];
    v.push(value);
    this.headers.set(key.toLowerCase(), v);
  }

  getHeader(key: string): string | null {
    return this.headers.get(key.toLowerCase())?.join(",") ?? null;
  }

  getHeaders(): Map<string, string> {
    let ret = new Map();
    for (const [k, v] of this.headers.entries()) {
      ret.set(k, v.join(","));
    }
    return ret;
  }

  asResponse(): object {
    let headers = new Map(this.headers);
    for (const key of UNSAFE_RESPONSE_HEADERS) {
      headers.delete(key);
    }
    return createResponse(this.status, Object.fromEntries(headers.entries()), this.body);
  }
}

export class AkamaiContext extends RecaptchaContext {
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

  /**
   * Log an exception.
   *
   * For Akamai, these messages can be dumped with CURL using enhanced debug headers.
   * see: https://techdocs.akamai.com/edgeworkers/docs/enable-enhanced-debug-headers
   */
  logException(e: any) {
    super.logException(e);
    logger.error("Exception: " + JSON.stringify(e, Object.getOwnPropertyNames(e)));
  }

  /**
   * Log a message.
   *
   * For Akamai, these messages can be dumped with CURL using enhanced debug headers.
   * see: https://techdocs.akamai.com/edgeworkers/docs/enable-enhanced-debug-headers
   */
  log(level: LogLevel, msg: string) {
    super.log(level, msg);
    switch (level) {
      case "debug":
        logger.debug(msg);
        break;
      case "info":
        logger.info(msg);
        break;
      case "warning":
        logger.warn(msg);
        break;
      case "error":
        logger.error(msg);
        break;
    }
  }

  buildEvent(req: EdgeRequest): object {
    return {
      // extracting common signals
      userIpAddress: (req as AkamaiRequest).req?.clientIp,
      headers: Array.from(req.getHeaders()).map(([k, v]) => `${k}:${v}`),
      ja3: ((req as AkamaiRequest).req as any)?.akamai?.bot_management?.ja3_hash ?? undefined,
      requestedUri: req.url,
      userAgent: req.getHeader("user-agent"),
    };
  }

  async fetch(req: EdgeRequest): Promise<EdgeResponse> {
    // Use a relative path, since this is the method for origin redirection used
    // on Akamai.
    let url = new URL(req.url);
    let headers = Object.fromEntries(req.getHeaders().entries());
    let body = (await req.getBodyText()) || undefined;
    return httpRequest(url.pathname + url.query, {
      method: req.method,
      headers,
      body,
      /* there is no timeout in a Fetch API request. Consider making it a member of the Context */
    }).then((v) => new AkamaiResponse(v));
  }

  createRequest(url: string, options: EdgeRequestInit): EdgeRequest {
    return new AkamaiRequest(url, options);
  }

  createResponse(body: string, options?: EdgeResponseInit): EdgeResponse {
    return new AkamaiResponse(body, options?.status, options?.headers);
  }

  // Overwritten because the TextEncoder object is different from the builtin NodeJS TextEncoder.
  encodeString(st: string): Uint8Array {
    return new TextEncoder().encode(st);
  }

  injectRecaptchaJs(resp: EdgeResponse): Promise<EdgeResponse> {
    let base_resp = resp as AkamaiResponse;
    const sessionKey = this.config.sessionSiteKey;
    const RECAPTCHA_JS_SCRIPT = `<script src="${RECAPTCHA_JS}?render=${sessionKey}&waf=session" async defer></script>`;
    // rewrite the response
    if (base_resp.getHeader("Content-Type")?.startsWith("text/html")) {
      let body = base_resp.body;
      if (typeof body === "string") {
        base_resp.body = body.replace("</head>", RECAPTCHA_JS_SCRIPT + "</head>");
      } else {
        base_resp.body = streamReplace(body, "</head>", RECAPTCHA_JS_SCRIPT + "</head>");
      }
    }
    return Promise.resolve(base_resp);
  }

  async fetch_origin(req: EdgeRequest): Promise<EdgeResponse> {
    return this.fetch(req);
  }

  // Fetch the firewall lists.
  // TODO: Cache the firewall policies.
  // https://techdocs.akamai.com/api-definitions/docs/caching
  // https://techdocs.akamai.com/property-mgr/docs/caching-2#how-it-works
  async fetch_list_firewall_policies(req: EdgeRequest): Promise<EdgeResponse> {
    return this.fetch(req);
  }

  /**
   * Call fetch for CreateAssessment
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_create_assessment(req: EdgeRequest): Promise<EdgeResponse> {
    return this.fetch(req);
  }

  /**
   * Call fetch for getting the ChallengePage
   * @param path: the URL to fetch the challenge page from.
   * @param soz_base64: the base64 encoded soz.
   */
  async fetch_challenge_page(req: EdgeRequest): Promise<EdgeResponse> {
    return this.fetch(req);
  }
}

export function recaptchaConfigFromRequest(request: EW.ResponseProviderRequest): RecaptchaConfig {
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
    sessionJsInjectPath: request.getVariable("PMUSER_SESSION_JS_INSTALL_PATH"),
    strict_cookie: (request.getVariable("PMUSER_STRICTCOOKIE") ?? "true") === "true", // default to true
  };
}
