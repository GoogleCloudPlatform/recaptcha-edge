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
  EdgeRequestInfo,
  EdgeResponse,
  LogLevel,
  EdgeResponseInit,
} from "@google-cloud/recaptcha";
import { HtmlRewritingStream } from "html-rewriter";
import { httpRequest, HttpResponse } from "http-request";
import { logger } from "log";
import { ReadableStream } from "streams";
import pkg from "../package.json";

function isHeaderRecord(obj: unknown): obj is Record<string, string | string[]> {
  return true;
}

function headersGuard(
  headers: Record<string, string | readonly string[]> | string[][] | object | undefined,
): Record<string, string | string[]> {
  if (headers === undefined) {
    return {};
  }

  // We have string[][]
  if (Array.isArray(headers)) {
    const headerMap: Record<string, string | string[]> = {};

    headers.forEach(([key, ...values]) => {
      headerMap[key] = values.length === 1 ? values[0] : values;
    });

    return headerMap;
  }

  const headerMap: Record<string, string | string[]> = {};
  if (isHeaderRecord(headers)) {
    // We have Record<string, string | readonly string[]>
    // remove readonly attribute
    for (const key in headers) {
      const value = headers[key];
      headerMap[key] = value.length === 1 ? value[0] : [...value];
    }
  } else {
    throw "Invalid header";
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

function relativePath(req: EdgeRequestInfo): string {
  let s;
  if (typeof req === "string") {
    let noprotocol = req.replace(/.*:\/\//, "");
    let path_index = noprotocol.indexOf("/");
    if (path_index < 0) {
      path_index = 0;
    }
    return noprotocol.slice(path_index);
  }
  return req.url; // the .url property is already relative in Akamai requests.
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

export class AkamaiRequest implements EdgeRequest {
  req: EW.ResponseProviderRequest;
  override_path: string;
  headers: Map<string, string>;

  constructor(req: EW.ResponseProviderRequest) {
    this.req = req;
    this.override_path = `${this.req.host}/${this.req.path}`;
    this.headers = new Map();
    let headers = req.getHeaders();
    for (const [key, value] of Object.entries(headers)) {
      this.headers.set(key, value.join(","));
    }
  }

  get url() {
    return this.override_path ?? `${this.req.host}/${this.req.path}`;
  }

  set url(url: string) {
    this.override_path = url;
  }

  get method() {
    return this.req.method;
  }

  addHeader(key: string, value: string): void {
    this.headers.set(key, value);
  }

  getHeader(key: string): string | null {
    return this.headers.get(key) ?? null;
  }

  getHeaders(): Map<string, string> {
    return this.headers;
  }

  getBodyText(): Promise<string> {
    throw "unimplemented";
  }
  getBodyJson(): Promise<any> {
    throw "unimplemented";
  }
}

export class AkamaiResponse implements EdgeResponse {
  resp?: HttpResponse;
  _body?: string;
  _status: number;
  headers: Map<string, string[]>;

  constructor(base: string | HttpResponse, status?: number, headers?: Record<string, string>) {
    if (typeof base === "string") {
      this._body = base;
      this._status = status ?? 200;
      this.headers = new Map();
      for (const [key, value] of Object.entries(headers ?? {})) {
        if (Array.isArray(value)) {
          this.headers.set(key, value);
        } else {
          this.headers.set(key, [value]);
        }
      }
    } else {
      // base type is HttpResponse
      this.resp = base;
      this._status = status ?? base.status;
      this.headers = new Map();
      let rh = base.getHeaders();
      for (const key in rh) {
        this.headers.set(key, rh[key]);
      }
    }
  }

  get status(): number {
    return this._status;
  }

  get body(): ReadableStream<any> | string {
    return this.resp?.body ?? this._body ?? "";
  }

  text(): Promise<string> {
    return this.resp?.text() ?? Promise.resolve(this._body ?? "");
  }

  json(): Promise<unknown> {
    return this.resp?.json() ?? Promise.resolve(JSON.parse(this._body ?? "{}"));
  }

  addHeader(key: string, value: string): void {
    let v = this.headers.get(key) ?? [];
    v.push(value);
    this.headers.set(key, v);
  }

  getHeader(key: string): string | null {
    return this.headers.get(key)?.join(",") ?? null;
  }

  getHeaders(): Map<string, string> {
    let ret = new Map();
    for (const [k, v] of this.headers.entries()) {
      ret.set(k, v.join(","));
    }
    return ret;
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
      userIpAddress: req.getHeader("True-Client-IP"),
      headers: Array.from(req.getHeaders()).map(([k, v]) => `${k}:${v}`),
      ja3: (req as any)?.akamai?.bot_management?.ja3_hash ?? undefined,
      requestedUri: req.url,
      userAgent: req.getHeader("user-agent"),
    };
  }

  async fetch(req: EdgeRequestInfo, options?: RequestInit): Promise<EdgeResponse> {
    // Convert RequestInfo to string if it's not already
    return httpRequest(relativePath(req), {
      method: options?.method ?? undefined,
      headers: headersGuard(options?.headers),
      body: bodyGuard(options?.body ?? null),
      /* there is no timeout in a Fetch API request. Consider making it a member of the Context */
    }).then((v) => new AkamaiResponse(v));
  }

  createResponse(body: string, options?: EdgeResponseInit): EdgeResponse {
    return new AkamaiResponse(body, options?.status, options?.headers);
  }

  getSafeResponseHeaders(headers: any) {
    for (const [headerKey] of Object.entries(headers)) {
      if (UNSAFE_RESPONSE_HEADERS.has(headerKey)) {
        headers.delete(headerKey);
      }
    }

    return headers;
  }

  injectRecaptchaJs(resp: EdgeResponse): Promise<EdgeResponse> {
    throw new Error("JavaScript Injection is not yet implemented on Akamai.");
  }

  async fetch_origin(req: EdgeRequestInfo, options?: RequestInit): Promise<EdgeResponse> {
    return httpRequest(relativePath(req), {
      method: options?.method ?? undefined,
      headers: headersGuard(options?.headers),
      body: bodyGuard(options?.body ?? null),
      /* there is no timeout in a Fetch API request. Consider making it a member of the Context */
    }).then((v) => new AkamaiResponse(v));
  }

  // Fetch the firewall lists.
  // TODO: Cache the firewall policies.
  // https://techdocs.akamai.com/api-definitions/docs/caching
  // https://techdocs.akamai.com/property-mgr/docs/caching-2#how-it-works
  async fetch_list_firewall_policies(req: EdgeRequestInfo, options?: RequestInit): Promise<EdgeResponse> {
    return this.fetch(relativePath(req), options);
  }

  /**
   * Call fetch for CreateAssessment
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_create_assessment(req: EdgeRequestInfo, options?: RequestInit): Promise<EdgeResponse> {
    return this.fetch(relativePath(req), options);
  }

  /**
   * Call fetch for getting the ChallengePage
   * @param path: the URL to fetch the challenge page from.
   * @param soz_base64: the base64 encoded soz.
   */
  async fetch_challenge_page(path: string, soz_base64: string): Promise<EdgeResponse> {
    return this.fetch(relativePath(path), {
      method: "POST",
      headers: {
        "content-type": "application/json;charset=UTF-8",
        "X-ReCaptcha-Soz": soz_base64,
      },
    });
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
  };
}
