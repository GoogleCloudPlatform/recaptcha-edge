/**
 * Copyright 2025 Google LLC
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

import { create } from "@bufbuild/protobuf";
import {
  RecaptchaConfig,
  RecaptchaContext,
  EdgeResponse,
  EdgeRequest,
  EdgeRequestInit,
  EdgeResponseInit,
  FetchApiResponse,
  FetchApiRequest,
  Event,
  LogLevel,
  Assessment,
  CHALLENGE_PAGE_URL,
  ListFirewallPoliciesResponse,
} from "@google-cloud/recaptcha-edge";
import pkg from "../package.json";
import {
  ProcessingResponseSchema,
  HttpHeaders,
  HeaderMutation,
  HeaderMutationSchema,
  HttpBody,
  CommonResponse_ResponseStatus,
  ProcessingResponse,
} from "../gen/envoy/service/ext_proc/v3/external_processor_pb.js";

import { StatusCode } from "../gen/envoy/type/v3/http_status_pb.js";
import { HeaderValueOption_HeaderAppendAction, HeaderValueOptionSchema } from "../gen/envoy/config/core/v3/base_pb.js";
import { Cache } from "memory-cache";

const RECAPTCHA_JS = "https://www.google.com/recaptcha/enterprise.js";

export class CalloutHeadersRequest implements EdgeRequest {
  ctx: RecaptchaContext;
  req?: HttpHeaders;
  resp: HeaderMutation;

  constructor(ctx: RecaptchaContext, req?: HttpHeaders) {
    this.ctx = ctx;
    this.req = req;
    this.resp = create(HeaderMutationSchema, {});
  }

  get url() {
    return `${this.getHeader(":scheme")}://${this.getHeader(":authority")}${this.getHeader(":path")}`;
  }

  set url(url: string) {
    this.ctx.log("error", "Unsupported: Setting a url on a callout headers request");
  }

  get method() {
    return this.getHeader(":method") || "";
  }

  addHeader(key: string, value: string) {
    this.resp.setHeaders.push(
      create(HeaderValueOptionSchema, {
        header: {
          key: key,
          rawValue: new TextEncoder().encode(value),
        },
        appendAction: HeaderValueOption_HeaderAppendAction.ADD_IF_ABSENT,
      }),
    );
  }

  getHeader(key: string): string | null {
    const trimmedSearchKey = key.toLowerCase().trim();
    const headerRawValue = this.req?.headers?.headers.find(
      (h) => h.key.toLowerCase().trim() === trimmedSearchKey,
    )?.rawValue;

    if (headerRawValue === null) {
      return null;
    }
    return new TextDecoder().decode(headerRawValue);
  }

  getHeaders(): Map<string, string> {
    const map = new Map<string, string>();
    this.req?.headers?.headers.forEach((h) => map.set(h.key, new TextDecoder().decode(h.rawValue)));
    return map;
  }

  getBodyText(): Promise<string> {
    return Promise.resolve("");
  }

  getBodyJson(): Promise<any> {
    return Promise.resolve(JSON.parse("{}"));
  }

  toResponse(): ProcessingResponse {
    return create(ProcessingResponseSchema, {
      response: {
        case: "requestHeaders",
        value: {
          response: {
            headerMutation: this.resp,
            status: CommonResponse_ResponseStatus.CONTINUE,
          },
        },
      },
    });
  }
}

export class CalloutBodyResponse implements EdgeResponse {
  ctx: RecaptchaContext;
  httpBody: HttpBody;
  newBody?: string;

  constructor(ctx: RecaptchaContext, body: HttpBody) {
    this.ctx = ctx;
    this.httpBody = body;
  }

  get status() {
    return 200;
  }

  addHeader(key: string, value: string) {}

  getHeader(key: string): string | null {
    return null;
  }

  getHeaders(): Map<string, string> {
    return new Map<string, string>();
  }

  text(): Promise<string> {
    return Promise.resolve(this.body as string);
  }

  json(): Promise<unknown> {
    return Promise.resolve(JSON.parse(this.body as string));
  }

  get body(): string {
    if (this.newBody === undefined) {
      return new TextDecoder().decode(this.httpBody.body);
    }
    return this.newBody;
  }

  set body(newBody: string) {
    this.newBody = newBody;
  }

  toResponse(): ProcessingResponse {
    if (this.newBody === undefined) {
      return create(ProcessingResponseSchema, {
        response: {
          case: "responseBody",
          value: {},
        },
      });
    }
    return create(ProcessingResponseSchema, {
      response: {
        case: "responseBody",
        value: {
          response: {
            bodyMutation: {
              mutation: {
                case: "body",
                value: new TextEncoder().encode(this.newBody),
              },
            },
          },
        },
      },
    });
  }
}

export class ImmediateResponse implements EdgeResponse {
  bodyStr: string;
  headerMutation: HeaderMutation;
  options?: EdgeResponseInit;
  decoder = new TextDecoder();
  encoder = new TextEncoder();

  constructor(body: string, options?: EdgeResponseInit) {
    this.bodyStr = body;
    this.options = options;
    this.headerMutation = create(HeaderMutationSchema, {});
  }

  get status() {
    return this.options?.status || 200;
  }

  addHeader(key: string, value: string) {
    this.headerMutation.setHeaders.push(
      create(HeaderValueOptionSchema, {
        header: {
          key: key,
          rawValue: new TextEncoder().encode(value),
        },
        appendAction: HeaderValueOption_HeaderAppendAction.OVERWRITE_IF_EXISTS_OR_ADD,
      }),
    );
  }

  getHeader(key: string): string | null {
    return this.getHeaders().get(key) || null;
  }

  getHeaders(): Map<string, string> {
    const result = new Map<string, string>();
    this.headerMutation.setHeaders.forEach((h) => {
      if (h.header !== undefined) {
        result.set(h.header.key, h.header.value);
      }
    });
    return result;
  }

  text(): Promise<string> {
    return Promise.resolve(this.bodyStr);
  }

  json(): Promise<unknown> {
    return Promise.resolve(JSON.parse(this.bodyStr));
  }

  toResponse(): ProcessingResponse {
    return create(ProcessingResponseSchema, {
      response: {
        case: "immediateResponse",
        value: {
          status: {
            code: this.status as StatusCode,
          },
          body: this.bodyStr,
          headers: this.headerMutation,
        },
      },
    });
  }
}

export class XlbContext extends RecaptchaContext {
  readonly sessionPageCookie = "recaptcha-gxlb-t";
  readonly challengePageCookie = "recaptcha-gxlb-e";
  readonly httpGetCachingEnabled = true;
  readonly environment: [string, string] = [pkg.name, pkg.version];
  readonly cache: Cache = new Cache();

  constructor(cfg: RecaptchaConfig) {
    super(cfg);
  }

  createResponse(body: string, options?: EdgeResponseInit): EdgeResponse {
    return new ImmediateResponse(body, options);
  }

  async fetch(req: EdgeRequest, options?: EdgeRequestInit): Promise<EdgeResponse> {
    let base_req = req as FetchApiRequest;
    let resp = await fetch(base_req.asRequest(), options);
    return new FetchApiResponse(resp);
  }

  async fetch_list_firewall_policies(options: EdgeRequestInit): Promise<ListFirewallPoliciesResponse> {
    let policies = this.cache.get("firewallPolicies");
    if (policies === null) {
      this.log("debug", "Cache miss: fetch_list_firewall_policies");
      let fp = await this.fetch(new FetchApiRequest(new Request(this.listFirewallPoliciesUrl, options)));
      policies = this.toListFirewallPoliciesResponse(fp);
      this.cache.put("firewallPolicies", policies, 600000 /* 10 min */);
    } else {
      this.log("debug", "Cache hit: fetch_list_firewall_policies");
    }
    return policies;
  }

  async fetch_create_assessment(options: EdgeRequestInit): Promise<Assessment> {
    const resp = await this.fetch(new FetchApiRequest(new Request(this.assessmentUrl, options)));
    return this.toAssessment(resp);
  }

  async fetch_challenge_page(options: EdgeRequestInit): Promise<EdgeResponse> {
    const resp = await this.fetch(
      new FetchApiRequest(new Request(this.config.challengePageUrl || CHALLENGE_PAGE_URL, options)),
    );
    const text = await resp.text();
    const newResp = new ImmediateResponse(text, { status: resp.status });
    resp.getHeaders().forEach((v, k) => newResp.addHeader(k, v));
    return newResp;
  }

  async buildEvent(req: EdgeRequest): Promise<Event> {
    return {
      userIpAddress: this.getUserIp(req),
      headers: Array.from(req.getHeaders().entries()).map(([k, v]) => `${k}:${v}`),
      ja3: undefined,
      requestedUri: req.url,
      userAgent: req.getHeader("user-agent") ?? undefined,
    };
  }

  injectRecaptchaJs(resp: EdgeResponse): Promise<EdgeResponse> {
    const sessionKey = this.config.sessionSiteKey;
    if (sessionKey === undefined || sessionKey === "") {
      return Promise.resolve(resp);
    }
    const recaptchaJsScript = `<script src="${RECAPTCHA_JS}?render=${sessionKey}&waf=session" async defer></script>`;
    const calloutResp = resp as CalloutBodyResponse;
    calloutResp.body = calloutResp.body.replace("</head>", recaptchaJsScript + "</head>");
    return Promise.resolve(resp);
  }

  getUserIp(req: EdgeRequest): string | undefined {
    // The xlb will append to the x-forwarded-for header both the ip of the connected
    // client and the ip of the destination server in this order. We want to extract the
    // client ip so it will be the second last in the list.
    const forwardedArr = (req.getHeader("X-Forwarded-For") || "").split(",");
    if (forwardedArr.length == 0) {
      return undefined;
    }
    const clientIpIdx = Math.max(forwardedArr.length - 2, 0);
    return forwardedArr[clientIpIdx].trim();
  }

  logException(e: any) {
    console.error("Exception: ", e);
  }

  log_performance_debug(event: any): void {
    console.debug("Performance: ", event);
  }

  log(level: LogLevel, msg: string) {
    switch (level) {
      case "debug":
        console.debug(msg);
        break;
      case "info":
        console.info(msg);
        break;
      case "warning":
        console.warn(msg);
        break;
      case "error":
        console.error(msg);
        break;
      default:
        console.error(msg);
        break;
    }
  }
}
