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
} from "@google-cloud/recaptcha";
import pkg from "../../../package.json";
import {
  ProcessingResponseSchema,
  HttpHeaders,
  HeaderMutation,
  HeaderMutationSchema,
  HttpBody,
  CommonResponse_ResponseStatus,
} from "../gen/envoy/service/ext_proc/v3/external_processor_pb.js";

import { StatusCode } from "../gen/envoy/type/v3/http_status_pb.js";
import { HeaderValueOption_HeaderAppendAction, HeaderValueOptionSchema } from "../gen/envoy/config/core/v3/base_pb.js";
import * as cache from "memory-cache";
import { ListFirewallPoliciesResponse } from "../../../src/index.js";

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
    return `${this.getHeader(":scheme")}://${this.getHeader(":host")}/${this.getHeader(":path")}`;
  }

  set url(url: string) {
    this.ctx.log("error", "Unsupported: Setting a url on a callout headers request");
  }

  get method() {
    return this.getHeader(":method");
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

  toResponse() {
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
  newBody: string;

  constructor(ctx: RecaptchaContext, body: HttpBody) {
    this.ctx = ctx;
    this.httpBody = body;
  }

  get status() {
    return null;
  }

  addHeader(key: string, value: string) {}

  getHeader(key: string): string | null {
    return null;
  }

  getHeaders(): Map<string, string> {
    return new Map<string, string>();
  }

  get text(): Promise<string> {
    return Promise.resolve(this.body as string);
  }

  get json(): Promise<unknown> {
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

  toResponse() {
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
  decoder: TextDecoder = new TextDecoder();
  encoder: TextEncoder = new TextEncoder();

  constructor(body: string, options?: EdgeResponseInit) {
    this.bodyStr = body;
    this.options = options;
    this.headerMutation = create(HeaderMutationSchema, {});
    options.headers?.forEach((v, k, m) => this.addHeader(k, v));
  }

  get status() {
    return this.options?.status;
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

  get text(): Promise<string> {
    return Promise.resolve(this.bodyStr);
  }

  get json(): Promise<unknown> {
    return Promise.resolve(JSON.parse(this.bodyStr));
  }

  toResponse() {
    return create(ProcessingResponseSchema, {
      response: {
        case: "immediateResponse",
        value: {
          status: {
            code: this.options.status as StatusCode,
          },
          body: this.bodyStr,
          headers: this.headerMutation,
        },
      },
    });
  }
}

export class Context extends RecaptchaContext {
  readonly sessionPageCookie = "recaptcha-gxlb-t";
  readonly challengePageCookie = "recaptcha-gxlb-e";
  readonly httpGetCachingEnabled = true;
  readonly environment: [string, string] = [pkg.name, pkg.version];

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
    let policies = cache.get("firewallPolicies");
    if (policies === null) {
      this.log("debug", "Cache miss: fetch_list_firewall_policies");
      let fp = await this.fetch(new FetchApiRequest(new Request(this.listFirewallPoliciesUrl, options)));
      policies = this.toListFirewallPoliciesResponse(fp);
      cache.put("firewallPolicies", policies, 600000 /* 10 min */);
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
    return new ImmediateResponse(text, { status: resp.status, headers: resp.getHeaders() });
  }

  async buildEvent(req: EdgeRequest): Promise<Event> {
    const forwardedArr = req.getHeader("X-Forwarded-For").split(",");
    return {
      userIpAddress: forwardedArr[0],
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
    resp.body = (resp.body as string).replace("</head>", recaptchaJsScript + "</head>");
    return Promise.resolve(resp);
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
