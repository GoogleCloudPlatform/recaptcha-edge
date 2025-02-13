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
 * @fileoverview reCAPTCHA Enterprise Library for Cloudflare Workers.
 */

type Env = any;

const RECAPTCHA_JS = "https://www.google.com/recaptcha/enterprise.js";
// Firewall Policies API is currently only available in the public preview.
const DEFAULT_RECAPTCHA_ENDPOINT = "https://public-preview-recaptchaenterprise.googleapis.com";

// eslint-disable-next-line  @typescript-eslint/no-unused-vars
import {
  processRequest,
  RecaptchaConfig,
  RecaptchaContext,
  EdgeRequest,
  EdgeResponse,
  FetchApiRequest,
  FetchApiResponse,
  EdgeResponseInit,
  UserInfo,
  Event,
} from "@google-cloud/recaptcha";
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

export class CloudflareContext extends RecaptchaContext {
  readonly sessionPageCookie = "recaptcha-cf-t";
  readonly challengePageCookie = "recaptcha-cf-e";
  readonly environment: [string, string] = [pkg.name, pkg.version];
  readonly httpGetCachingEnabled = true;
  start_time: number;
  performance_counters: Array<[string, number]> = [];

  constructor(
    private env: Env,
    private ctx: ExecutionContext,
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
      this.performance_counters.push([event, performance.now() - this.start_time]);
    }
  }

  // Get UserInfo from the default login event.
  async getUserInfo(req: EdgeRequest, accountIdField: string, usernameField: string): Promise<UserInfo> {
    const contentType = req.getHeader("content-type");
    let userInfo: UserInfo = { accountId: "", userIds: [] };
    if (contentType && contentType.includes("application/json")) {
      try {
        const body = (await (req as FetchApiRequest).req.clone().json()) as any;
        const accountId = body[accountIdField];
        const username = body[usernameField];

        if (accountId) {
          userInfo = {
            accountId,
            userIds: [{ username: username }],
          };
        }
      } catch (error) {
        console.error("Error parsing json when getting UserInfo:", error);
      }
    } else if (contentType && contentType.includes("application/x-www-form-urlencoded")) {
      try {
        const bodyText = (await (req as FetchApiRequest).req.clone().text()) as any;
        const formData = new URLSearchParams(bodyText);
        const accountId = formData.get(accountIdField);
        const username = formData.get(usernameField);

        if (accountId) {
          userInfo = {
            accountId,
            userIds: username ? [{ username }] : [],
          };
        }
      } catch (error) {
        console.error("Error parsing form data when getting UserInfo:", error);
      }
    }
    return userInfo;
  }

  async buildEvent(req: EdgeRequest): Promise<Event> {
    let base_req = (req as FetchApiRequest).asRequest();
    let userInfo: UserInfo | undefined = undefined;
    if (req.method === "POST" && new URL(req.url).pathname === this.config.credentialPath) {
      userInfo = await this.getUserInfo(req, this.config.accountId ?? "", this.config.username ?? "");
    }
    return {
      // extracting common signals
      userIpAddress: req.getHeader("CF-Connecting-IP") ?? undefined,
      headers: Array.from(req.getHeaders().entries()).map(([k, v]) => `${k}:${v}`),
      ja3: (base_req as any)?.["cf"]?.["bot_management"]?.["ja3_hash"] ?? undefined,
      requestedUri: req.url,
      userAgent: req.getHeader("user-agent") ?? undefined,
      userInfo,
    };
  }

  injectRecaptchaJs(resp: EdgeResponse): Promise<EdgeResponse> {
    let base = (resp as FetchApiResponse).asResponse();
    const sessionKey = this.config.sessionSiteKey ?? "";
    const recaptchaJsUrl = new URL(RECAPTCHA_JS);
    recaptchaJsUrl.searchParams.set("render", sessionKey);
    recaptchaJsUrl.searchParams.set("waf", "session");
    const RECAPTCHA_JS_SCRIPT = `<script src="${recaptchaJsUrl.toString()}" async defer></script>`;
    return Promise.resolve(
      new FetchApiResponse(
        new HTMLRewriter()
          .on("head", {
            element(element: any) {
              element.append(RECAPTCHA_JS_SCRIPT, { html: true });
            },
          })
          .transform((resp as FetchApiResponse).asResponse()),
      ),
    );
  }

  createRequest(url: string, options: any): EdgeRequest {
    return new FetchApiRequest(new Request(url, options));
  }

  createResponse(body: string, options?: EdgeResponseInit): EdgeResponse {
    return new FetchApiResponse(body, options);
  }

  async fetch(req: EdgeRequest, options?: RequestInit): Promise<EdgeResponse> {
    let base_req = (req as FetchApiRequest).asRequest();
    return fetch(base_req, options).then((v) => new FetchApiResponse(v));
  }

  async fetch_list_firewall_policies(req: EdgeRequest, options?: RequestInit): Promise<EdgeResponse> {
    return this.fetch(req, {
      ...options,
      cf: {
        cacheEverything: true,
        cacheTtlByStatus: { "200-299": 600, 404: 1, "500-599": 0 },
      },
    });
  }
}

export function recaptchaConfigFromEnv(env: Env): RecaptchaConfig {
  return {
    projectNumber: env.PROJECT_NUMBER,
    apiKey: env.API_KEY,
    actionSiteKey: env.ACTION_SITE_KEY,
    expressSiteKey: env.EXPRESS_SITE_KEY,
    sessionSiteKey: env.SESSION_SITE_KEY,
    challengePageSiteKey: env.CHALLENGE_PAGE_SITE_KEY,
    enterpriseSiteKey: env.ENTERPRISE_SITE_KEY,
    recaptchaEndpoint: env.RECAPTCHA_ENDPOINT ?? DEFAULT_RECAPTCHA_ENDPOINT,
    sessionJsInjectPath: env.SESSION_JS_INSTALL_PATH,
    credentialPath: env.CREDENTIAL_PATH,
    accountId: env.USER_ACCOUNT_ID,
    username: env.USERNAME,
    debug: env.DEBUG ?? false,
    unsafe_debug_dump_logs: env.UNSAFE_DEBUG_DUMP_LOGS ?? false,
  };
}
