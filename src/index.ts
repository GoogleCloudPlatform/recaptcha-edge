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
 * @fileoverview reCAPTCHA Enterprise TypeScript Library.
 */
export { InitError, NetworkError, ParseError, RecaptchaError } from "./error";
export { AllowAction, BlockAction, InjectJsAction, RedirectAction, SetHeaderAction, SubstituteAction } from "./action";

export { Assessment, Event, FirewallPolicy, UserInfo } from "./assessment";

import { Event } from "./assessment";

export { callCreateAssessment, createPartialEventWithSiteInfo } from "./createAssessment";

export { FetchApiRequest, FetchApiResponse } from "./fetchApi";

export {
  ListFirewallPoliciesResponse,
  callListFirewallPolicies,
} from "./listFirewallPolicies";

export {
  applyActions,
  evaluatePolicyAssessment,
  localPolicyAssessment,
  policyConditionMatch,
  policyPathMatch,
  processRequest,
} from "./policy";

export type EdgeRequestInit = {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
};

export interface EdgeRequest {
  readonly method: string;
  url: string;
  addHeader(key: string, value: string): void;
  getHeader(key: string): string | null;
  getHeaders(): Map<string, string>;
  getBodyText(): Promise<string>;
  getBodyJson(): Promise<any>;
}
export type EdgeResponseInit = {
  readonly status?: number;
  readonly headers?: Record<string, string>;
};

export interface EdgeResponse {
  text(): Promise<string>;
  json(): Promise<unknown>;
  addHeader(key: string, value: string): void;
  getHeader(key: string): string | null;
  getHeaders(): Map<string, string>;
  readonly status: number;
}

/**
 * reCAPTCHA Enterprise configuration.
 */
export interface RecaptchaConfig {
  projectNumber: number;
  apiKey: string;
  actionSiteKey?: string;
  expressSiteKey?: string;
  sessionSiteKey?: string;
  challengePageSiteKey?: string;
  enterpriseSiteKey?: string;
  sessionJsInjectPath?: string;
  recaptchaEndpoint: string;
  debug?: boolean;
  unsafe_debug_dump_logs?: boolean;
  strict_cookie?: boolean;
  credentialPath?: string;
  accountId?: string;
  username?: string;
}

export class DebugTrace {
  exception_count?: number;
  list_firewall_policies_status?: "ok" | "err";
  create_assessment_status?: "ok" | "err";
  _list_firewall_policies_headers?: Map<string, string>;
  _create_assessment_headers?: Map<string, string>;
  policy_count?: number;
  policy_match?: boolean;
  inject_js_match?: boolean;
  site_key_used?: "action" | "session" | "challenge" | "express" | "none" | "enterprise";
  site_keys_present?: string;
  version?: string;
  empty_config?: string;
  performance_counters: Array<[string, number]> = [];

  constructor(context: RecaptchaContext) {
    this.site_keys_present = "";
    if (context.config.actionSiteKey?.trim()) {
      this.site_keys_present += "a";
    }
    if (context.config.sessionSiteKey?.trim()) {
      this.site_keys_present += "s";
    }
    if (context.config.challengePageSiteKey?.trim()) {
      this.site_keys_present += "c";
    }
    if (context.config.expressSiteKey?.trim()) {
      this.site_keys_present += "e";
    }
    const empty = [];
    if (!context.config.apiKey.trim()) {
      empty.push("apikey");
    }
    if (!context.config.projectNumber) {
      empty.push("project");
    }
    if (!context.config.recaptchaEndpoint) {
      empty.push("endpoint");
    }
    if (!this.site_keys_present) {
      empty.push("sitekeys");
    }
    if (empty.length > 0) {
      this.empty_config = empty.join(",");
    }
    this.version = context.environment[1];
  }

  /**
   * Creates a Header value from an object, used for debug data.
   * @param data an Object with string,number,boolean values.
   * @returns a string in the format k1=v1;k2=v2
   */
  formatAsHeaderValue(): string {
    const parts: string[] = [];
    for (const key of Object.keys(this)) {
      // Iterate over property names
      const value = this[key as keyof this]; // Access value using key and type assertion

      if (value && !key.startsWith("_")) {
        parts.push(`${key}=${value}`);
      }
    }

    return parts.join(";");
  }
}

export type LogLevel = "debug" | "info" | "warning" | "error";
/**
 * reCAPTCHA Enterprise context.
 * This context provides an abstraction layer per-WAF, and a subclass
 * should be created for each platform.
 */
export abstract class RecaptchaContext {
  config: RecaptchaConfig;
  exceptions: any[] = [];
  log_messages: Array<[LogLevel, string[]]> = [];
  debug_trace: DebugTrace;
  readonly environment: [string, string] = ["[npm] @google-cloud/recaptcha", ""];
  abstract readonly sessionPageCookie: string;
  abstract readonly challengePageCookie: string;

  constructor(config: RecaptchaConfig) {
    this.config = config;
    this.debug_trace = new DebugTrace(this);
  }

  abstract createRequest(url: string, options: EdgeRequestInit): EdgeRequest;
  abstract createResponse(body: string, options?: EdgeResponseInit): EdgeResponse;
  encodeString(st: string): Uint8Array {
    return new TextEncoder().encode(st);
  }
  abstract fetch(req: EdgeRequest): Promise<EdgeResponse>;

  /**
   * Fetch from the customer's origin.
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_origin(req: EdgeRequest): Promise<EdgeResponse> {
    return this.fetch(req);
  }

  /**
   * Call fetch for ListFirewallPolicies.
   * Parameters and outputs are the same as the 'fetch' function.
   */
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

  /**
   * Log performance debug information.
   *
   * This should be implemnented on a per-WAF basis. The default implementation
   * does nothing. This method should conditionally log performance only if the
   * config.debug flag is set to true.
   */
  // eslint-disable-next-line  @typescript-eslint/no-unused-vars
  log_performance_debug(event: string) {}

  /**
   * Log an exception.
   *
   * The default behavior is to store the exception in a list.
   * While debugging, this list can be checked after processing the request.
   * WAF-specific implementations may override this behavior to provide more
   * useful logging.
   */
  logException(e: any) {
    this.exceptions.push(e);
  }

  /**
   * Log a message.
   *
   * The default behavior is to store the message in a list.
   * While debugging, this list can be checked after processing the request.
   * WAF-specific implementations may override this behavior to provide more
   * useful logging.
   */
  log(level: LogLevel, msg: string) {
    this.log_messages.push([level, [msg]]);
  }

  abstract buildEvent(req: EdgeRequest): Promise<Event>;
  abstract injectRecaptchaJs(resp: EdgeResponse): Promise<EdgeResponse>;
}
