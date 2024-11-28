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

export {
  AllowAction,
  AllowActionSchema,
  BlockAction,
  BlockActionSchema,
  InjectJsAction,
  InjectJsActionSchema,
  RedirectAction,
  RedirectActionSchema,
  SetHeaderAction,
  SetHeaderActionSchema,
  SubstituteAction,
  SubstituteActionSchema,
} from "./action";

export {
  Assessment,
  AssessmentSchema,
  Event,
  EventSchema,
  FirewallPolicy,
  FirewallPolicySchema,
} from "./assessment";

export {
  callCreateAssessment,
  createPartialEventWithSiteInfo,
} from "./createAssessment";

export {
  ListFirewallPoliciesResponse,
  ListFirewallPoliciesResponseSchema,
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
  sessionJsInjectPath?: string;
  recaptchaEndpoint: string;
  debug?: boolean;
  strict_cookie?: boolean;
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
  readonly environment: [string, string] = [
    "[npm] @google-cloud/recaptcha",
    "",
  ];
  abstract readonly httpGetCachingEnabled: boolean;
  abstract readonly sessionPageCookie: string;
  abstract readonly challengePageCookie: string;

  constructor(config: RecaptchaConfig) {
    this.config = config;
  }

  async fetch(req: RequestInfo, options?: RequestInit): Promise<Response> {
    return fetch(req, options);
  }

  /**
   * Fetch from the customer's origin.
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_origin(
    req: RequestInfo,
    options?: RequestInit,
  ): Promise<Response> {
    return this.fetch(req, options);
  }

  /**
   * Call fetch for ListFirewallPolicies.
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_list_firewall_policies(
    req: RequestInfo,
    options?: RequestInit,
  ): Promise<Response> {
    return this.fetch(req, options);
  }

  /**
   * Call fetch for CreateAssessment
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_create_assessment(
    req: RequestInfo,
    options?: RequestInit,
  ): Promise<Response> {
    return this.fetch(req, options);
  }

  /**
   * Call fetch for getting the ChallengePage
   * Parameters and outputs are the same as the 'fetch' function.
   */
  async fetch_challenge_page(
    req: RequestInfo,
    options?: RequestInit,
  ): Promise<Response> {
    return this.fetch(req, options);
  }

  /**
   * Log performance debug information.
   *
   * This should be implemnented on a per-WAF basis. The default implementation
   * does nothing. This method should conditionally log performance only if the
   * config.debug flag is set to true.
   */
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

  abstract buildEvent(req: Request): any;
  abstract injectRecaptchaJs(resp: Response): Promise<Response>;
}
