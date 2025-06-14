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
 * @fileoverview Client functions related to FirewallPolicies.
 */

import picomatch from "picomatch";
import * as action from "./action";
import { FirewallPolicy } from "./assessment";
import { callCreateAssessment } from "./createAssessment";
import * as error from "./error";
import { RecaptchaContext, EdgeRequest, EdgeResponse, ListFirewallPoliciesResponse } from "./index";
import { createSoz } from "./soz";
import URL from "url-parse";
import {
  isBlockAction,
  isInjectJsAction,
  isRedirectAction,
  isRequestNonTerminalAction,
  isResponseNonTerminalAction,
  isSetHeaderAction,
  isSubstituteAction,
  isTerminalAction,
} from "./action";

type LocalAssessment = action.Action[] | "recaptcha-required";

/**
 * Path to the hosted reCAPTCHA Enterprise Javascript.
 * This path may be injected into the response.
 */
export const RECAPTCHA_JS = "https://www.google.com/recaptcha/enterprise.js";

/**
 * Checks whether a particular policy path pattern matches the incoming request.
 */
export function policyPathMatch(req: EdgeRequest, policy: FirewallPolicy): boolean {
  const url = new URL(req.url);
  if (!policy.path) {
    return true;
  }
  return picomatch.isMatch(url.pathname, policy.path);
}

/**
 * Checks whether a particular incoming request matching a set of glob path patterns.
 * An empty string is considered a 'wildcard' and matches all paths.
 * @param req the incoming request to match against
 * @param patterns the path glob pattern(s) to try matching
 * @param method (optional) A HTTP method (GET, POST,...) to check against the request
 * @returns true if any path pattern (and method) matches the request.
 */
export function pathMatch(req: EdgeRequest, patterns: [string] | string, method?: string): boolean {
  if(method && method != req.method) {
    return false;
  }
  const url = new URL(req.url);
  if (typeof patterns === "string") {
    patterns = [patterns];
  }
  for (const pattern of patterns) {
    if (!pattern || picomatch.isMatch(url.pathname, pattern)) {
      return true;
    }
  }
  return false;
}


/**
 * Evaluate the condition of a policy locally, to the best of our ability.
 *
 * @return true if the condition matches, false if it doesn't match, or
 * 'unknown' if we can't evaluate the condition locally.
 */
// eslint-disable-next-line  @typescript-eslint/no-unused-vars
export function policyConditionMatch(req: EdgeRequest, policy: FirewallPolicy): boolean | "unknown" {
  // An empty condition imples 'true' and always matches.
  if (!policy?.condition?.trim()) {
    return true;
  }
  const condition = policy.condition.toLowerCase();
  // A 'true' condition always matches.
  if (condition === "true") {
    return true;
  }
  // A 'false' condition doesn't make sense, but some customers might use it
  // to temporarily disable a policy.
  if (condition === "false") {
    return false;
  }
  // TODO: handle non-recaptcha-namespace conditions like IP only.
  return "unknown";
}

/**
 * Call the reCAPTCHA API to list firewall policies.
 */
export async function callListFirewallPolicies(context: RecaptchaContext): Promise<ListFirewallPoliciesResponse> {
  const options = {
    method: "GET",
    headers: {
      "content-type": "application/json;charset=UTF-8",
    },
  };
  return context.fetch_list_firewall_policies(options).catch((reason) => {
    context.debug_trace.list_firewall_policies_status = "err";
    context.log("debug", "[rpc] listFirewallPolicies (fail)");
    if (reason instanceof error.RecaptchaError) {
      throw reason;
    }
    throw new error.NetworkError(reason.message);
  });
}

/**
 * Check if a request can be locally accessed,
 * with amortized caching of policies.
 */
export async function localPolicyAssessment(context: RecaptchaContext, req: EdgeRequest): Promise<LocalAssessment> {
  // Optimization to inspect a cached copy of the firewall policies if HTTP caching is enabled.
  let resp;
  try {
    context.log_performance_debug("[rpc] callListFirewallPolicies - start");
    resp = await callListFirewallPolicies(context);
    context.log_performance_debug("[rpc] callListFirewallPolicies - end");
  } catch (reason) {
    context.logException(reason);
    return "recaptcha-required";
  }
  const policies = resp.firewallPolicies ?? [];
  for (const policy of policies) {
    if (policyPathMatch(req, policy)) {
      const conditionMatch = policyConditionMatch(req, policy);
      if (conditionMatch === "unknown") {
        return "recaptcha-required";
      } else if (conditionMatch) {
        // TODO: handle multiple policies.
        context.log_performance_debug("conditionMatch");
        context.log("debug", "local assessment condition matched");
        return policy?.actions ?? [];
      }
    }
  }
  context.log_performance_debug("no conditionMatch");
  // No policies were found to match in the cache. This default to 'allow'.
  return [action.createAllowAction()];
}

/**
 * Evaluate the policy assessment for a request.
 */
export async function evaluatePolicyAssessment(context: RecaptchaContext, req: EdgeRequest): Promise<action.Action[]> {
  let assessment;
  try {
    context.log_performance_debug("[rpc] callCreateAssessment - start");
    assessment = await callCreateAssessment(context, req, {
      firewallPolicyEvaluation: true,
    },  context.environment);
    context.log_performance_debug("[rpc] callCreateAssessment - end");
  } catch (reason) {
    if (reason instanceof error.RecaptchaError) {
      if (reason.recommendedAction) {
        context.logException(reason);
        return [reason.recommendedAction];
      }
    }
    /* v8 ignore next */
    throw reason;
  }
  return assessment?.firewallPolicyAssessment?.firewallPolicy?.actions ?? [];
}

/**
 * Apply pre-request actions. If a terminal action is applied it will generate a response
 * which will be returned. Non terminal actions will modify the request and return null;
 */
export async function applyPreRequestActions(
  context: RecaptchaContext,
  req: EdgeRequest,
  actions: action.Action[],
): Promise<EdgeResponse | null> {
  let terminalAction: action.Action = action.createAllowAction();
  const reqNonterminalActions: action.RequestNonTerminalAction[] = [];

  for (const action of actions) {
    if (isTerminalAction(action)) {
      terminalAction = action;
    } else if (isRequestNonTerminalAction(action)) {
      reqNonterminalActions.push(action);
    } else if (isResponseNonTerminalAction(action)) {
      context.log("debug", "Applying request actions, ignoring response actions");
    } else {
      /* v8 ignore next */
      throw new Error("Unsupported action: " + action);
    }
  }
  if (isBlockAction(terminalAction)) {
    context.log("debug", "terminalAction: block");
    return context.createResponse("", { status: 403 }); // TODO: custom html
  }

  if (isRedirectAction(terminalAction)) {
    context.log("debug", "terminalAction: redirect");
    // TODO: consider caching event.
    const event = await context.buildEvent(req);
    const url = new URL(req.url);
    if (!context.config.challengePageSiteKey) {
      context.log("error", "[!] attempt to redirect without challenge page site key!");
    }
    const soz = createSoz(
      context,
      url.hostname,
      event.userIpAddress ?? "",
      context.config.projectNumber,
      context.config.challengePageSiteKey ?? "", // TODO: default site key?
    );
    const reqOptions = {
      method: "POST",
      headers: {
        "content-type": "application/json;charset=UTF-8",
        "X-ReCaptcha-Soz": soz,
      },
    };
    return context.fetch_challenge_page(reqOptions);
  }

  // Handle Pre-Request actions.
  for (const action of reqNonterminalActions) {
    context.log("debug", "reqNonterminal action: setHeader");
    if (isSetHeaderAction(action)) {
      req.addHeader(action.setHeader.key ?? "", action.setHeader.value ?? "");
    } else if (isSubstituteAction(action)) {
      context.log("debug", "reqNonterminal action: substitute");
      const url = new URL(req.url);
      req.url = `${url.origin}${action.substitute.path}`;
    } else {
      /* v8 ignore next 2 lines */
      throw new Error("Unsupported pre-request action: " + action);
    }
  }

  context.log("debug", "terminalAction: allow");
  return null;
}

/**
 * Apply post response actions. Returns a (possibly modified) response.
 */
export async function applyPostResponseActions(
  context: RecaptchaContext,
  resp: EdgeResponse,
  actions: action.Action[],
): Promise<EdgeResponse> {
  const respNonterminalActions: action.ResponseNonTerminalAction[] = [];
  for (const action of actions) {
    if (isTerminalAction(action) || isRequestNonTerminalAction(action)) {
      context.log("debug", "Applying response actions, ignoring request action");
    } else if (isResponseNonTerminalAction(action)) {
      respNonterminalActions.push(action);
    } else {
      /* v8 ignore next */
      throw new Error("Unsupported action: " + action);
    }
  }

  // Handle Post-Response actions.
  let modifiedResp = resp;
  const once = new Set<string>();
  for (const action of respNonterminalActions) {
    if (isInjectJsAction(action)) {
      if (once.has("injectjs")) {
        continue; // TODO: should this throw an error?
      }
      once.add("injectjs");
      context.log("debug", "respNonterminal action: injectjs");
      context.log_performance_debug("[func] injectJS - start");
      modifiedResp = await context.injectRecaptchaJs(resp);
      // If 'debug' is enabled, await the response to get reasonable performance metrics.
      if (context.config.debug) {
        modifiedResp = await Promise.resolve(resp);
      }
      context.log_performance_debug("[func] injectJS - end");
    } else {
      throw new Error("Unsupported post-response action: " + action);
    }
  }
  return modifiedResp;
}

/**
 * Apply actions to a request.
 */
export async function applyActions(
  context: RecaptchaContext,
  req: EdgeRequest,
  actions: action.Action[],
): Promise<EdgeResponse> {
  const response = await applyPreRequestActions(context, req, actions);
  if (response !== null) {
    return response;
  }
  let resp = await context.fetch_origin(req);
  return applyPostResponseActions(context, resp, actions);
}

/**
 *
 * Fetches a list of the applicable actions, given a request.
 */
export async function fetchActions(context: RecaptchaContext, req: EdgeRequest): Promise<action.Action[]> {
  let actions: action.Action[] = [];
  try {
    const localAssessment = await localPolicyAssessment(context, req);
    if (localAssessment === "recaptcha-required") {
      context.log("debug", "no local match, calling reCAPTCHA");
      actions = await evaluatePolicyAssessment(context, req);
    } else {
      context.log("debug", "local assessment succeeded");
      actions = localAssessment;
    }
  } catch (reason) {
    context.logException(reason);
    actions = [action.createAllowAction()];
  }

  if (context.config.sessionJsInjectPath) {
    const patterns = context.config.sessionJsInjectPath?.split(";");
    const url = new URL(req.url);
    for (const pattern of patterns) {
      if (picomatch.isMatch(url.pathname, pattern)) {
        context.debug_trace.inject_js_match = true;
        context.log("debug", "Request matching session JS inject pattern: " + pattern);
        // We don't need to check if it's already there, since policies currently
        // can't insert this action.
        actions.unshift(action.createInjectJsAction());
        break;
      }
    }
  }
  return actions;
}

/**
 * Process reCAPTCHA request.
 */
export async function processRequest(context: RecaptchaContext, req: EdgeRequest): Promise<EdgeResponse> {
  const actions = await fetchActions(context, req);
  context.log_performance_debug("[func] applyActions - start");
  let resp = applyActions(context, req, actions);
  context.log_performance_debug("[func] applyActions - end");

  // Create a response that dumps the exceptions and log messages.
  // This response will look like a JSON object like { logs: ["log msg 1", "log msg 2"], exceptions: ["exception1"]}
  // This is used solely for debugging, and will replace the expected response.
  // This is unsafe and should never be used in production, as it overwrites the response.
  // The logs dumped here are much more substantial than the debug response header populated with the 'debug' flag.
  if (context.config.unsafe_debug_dump_logs) {
    await resp;
    resp = Promise.resolve(
      context.createResponse(
        JSON.stringify(
          {
            logs: context.log_messages,
            exceptions: context.exceptions,
            list_firewall_policies_headers: Array.from(
              (context.debug_trace._list_firewall_policies_headers ?? new Map()).entries(),
            ),
            create_assessment_headers: Array.from(
              (context.debug_trace._create_assessment_headers ?? new Map()).entries(),
            ),
          },
          null,
          2,
        ),
      ),
    );
  }
  // Create a debug response header.
  // This header has some useful stats like what action was chose, what site key was used, how many policies were loaded, etc.
  if (context.config.debug) {
    let resolved_resp = await resp;
    context.debug_trace.exception_count = context.exceptions.length;
    resolved_resp.addHeader("X-RECAPTCHA-DEBUG", context.debug_trace.formatAsHeaderValue());
    resp = Promise.resolve(resolved_resp);
  }

  return resp;

  // TODO: post return call analytics
}
