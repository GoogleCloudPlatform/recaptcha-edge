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
import { RecaptchaContext } from "./index";
import { callListFirewallPolicies } from "./listFirewallPolicies";
import { createSoz } from "./proto/soz";

type LocalAssessment = action.Action[] | "recaptcha-required";

/**
 * Path to the hosted reCAPTCHA Enterprise Javascript.
 * This path may be injected into the response.
 */
export const RECAPTCHA_JS = "https://www.google.com/recaptcha/enterprise.js";

/** @type {string} */
export const CHALLENGE_PAGE_URL = "https://www.google.com/recaptcha/challengepage";

/**
 * Checks whether a particular policy path pattern matches the incoming request.
 */
export function policyPathMatch(policy: FirewallPolicy, req: Request): boolean {
  const url = new URL(req.url);
  if (!policy.path) {
    return true;
  }
  return picomatch.isMatch(url.pathname, policy.path);
}

/**
 * Evaluate the condition of a policy locally, to the best of our ability.
 *
 * @return true if the condition matches, false if it doesn't match, or
 * 'unknown' if we can't evaluate the condition locally.
 */
// eslint-disable-next-line  @typescript-eslint/no-unused-vars
export function policyConditionMatch(policy: FirewallPolicy, req: Request): boolean | "unknown" {
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
 * Check if a request can be locally accessed,
 * with amortized caching of policies.
 */
export async function localPolicyAssessment(context: RecaptchaContext, req: Request): Promise<LocalAssessment> {
  // TODO: local overrides or hooks

  // Optimization to inspect a cached copy of the firewall policies if HTTP caching is enabled.
  if (context.httpGetCachingEnabled) {
    // TODO: some platforms might need explicit caching?
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
      if (policyPathMatch(policy, req)) {
        const conditionMatch = policyConditionMatch(policy, req);
        if (conditionMatch === "unknown") {
          return "recaptcha-required";
        } else if (conditionMatch) {
          // TODO: handle multiple policies.
          context.log("debug", "local assessment condition matched");
          return policy?.actions ?? [];
        }
      }
    }
  }
  // No policies were found to match in the cache. This default to 'allow'.
  return [action.createAllowAction()];
}

/**
 * Evaluate the policy assessment for a request.
 */
export async function evaluatePolicyAssessment(context: RecaptchaContext, req: Request): Promise<action.Action[]> {
  let assessment;
  try {
    context.log_performance_debug("[rpc] callCreateAssessment - start");
    assessment = await callCreateAssessment(context, req, context.environment, {
      firewallPolicyEvaluation: true,
    });
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
 * Apply actions to a request.
 */
export async function applyActions(
  context: RecaptchaContext,
  req: Request,
  actions: action.Action[],
): Promise<Response> {
  let terminalAction: action.Action = action.createAllowAction();
  const reqNonterminalActions: action.RequestNonTerminalAction[] = [];
  const respNonterminalActions: action.ResponseNonTerminalAction[] = [];
  let newReq = new Request(req.url, req);

  // Actions are assumed to be in order of processing. Non-terminal actions must
  // be processed before terminal actions, and will be ignored if erroniously
  // placed after terminal actions.
  filterActions: for (const action of actions) {
    switch (action.type) {
      case "allow":
      case "block":
      case "redirect":
      case "challengepage":
        terminalAction = action;
        break filterActions;
      case "setHeader":
      case "substitute":
        context.log("debug", "nonTerminalAction: " + action.type);
        reqNonterminalActions.push(action);
        continue;
      case "injectjs":
        context.log("debug", "nonTerminalAction: " + action.type);
        respNonterminalActions.push(action);
        continue;
      default:
        /* v8 ignore next */
        throw new Error("Unsupported action: " + action);
    }
  }
  context.log("debug", "terminalAction: " + terminalAction.type);

  if (terminalAction.type === "block") {
    return new Response(null, { status: 403 }); // TODO: custom html
  }

  if (terminalAction.type === "redirect") {
    // TODO: consider caching event.
    const event = context.buildEvent(req);
    const url = new URL(req.url);
    if (!context.config.challengePageSiteKey) {
      context.log("error", "[!] attempt to redirect without challenge page site key!");
    }
    const soz = createSoz(
      url.hostname,
      event.userIpAddress,
      context.config.projectNumber,
      context.config.challengePageSiteKey ?? "", // TODO: default site key?
    );
    return context.fetch_challenge_page(
      new Request(CHALLENGE_PAGE_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json;charset=UTF-8",
          "X-ReCaptcha-Soz": soz,
        },
      }),
    );
  }

  // Handle Pre-Request actions.
  for (const action of reqNonterminalActions) {
    context.log("debug", "reqNonterminal action: " + action.type);
    if (action.type === "setHeader") {
      newReq.headers.set(action.setHeader.key, action.setHeader.value);
      continue;
    }
    if (action.type === "substitute") {
      const url = new URL(newReq.url);
      newReq = new Request(`${url.origin}${action.substitute.path}`, newReq);
      continue;
    }
    /* v8 ignore next 2 lines */
    throw new Error("Unsupported pre-request action: " + action);
  }

  // Fetch from the backend, whether redirected or not.
  let resp = context.fetch_origin(newReq);

  // Handle Post-Response actions.
  const once = new Set<string>();
  for (const action of respNonterminalActions) {
    context.log("debug", "respNonterminal action: " + action.type);
    if (once.has(action.type)) {
      continue; // TODO: should this throw an error?
    }
    switch (action.type) {
      case "injectjs":
        // Only inject JS once, even if multiple actions erroneously specify it.
        once.add(action.type);
        resp = context.injectRecaptchaJs(await resp);
        continue;
      /* v8 ignore next 2 lines */
      default:
        throw new Error("Unsupported post-response action: " + action);
    }
  }

  return resp;
}

/**
 * Process reCAPTCHA request.
 */
export async function processRequest(context: RecaptchaContext, req: Request): Promise<Response> {
  let actions = [];
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

  const resp = applyActions(context, req, actions);

  // Create a debug response header.
  if (context.config.debug) {
    const new_resp = await resp;
    context.debug_trace.exception_count = context.exceptions.length;
    new_resp.headers.append("X-RECAPTCHA-DEBUG", context.debug_trace.formatAsHeaderValue());
  }
  // Create a response that dumps the exceptions and log messages.
  // This response will look like a JSON object like { logs: ["log msg 1", "log msg 2"], exceptions: ["exception1"]}
  // This is used solely for debugging, and will replace the expected response.
  // This is unsafe and should never be used in production, as it overwrites the response.
  // The logs dumped here are much more substantial than the debug response header populated with the 'debug' flag.
  if (context.config.unsafe_debug_dump_logs) {
    await resp;
    return new Response(JSON.stringify({ logs: context.log_messages, exceptions: context.exceptions }, null, 2));
  }

  return resp;

  // TODO: post return call analytics
}
