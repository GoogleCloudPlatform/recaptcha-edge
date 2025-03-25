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
 * @fileoverview Helper functions and types related to the ListFirewallPolicies RPC.
 */

import { FirewallPolicy, isRpcError, RpcError } from "./assessment";
import * as error from "./error";
import { RecaptchaContext } from "./index";

/** Zod Schema for ListFirewallPoliciesResponse */
export interface ListFirewallPoliciesResponse {
  firewallPolicies: FirewallPolicy[];
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
