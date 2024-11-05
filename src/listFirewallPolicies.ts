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

import {z} from 'zod';
import {FirewallPolicySchema} from './assessment';
import * as error from './error';
import {RecaptchaContext} from './index';

/** Zod Schema for ListFirewallPoliciesResponse */
export const ListFirewallPoliciesResponseSchema = z.object({
  firewallPolicies: z.array(FirewallPolicySchema),
});

/** Response type from ListFirewallPolicies RPC */
export type ListFirewallPoliciesResponse = z.infer<
  typeof ListFirewallPoliciesResponseSchema
>;

/**
 * Call the reCAPTCHA API to list firewall policies.
 */
export async function callListFirewallPolicies(
  context: RecaptchaContext,
): Promise<ListFirewallPoliciesResponse> {
  const options = {
    method: 'GET',
    headers: {
      'content-type': 'application/json;charset=UTF-8',
    },
  };
  const endpoint = context.config.recaptchaEndpoint;
  const projectNumber = context.config.projectNumber;
  const apiKey = context.config.apiKey;
  const policiesUrl = `${endpoint}/v1/projects/${projectNumber}/firewallpolicies?key=${apiKey}&page_size=1000`;

  return context
    .fetch_list_firewall_policies(policiesUrl, options)
    .then((response) => {
      return response
        .json()
        .then((json) => {
          let ret = ListFirewallPoliciesResponseSchema.parse(json);
          context.log('debug', '[rpc] listFirewallPolicies (ok)');
          return ret;
        })
        .catch((reason) => {
          throw new error.ParseError(reason.message);
        });
    })
    .catch((reason) => {
      context.log('debug', '[rpc] listFirewallPolicies (fail)');
      throw new error.NetworkError(reason.message);
    });
}
