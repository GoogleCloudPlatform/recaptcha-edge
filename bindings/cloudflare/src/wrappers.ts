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
 * @fileoverview Exposes convenient wrappers to underlying API methods or abstractions with
 * platform specific types.
 */

// eslint-disable-next-line  @typescript-eslint/no-unused-vars
import {
  callCreateAssessment,
  callListFirewallPolicies,
  processRequest as baseProcessRequest,
  pathMatch as basePathMatch,
  Event,
  FetchApiRequest,
  FetchApiResponse,
  Assessment,
  ListFirewallPoliciesResponse,
} from "@google-cloud/recaptcha-edge";

import { CloudflareContext } from "./context";

export async function processRequest(ctx: CloudflareContext, r: Request): Promise<Response> {
  const v = await baseProcessRequest(ctx, new FetchApiRequest(r));
  return (v as FetchApiResponse).asResponse();
}

export function pathMatch(req: Request, patterns: string | [string], method?: string): boolean {
  return basePathMatch(new FetchApiRequest(req), patterns, method);
}

export function createAssessment(
  ctx: CloudflareContext,
  r: Request,
  additionalParams?: Event,
  environment?: [string, string],
): Promise<Assessment> {
  return callCreateAssessment(ctx, new FetchApiRequest(r), additionalParams, environment);
}

export function listFirewallPolicies(ctx: CloudflareContext): Promise<ListFirewallPoliciesResponse> {
  return callListFirewallPolicies(ctx);
}
