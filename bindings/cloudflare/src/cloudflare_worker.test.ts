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

import { createExecutionContext, env, fetchMock, SELF, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeAll, expect, test } from "vitest";

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

beforeAll(() => {
  // Enable outbound request mocking...
  fetchMock.activate();
  // ...and throw errors if an outbound request isn't mocked
  fetchMock.disableNetConnect();
});
// Ensure we matched every mock we defined
afterEach(() => fetchMock.assertNoPendingInterceptors());

test("nomatch-ok", async () => {
  const testPolicies = [
    {
      name: "test-policy",
      description: "test-description",
      path: "/teste2e",
      condition: "recaptcha.score > 0.5",
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{ allow: {}, type: "allow" }],
    },
    {
      name: "test-policy2",
      description: "test-description2",
      path: "test-path2",
      condition: "test-condition2",
      actions: [{ block: {}, type: "block" }],
    },
  ];
  // Mock the first fetch request to get firewall policies
  fetchMock
    .get("https://recaptchaenterprise.googleapis.com")
    .intercept({
      path: "/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000",
    })
    .reply(200, JSON.stringify({ firewallPolicies: testPolicies }));
  // Mock the second fetch request to get assessment
  fetchMock
    .get("https://recaptchaenterprise.googleapis.com")
    .intercept({
      path: "/v1/projects/12345/assessments?key=abc123",
      method: "POST",
      body: JSON.stringify({
        event: {
          token: "action-token",
          siteKey: "action-site-key",
          wafTokenAssessment: true,
          userAgent: "test-user-agent",
          userIpAddress: "1.2.3.4",
          requestedUri: "http://example.com/teste2e",
          headers: ["cf-connecting-ip:1.2.3.4", "user-agent:test-user-agent", "x-recaptcha-token:action-token"],
          userInfo: undefined,
          firewallPolicyEvaluation: true,
        },
        assessmentEnvironment: {
          client: "@google-cloud/recaptcha-cloudflare",
          version: "1.0.0",
        },
      }),
    })
    .reply(200, JSON.stringify({ firewallPolicyAssessment: {} }));
  // Mock the third fetch request to the actual website
  fetchMock.get("http://example.com").intercept({ path: "/teste2e" }).reply(200, "<HTML>Hello World</HTML>");
  const req = new IncomingRequest("http://example.com/teste2e", {
    headers: {
      "X-Recaptcha-Token": "action-token",
      "CF-Connecting-IP": "1.2.3.4",
      "user-agent": "test-user-agent",
    },
  });
  // Create an empty context to pass to `worker.fetch()`
  const ctx = createExecutionContext();
  const res = await SELF.fetch(req, env, ctx);
  // Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
  await waitOnExecutionContext(ctx);
  expect(await res.text()).toBe("<HTML>Hello World</HTML>");
});
