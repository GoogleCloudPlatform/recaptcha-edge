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

// test/index.spec.ts
import { createExecutionContext, env, SELF, fetchMock, waitOnExecutionContext } from "cloudflare:test";
import { expect, test, beforeAll, afterEach } from "vitest";
import worker from "../src/index";
import { testing } from "@google-cloud/recaptcha-cloudflare";

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

beforeAll(() => {
  // Enable outbound request mocking...
  fetchMock.activate();
  // ...and throw errors if an outbound request isn't mocked
  fetchMock.disableNetConnect();
});
// Ensure we matched every mock we defined
afterEach(() => fetchMock.assertNoPendingInterceptors());

let mock_assessment_request = {
  path: "/v1/projects/12345/assessments?key=abc123",
  method: "POST",
  body: (body: any) => {
    let parsedBody = JSON.parse(body);
    parsedBody.assessmentEnvironment = undefined;
    let expected = {
      event: {
        token: "action-token",
        siteKey: "action-site-key",
        wafTokenAssessment: true,
        userIpAddress: "1.2.3.4",
        headers: ["cf-connecting-ip:1.2.3.4", "user-agent:test-user-agent", "x-recaptcha-token:action-token"],
        requestedUri: "http://example.com/myapi",
        userAgent: "test-user-agent",
      },
      assessmentEnvironment: undefined,
    };
    return JSON.stringify(parsedBody) == JSON.stringify(expected);
  },
};

test("allow", async () => {
  const request = new IncomingRequest("http://example.com/myapi", {
    headers: {
      "X-Recaptcha-Token": "action-token",
      "CF-Connecting-IP": "1.2.3.4",
      "user-agent": "test-user-agent",
    },
  });
  fetchMock
    .get("https://recaptchaenterprise.googleapis.com")
    .intercept(mock_assessment_request)
    .reply(200, JSON.stringify(testing.good_assessment));

  fetchMock.get("http://example.com").intercept({ path: "/myapi" }).reply(200, "<HTML>Hello World</HTML>");

  // Create an empty context to pass to `worker.fetch()`.
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  // Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
  await waitOnExecutionContext(ctx);
  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual("<HTML>Hello World</HTML>");
});

test("block", async () => {
  const request = new IncomingRequest("http://example.com/myapi", {
    headers: {
      "X-Recaptcha-Token": "action-token",
      "CF-Connecting-IP": "1.2.3.4",
      "user-agent": "test-user-agent",
    },
  });
  fetchMock
    .get("https://recaptchaenterprise.googleapis.com")
    .intercept(mock_assessment_request)
    .reply(200, JSON.stringify(testing.bad_assessment));

  // Create an empty context to pass to `worker.fetch()`.
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  // Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
  await waitOnExecutionContext(ctx);
  expect(response.status).toEqual(403);
  expect(await response.text()).equals("This request has been blocked for security reasons.");
});