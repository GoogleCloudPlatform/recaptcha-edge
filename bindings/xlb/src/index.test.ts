/**
 * Copyright 2025 Google LLC
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

import { createClient } from "@connectrpc/connect";
import { create, MessageInitShape } from "@bufbuild/protobuf";
import { createGrpcTransport } from "@connectrpc/connect-node";
import { describe, test, it, expect } from "vitest";
import * as calloutServer from "./index";
import express from "express";

import {
  ExternalProcessor,
  ProcessingRequestSchema,
  ProcessingResponse,
  ProcessingResponseSchema,
} from "../gen/envoy/service/ext_proc/v3/external_processor_pb.js";
import { StatusCode } from "../gen/envoy/type/v3/http_status_pb.js";

import { RecaptchaConfig } from "@google-cloud/recaptcha-edge";

type CalloutEvent =
  | "requestHeaders"
  | "requestBody"
  | "requestTrailers"
  | "responseHeaders"
  | "responseBody"
  | "responseTrailers";

describe("WAF Callouts Suite", async function () {
  // Set up a local recaptcha app.
  const rc_app = express();
  rc_app.use(express.json());

  // Return all the test policies.
  rc_app.get("/v1/projects/:projectNumber/firewallpolicies", (req, res) => {
    const all = Array.from(testPolicies.values());
    res.json({ firewallPolicies: all });
  });

  // All tests must specify the firewall policy they match in url. For convenience,
  // the path attribute of the policy is ignored by the server implementation.
  rc_app.post("/v1/projects/:projectNumber/assessments", (req, res) => {
    const uri = req.body.event.requestedUri;
    const key = req.body.event.siteKey;
    const token = req.body.event.token;
    const policyKey = uri + "/" + key + "/" + token;
    console.log("policy key: ", policyKey);
    const policy = testPolicies.get(uri + "/" + key + "/" + token);
    res.json({
      riskAnalysis: {
        score: 0.9,
      },
      firewallPolicyAssessment: {
        firewallPolicy: policy,
      },
    });
  });

  // Start the server.
  rc_app.listen(18082, () => {
    console.log("recaptcha mock running on port 18082");
  });

  // Create a mock that will serve the challenge page.
  const challenge_app = express();

  // Set a custom header in the challenge page to make sure
  // the headers are preserved in the response.
  challenge_app.post("/challenge", (req, res) => {
    res.set("my-custom-header", "test");
    res.send(challengePageHtml);
  });

  // Start the server.
  challenge_app.listen(18083, () => {
    console.log("challenge app started");
  });

  // Start the callout server.
  const _ = await calloutServer.start(config, 10023, () => {
    console.log("started server!");
  });

  // Create the client to talk to the callout server.
  const transport = createGrpcTransport({
    baseUrl: "http://127.0.0.1:10023",
    interceptors: [],
  });
  const client = createClient(ExternalProcessor, transport);

  it.each([
    { type: "requestBody" },
    { type: "requestTrailers" },
    { type: "responseHeaders" },
    { type: "responseBody" },
    { type: "responseTrailers" },
  ])("can handle event: $type", async (event) => {
    const resp = await sendRequest(client, {
      request: {
        case: event.type as CalloutEvent,
        value: {},
      },
    });
    const processingResponse = resp[0];
    // Ensure headers are preserved.
    expect(processingResponse).toStrictEqual(
      create(ProcessingResponseSchema, {
        response: {
          case: event.type as CalloutEvent,
          value: {},
        },
      }),
    );
  });

  test("action redirect", async () => {
    const resp = await sendRequest(client, {
      request: {
        case: "requestHeaders",
        value: {
          headers: {
            headers: [
              {
                key: "origin",
                rawValue: new TextEncoder().encode("https://example.com"),
              },
              {
                key: ":path",
                rawValue: new TextEncoder().encode("/redirect"),
              },
              {
                key: "X-Recaptcha-Token",
                rawValue: new TextEncoder().encode("anytoken"),
              },
              {
                key: "X-Forwarded-For",
                rawValue: new TextEncoder().encode("127.0.0.1,34.45.56.666"),
              },
            ],
          },
        },
      },
    });
    const processingResponse = resp[0];
    // Ensure headers are preserved.
    expect(readSetHeaders(processingResponse)).toContainEqual({ key: "my-custom-header", value: "test" });
    // Ensure body mutation is accurate.
    expect(readBodyMutation(processingResponse)).toBe(challengePageHtml);
  });

  test("action block", async () => {
    const resp = await sendRequest(client, {
      request: {
        case: "requestHeaders",
        value: {
          headers: {
            headers: [
              {
                key: "origin",
                rawValue: new TextEncoder().encode("https://example.com"),
              },
              {
                key: ":path",
                rawValue: new TextEncoder().encode("/block"),
              },
              {
                key: "X-Recaptcha-Token",
                rawValue: new TextEncoder().encode("anytoken"),
              },
              {
                key: "X-Forwarded-For",
                rawValue: new TextEncoder().encode("127.0.0.1,34.45.56.666"),
              },
            ],
          },
        },
      },
    });
    const processingResponse = resp[0];
    expect(readStatus(processingResponse)).toBe(StatusCode.Forbidden);
  });

  test("action set header", async () => {
    const resp = await sendRequest(client, {
      request: {
        case: "requestHeaders",
        value: {
          headers: {
            headers: [
              {
                key: "origin",
                rawValue: new TextEncoder().encode("https://example.com"),
              },
              {
                key: ":path",
                rawValue: new TextEncoder().encode("/setHeader"),
              },
              {
                key: "X-Recaptcha-Token",
                rawValue: new TextEncoder().encode("anytoken"),
              },
              {
                key: "X-Forwarded-For",
                rawValue: new TextEncoder().encode("127.0.0.1,34.45.56.666"),
              },
            ],
          },
        },
      },
    });
    const processingResponse = resp[0];
    // Ensure headers are preserved.
    expect(readSetHeaders(processingResponse)).toContainEqual({ key: "my-custom-header", value: "test123" });
  });
  test("session cookie block", async () => {
    const resp = await sendRequest(client, {
      request: {
        case: "requestHeaders",
        value: {
          headers: {
            headers: [
              {
                key: "origin",
                rawValue: new TextEncoder().encode("https://example.com"),
              },
              {
                key: ":path",
                rawValue: new TextEncoder().encode("/block"),
              },
              {
                key: "cookie",
                rawValue: new TextEncoder().encode("OTZ=7960024_76_76_104100_72_446760; recaptcha-fastly-t=anytoken"),
              },
              {
                key: "X-Forwarded-For",
                rawValue: new TextEncoder().encode("127.0.0.1,34.45.56.666"),
              },
            ],
          },
        },
      },
    });
    const processingResponse = resp[0];
    expect(readStatus(processingResponse)).toBe(StatusCode.Forbidden);
  });

  test("session cookie redirect", async () => {
    const resp = await sendRequest(client, {
      request: {
        case: "requestHeaders",
        value: {
          headers: {
            headers: [
              {
                key: "origin",
                rawValue: new TextEncoder().encode("https://example.com"),
              },
              {
                key: ":path",
                rawValue: new TextEncoder().encode("/redirect"),
              },
              {
                key: "cookie",
                rawValue: new TextEncoder().encode("blah=test;hi=hello;recaptcha-gxlb-e=anytoken"),
              },
              {
                key: "X-Forwarded-For",
                rawValue: new TextEncoder().encode("127.0.0.1,34.45.56.666"),
              },
            ],
          },
        },
      },
    });
    const processingResponse = resp[0];
    // Ensure headers are preserved.
    expect(readSetHeaders(processingResponse)).toContainEqual({ key: "my-custom-header", value: "test" });
    // Ensure body mutation is accurate.
    expect(readBodyMutation(processingResponse)).toBe(challengePageHtml);
  });

  test("JS injection", async () => {
    const simpleHttp = "<http><head></head></http>";
    const resp = await sendRequest(
      client,
      {
        request: {
          case: "requestHeaders",
          value: {
            headers: {
              headers: [
                {
                  key: "origin",
                  rawValue: new TextEncoder().encode("https://example.com"),
                },
                {
                  key: ":path",
                  rawValue: new TextEncoder().encode("/inject"),
                },
                {
                  key: "X-Recaptcha-Token",
                  rawValue: new TextEncoder().encode("anytoken"),
                },
                {
                  key: "X-Forwarded-For",
                  rawValue: new TextEncoder().encode("127.0.0.1,34.45.56.666"),
                },
              ],
            },
          },
        },
      },
      {
        request: {
          case: "responseBody",
          value: {
            body: new TextEncoder().encode(simpleHttp),
          },
        },
      },
    );
    expect(readBodyMutation(resp[1])).toBe(
      '<http><head><script src="https://www.google.com/recaptcha/enterprise.js?render=sessionKey&waf=session" async defer></script></head></http>',
    );
  });
});

async function* genRequests(
  ...requests: MessageInitShape<typeof ProcessingRequestSchema>[]
): AsyncIterable<MessageInitShape<typeof ProcessingRequestSchema>> {
  for (const request of requests) {
    yield request;
  }
}

async function sendRequest(
  client,
  ...requests: MessageInitShape<typeof ProcessingRequestSchema>[]
): Promise<ProcessingResponse[]> {
  let count = 0;
  const ret: ProcessingResponse[] = [];

  const responses = client.process(genRequests(...requests));
  for await (const resp of responses) {
    ret.push(resp);
    count++;
    if (ret.length === requests.length) {
      return ret;
    }
  }
  return ret;
}

function readBodyMutation(res: ProcessingResponse): string {
  switch (res.response.case) {
    case "immediateResponse":
      return res.response.value.body;
    case "responseBody":
      if (res.response.value.response?.bodyMutation?.mutation.case === "body")
        return new TextDecoder().decode(res.response.value.response?.bodyMutation?.mutation.value);
      else return "<invalid response body>";
    default:
      return "<unknown body mutation>";
  }
}

function readSetHeaders(res: ProcessingResponse): object[] {
  switch (res.response.case) {
    case "immediateResponse":
      return (
        res.response.value.headers?.setHeaders?.map((h) => {
          return {
            key: h.header?.key,
            value: new TextDecoder().decode(h.header?.rawValue),
          };
        }) || []
      );
    case "requestHeaders":
      return (
        res.response.value.response?.headerMutation?.setHeaders?.map((h) => {
          return {
            key: h.header?.key,
            value: new TextDecoder().decode(h.header?.rawValue),
          };
        }) || []
      );
    default:
      return [];
  }
}

function readStatus(res: ProcessingResponse) {
  switch (res.response.case) {
    case "immediateResponse":
      return res.response.value.status?.code;
    default:
      return undefined;
  }
}

const testPolicies = new Map();
testPolicies.set("https://example.com/block/actionKey/anytoken", {
  name: "action token block",
  description: "test-description2",
  path: "/block",
  condition: "recaptcha.score > 0.5",
  actions: [{ block: {}, type: "block" }],
});
testPolicies.set("https://example.com/block/sessionKey/anytoken", {
  name: "session token block",
  description: "test-description2",
  path: "/block",
  condition: "recaptcha.score > 0.5",
  actions: [{ block: {}, type: "block" }],
});
testPolicies.set("https://example.com/redirect/actionKey/anytoken", {
  name: "action token redirect",
  description: "test-description3",
  path: "/redirect",
  condition: "recaptcha.score > 0.5",
  actions: [{ redirect: {}, type: "redirect" }],
});
testPolicies.set("https://example.com/setHeader/actionKey/anytoken", {
  name: "action token set header",
  description: "test-description3",
  path: "/setHeader",
  condition: "recaptcha.score > 0.5",
  actions: [
    {
      setHeader: {
        key: "my-custom-header",
        value: "test123",
      },
      type: "setHeader",
    },
  ],
});
testPolicies.set("https://example.com/redirect/challengePageSiteKey/anytoken", {
  name: "challenge token redirect",
  description: "test-description3",
  path: "/redirect",
  condition: "recaptcha.score > 0.5",
  actions: [{ redirect: {}, type: "redirect" }],
});

const challengePageHtml = "<html><h1>Challenge page</h1><html>";

const config: RecaptchaConfig = {
  projectNumber: 34348585,
  apiKey: "apiKey",
  actionSiteKey: "actionKey",
  expressSiteKey: undefined,
  sessionSiteKey: "sessionKey",
  challengePageSiteKey: "challengePageSiteKey",
  enterpriseSiteKey: undefined,
  recaptchaEndpoint: "http://127.0.0.1:18082",
  challengePageUrl: "http://127.0.0.1:18083/challenge",
  sessionJsInjectPath: "/inject",
  debug: true,
  unsafe_debug_dump_logs: true,
  strict_cookie: false,
};
