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
 * Tests for index.ts
 */
import { expect, test, vi, Mock } from "vitest";

import {
  applyActions,
  getActions,
  callCreateAssessment,
  callListFirewallPolicies,
  createPartialEventWithSiteInfo,
  evaluatePolicyAssessment,
  localPolicyAssessment,
  policyConditionMatch,
  policyPathMatch,
  processRequest,
  RecaptchaConfig,
  RecaptchaContext,
  SetHeaderAction,
  LogLevel,
  DebugTrace,
  EdgeRequest,
  EdgeResponse,
  EdgeResponseInit,
  FirewallPolicy,
  Event,
  applyPreRequestActions,
  applyPostResponseActions,
} from "./index";

import { FetchApiRequest, FetchApiResponse } from "./fetchApi";

import {
  Action,
  AllowAction,
  createAllowAction,
  createBlockAction,
  isBlockAction,
  isAllowAction,
  isSetHeaderAction,
} from "./action";

async function fetchHasRequest(o: Request): Promise<boolean> {
  let calls = (fetch as Mock).mock.calls;
  expect(calls.length).equals(1);
  let req = calls[0][0] as Request;
  return (
    req.url == o.url && req.headers == o.headers && req.method == o.method && (await req.text()) == (await o.text())
  );
}

const testConfig: RecaptchaConfig = {
  recaptchaEndpoint: "https://recaptchaenterprise.googleapis.com",
  projectNumber: 12345,
  apiKey: "abc123",
  actionSiteKey: "action-site-key",
  expressSiteKey: "express-site-key",
  sessionSiteKey: "session-site-key",
  challengePageSiteKey: "challenge-page-site-key",
  enterpriseSiteKey: "enterprise-site-key",
  credentialPath: "test/login",
  accountId: "account-id-is-here",
  username: "username-is-here",
};

class TestContext extends RecaptchaContext {
  sessionPageCookie = "recaptcha-test-t";
  challengePageCookie = "recaptcha-test-e";
  exceptions: any[] = [];
  log_messages: Array<[LogLevel, string[]]> = [];

  constructor(config: RecaptchaConfig) {
    super(JSON.parse(JSON.stringify(config)));
  }

  createRequest(url: string, options: any): EdgeRequest {
    return new FetchApiRequest(new Request(url, options));
  }

  createResponse(body: string, options?: EdgeResponseInit): EdgeResponse {
    return new FetchApiResponse(body, options);
  }

  async fetch(req: EdgeRequest): Promise<EdgeResponse> {
    let base_req = (req as FetchApiRequest).asRequest();
    return fetch(base_req).then((v) => new FetchApiResponse(v));
  }
  logException = (e: any) => {
    this.exceptions.push(e);
  };
  log = (level: LogLevel, msg: string) => {
    this.log_messages.push([level, [msg]]);
  };
  // eslint-disable-next-line  @typescript-eslint/no-unused-vars

  buildEvent = async (req: EdgeRequest) => {
    const partialEvent = await createPartialEventWithSiteInfo(this, req);
    const baseEvent = {
      userIpAddress: "1.2.3.4",
      userAgent: "test-user-agent",
    } as Event;
    return { ...baseEvent, ...partialEvent };
  };
  injectRecaptchaJs = async (resp: EdgeResponse) => {
    let html = await resp.text();
    html = html.replace("<HTML>", '<HTML><script src="test.js"/>');
    return new FetchApiResponse(new Response(html, resp));
  };
}

test("callCreateAssessment-ok", async () => {
  const baseEvent = {};
  const testEvent = {
    token: "test-token",
    siteKey: "action-site-key",
    wafTokenAssessment: true,
  };
  const testAssessment = {
    event: testEvent,
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(() =>
      Promise.resolve({
        json: () => Promise.resolve(testAssessment),
        headers: new Headers(),
      }),
    ),
  );

  const testContext = new TestContext(testConfig);
  testContext.buildEvent = (req: EdgeRequest) => {
    return Promise.resolve(baseEvent);
  };

  const req = new FetchApiRequest("https://www.google.com");
  req.addHeader("X-Recaptcha-Token", "test-token");
  const resp = await callCreateAssessment(testContext as RecaptchaContext, req, ["test-env", "test-version"]);
  expect(
    await fetchHasRequest(
      new Request("https://recaptchaenterprise.googleapis.com/v1/projects/12345/assessments?key=abc123", {
        body: JSON.stringify({
          event: testEvent,
          assessmentEnvironment: { client: "test-env", version: "test-version" },
        }),
        headers: {
          "content-type": "application/json;charset=UTF-8",
        },
        method: "POST",
      }),
    ),
  );
  expect(resp).toEqual(testAssessment);
});

test("callCreateAssessmentWithUserInfo-ok", async () => {
  const testEvent = {
    token: "test-token",
    siteKey: "enterprise-site-key",
    wafTokenAssessment: false,
    userInfo: {
      accountId: "testuser",
      userIds: [
        {
          email: "testing@google.com",
        },
        {
          phoneNumber: "123456789",
        },
        {
          username: "test",
        },
      ],
    },
  };
  const testAssessment = {
    event: testEvent,
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(() =>
      Promise.resolve({
        json: () => Promise.resolve(testAssessment),
        headers: new Headers(),
      }),
    ),
  );

  const testContext = new TestContext(testConfig);
  testContext.buildEvent = (req: EdgeRequest) => {
    return Promise.resolve(testEvent);
  };

  const resp = await callCreateAssessment(
    testContext as RecaptchaContext,
    new FetchApiRequest(
      new Request("https://www.google.com", {
        body: JSON.stringify({
          "g-recaptcha-response": "test-token",
        }),
        headers: {
          "content-type": "application/json;charset=UTF-8",
        },
        method: "POST",
      }),
    ),
    ["test-env", "test-version"],
  );
  expect(
    await fetchHasRequest(
      new Request("https://recaptchaenterprise.googleapis.com/v1/projects/12345/assessments?key=abc123", {
        body: JSON.stringify({
          event: testEvent,
          assessmentEnvironment: { client: "test-env", version: "test-version" },
        }),
        headers: {
          "content-type": "application/json;charset=UTF-8",
        },
        method: "POST",
      }),
    ),
  );
  expect(resp).toEqual(testAssessment);
});

test("callListFirewallPolicies-ok", async () => {
  const testPolicies = [
    {
      name: "test-policy",
      description: "test-description",
      path: "test-path",
      condition: "test-condition",
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
  vi.stubGlobal(
    "fetch",
    vi.fn(() =>
      Promise.resolve({
        json: () =>
          Promise.resolve({
            firewallPolicies: testPolicies,
          }),
        headers: new Headers(),
      }),
    ),
  );

  const resp = await callListFirewallPolicies(new TestContext(testConfig));
  expect(
    await fetchHasRequest(
      new Request(
        "https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000",
        {
          headers: {
            "content-type": "application/json;charset=UTF-8",
          },
          method: "GET",
        },
      ),
    ),
  );
  expect(resp).toEqual({
    firewallPolicies: testPolicies,
  });
});

test("ActionSchema-parseOk", () => {
  const allowaction: Action = JSON.parse('{"allow":{}}');
  expect(isAllowAction(allowaction));
  const shaction: Action = JSON.parse('{"setHeader":{"key":"test-key","value":"test-value"}}');
  expect(isSetHeaderAction(shaction));
  const shaction2 = shaction as SetHeaderAction;
  expect(shaction2.setHeader.key).toEqual("test-key");
  expect(shaction2.setHeader.value).toEqual("test-value");
});

test("ApplyActions-allow", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/doallow");
  vi.stubGlobal(
    "fetch",
    vi.fn(() => Promise.resolve({ status: 200, headers: new Headers(), text: () => "<HTML>Hello World</HTML>" })),
  );
  const resp = await applyActions(context, req, [createAllowAction()]);
  expect(resp.status).toEqual(200);
  expect(resp.text()).toEqual("<HTML>Hello World</HTML>");
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("ApplyActions-block", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/doblock");
  vi.stubGlobal(
    "fetch",
    vi.fn(() => Promise.resolve({ status: 200, text: () => "<HTML>Hello World</HTML>" })),
  );
  const resp = await applyActions(context, req, [createBlockAction()]);
  expect(await resp.text()).toEqual("");
  expect(resp.status).toEqual(403);
  // TODO: custom html
  expect(fetch).toHaveBeenCalledTimes(0);
});

test("ApplyActions-setHeader", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/setheader");
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.headers.get("test-key")).toEqual("test-value");
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        text: () => "<HTML>Hello World</HTML>",
      });
    }),
  );
  const resp = await applyActions(context, req, [
    { setHeader: { key: "test-key", value: "test-value" } } as SetHeaderAction,
  ]);
  expect(resp.status).toEqual(200);
  expect(resp.text()).toEqual("<HTML>Hello World</HTML>");
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("ApplyActions-redirect", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/originalreq");
  req.addHeader("test-key", "test-value");
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.url).toEqual("https://www.google.com/recaptcha/challengepage");
      expect(req.headers.get("test-key")).toEqual(null);
      expect(req.headers.get("X-ReCaptcha-Soz")).toEqual(
        "eyJob3N0Ijoid3d3LmV4YW1wbGUuY29tIiwicHJvamVjdE51bWJlciI6MTIzNDUsInNpdGVLZXkiOiJjaGFsbGVuZ2UtcGFnZS1zaXRlLWtleSIsInVzZXJJcCI6IkFRSURCQSJ9",
      );
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        text: () => "<HTML>Hello World</HTML>",
      });
    }),
  );
  const resp = await applyActions(context, req, [{ redirect: {} }]);
  expect(resp.status).toEqual(200);
  expect(resp.text()).toEqual("<HTML>Hello World</HTML>");
  expect(fetch).toHaveBeenCalledTimes(1);
});
test("ApplyActions-substitute", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/substitute");
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.url).toEqual("https://www.example.com/newdest");
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        text: () => "<HTML>Hello World</HTML>",
      });
    }),
  );
  const resp = await applyActions(context, req, [{ substitute: { path: "/newdest" } }]);
  expect(resp.status).toEqual(200);
  expect(resp.text()).toEqual("<HTML>Hello World</HTML>");
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("ApplyActions-injectJs", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testinject");
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.url).toEqual("https://www.example.com/testinject");
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        text: () => "<HTML>Hello World</HTML>",
      });
    }),
  );
  const resp = await applyActions(context, req, [{ injectjs: {} }]);
  expect(resp.status).toEqual(200);
  // calls the TestContext injectRecaptchaJs.
  expect(await resp.text()).toEqual('<HTML><script src="test.js"/>Hello World</HTML>');
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("ApplyActions-injectJsOnlyOnce", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testinject");
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.url).toEqual("https://www.example.com/testinject");
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        text: () => "<HTML>Hello World</HTML>",
      });
    }),
  );
  const resp = await applyActions(context, req, [{ injectjs: {} }, { injectjs: {} }]);
  expect(resp.status).toEqual(200);
  // calls the TestContext injectRecaptchaJs.
  expect(await resp.text()).toEqual('<HTML><script src="test.js"/>Hello World</HTML>');
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("localPolicyAssessment-matchTrivialCondition", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testlocal");
  const testPolicies = [
    {
      name: "projects/12345/firewallpolicies/100",
      description: "test-description",
      path: "/badpath",
      condition: "recaptcha.score > 0.5",
      actions: [{ allow: {} }],
    },
    {
      name: "projects/12345/firewallpolicies/200",
      description: "test-description2",
      path: "/testlocal",
      condition: "true",
      actions: [{ block: {} }],
    },
  ];
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.url).toEqual(
        "https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000",
      );
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        json: () =>
          Promise.resolve({
            firewallPolicies: testPolicies,
          }),
      });
    }),
  );
  const localAssessment = await localPolicyAssessment(context, req);
  expect(localAssessment as Action[]).toEqual([{ block: {} }]);
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("localPolicyAssessment-noMatch", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testlocal");
  const testPolicies = [
    {
      name: "projects/12345/firewallpolicies/100",
      description: "test-description",
      path: "/badpath",
      condition: "true",
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{ block: {}, type: "block" }],
    },
    {
      name: "projects/12345/firewallpolicies/200",
      description: "test-description2",
      path: "/blahblah",
      condition: "true",
      actions: [{ block: {}, type: "block" }],
    },
  ];
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.url).toEqual(
        "https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000",
      );
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        json: () =>
          Promise.resolve({
            firewallPolicies: testPolicies,
          }),
      });
    }),
  );
  const localAssessment = await localPolicyAssessment(context, req);
  expect(localAssessment as Action[]).toEqual([{ allow: {} }]);
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("localPolicyAssessment-matchNontrivialCondition", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testlocal");
  const testPolicies = [
    {
      name: "projects/12345/firewallpolicies/100",
      description: "test-description",
      path: "/badpath",
      condition: "true",
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{ allow: {}, type: "allow" }],
    },
    {
      name: "projects/12345/firewallpolicies/200",
      description: "test-description2",
      path: "/testlocal",
      condition: "recaptcha.score > 0.5",
      actions: [{ block: {}, type: "block" }],
    },
  ];
  vi.stubGlobal(
    "fetch",
    vi.fn((url) => {
      expect(url).toEqual(
        "https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000",
      );
      return Promise.resolve({
        status: 200,
        json: () =>
          Promise.resolve({
            firewallPolicies: testPolicies,
          }),
      });
    }),
  );
  const localAssessment = await localPolicyAssessment(context, req);
  expect(localAssessment).toEqual("recaptcha-required");
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("localPolicyAssessment-performance", async () => {
  const numPolicies = 500;
  const testPolicies: FirewallPolicy[] = [];
  const testPath = "/test-path-performance";

  const context = new TestContext(testConfig);
  const req = new FetchApiRequest(`https://www.example.com${testPath}`);

  // Create a large array of non trivial policies that all match the test path.
  for (let i = 0; i < numPolicies; i++) {
    testPolicies.push({
      name: `policy-${i}`,
      description: `Test policy ${i}`,
      path: testPath, // All policies match the path
      condition: `recaptcha.score < 0.${i}`,
      actions: [{ block: {} }], // Simple action
    });
  }

  const startTime = performance.now();
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.url).toEqual(
        "https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000",
      );
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        json: () =>
          Promise.resolve({
            firewallPolicies: testPolicies,
          }),
      });
    }),
  );
  const localAssessment = await localPolicyAssessment(context, req);
  expect(localAssessment).toEqual("recaptcha-required");
  expect(fetch).toHaveBeenCalledTimes(1);

  const endTime = performance.now();
  const duration = endTime - startTime;

  console.log(`Fetch & nonTrivialLocalPolicyAssessment took ${duration}ms for ${numPolicies} policies`);
  expect(duration).toBeLessThan(1000);
});

test("policyPathMatch", async () => {
  expect(
    policyPathMatch(
      {
        name: "projects/12345/firewallpolicies/100",
        description: "test-description",
        path: "/goodpath",
        condition: "true",
        // 'type' isn't a part of the interface, but is added for testing.
        actions: [{ allow: {} }],
      },
      new FetchApiRequest("https://www.example.com/goodpath"),
    ),
  ).toEqual(true);
  expect(
    policyPathMatch(
      {
        path: "/goo?path",
      },
      new FetchApiRequest("https://www.example.com/goodpath"),
    ),
  ).toEqual(true);
  expect(policyPathMatch({}, new FetchApiRequest("https://www.example.com/goodpath"))).toEqual(true);
  expect(
    policyPathMatch(
      {
        path: "/goodppath",
      },
      new FetchApiRequest("https://www.example.com/goodpath"),
    ),
  ).toEqual(false);
  expect(
    policyPathMatch(
      {
        path: "/badppath",
      },
      new FetchApiRequest("https://www.example.com/badpath"),
    ),
  ).toEqual(false);
  expect(
    policyPathMatch(
      {
        path: "/wild/*/path",
      },
      new FetchApiRequest("https://www.example.com/wild/card/path"),
    ),
  ).toEqual(true);
  expect(
    policyPathMatch(
      {
        path: "/wild/card/*a*",
      },
      new FetchApiRequest("https://www.example.com/wild/card/path"),
    ),
  ).toEqual(true);
  expect(
    policyPathMatch(
      {
        path: "/wild/**/path",
      },
      new FetchApiRequest("https://www.example.com/wild/long/card/path"),
    ),
  ).toEqual(true);
});

test("policyConditionMatch", async () => {
  expect(
    policyConditionMatch(
      {
        name: "projects/12345/firewallpolicies/100",
        description: "test-description",
        path: "/goodpath",
        condition: "true",
        // 'type' isn't a part of the interface, but is added for testing.
        actions: [{ allow: {} }],
      },
      new FetchApiRequest("https://www.example.com/goodpath"),
    ),
  ).toEqual(true);

  expect(policyConditionMatch({}, new FetchApiRequest("https://www.example.com/goodpath"))).toEqual(true);

  expect(
    policyConditionMatch(
      {
        condition: "false",
      },
      new FetchApiRequest("https://www.example.com/goodpath"),
    ),
  ).toEqual(false);

  expect(
    policyConditionMatch(
      {
        condition: "recaptcha.score > 0.5",
      },
      new FetchApiRequest("https://www.example.com/goodpath"),
    ),
  ).toEqual("unknown");
});

test("localPolicyAssessment-failedRpc", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testlocal");
  vi.stubGlobal(
    "fetch",
    vi.fn((url) => {
      expect(url).toEqual(
        "https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000",
      );
      return Promise.reject(new Error("test-error"));
    }),
  );
  const localAssessment = await localPolicyAssessment(context, req);
  expect(localAssessment).toEqual("recaptcha-required");
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("localPolicyAssessment-badJson", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testlocal");
  vi.stubGlobal(
    "fetch",
    vi.fn((url) => {
      expect(url).toEqual(
        "https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000",
      );
      return Promise.resolve({
        status: 200,
        json: () => Promise.reject(new Error("test-error")),
      });
    }),
  );
  const localAssessment = await localPolicyAssessment(context, req);
  expect(localAssessment).toEqual("recaptcha-required");
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("localPolicyAssessment-errJson", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testlocal");
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.url).toEqual(
        "https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000",
      );
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        json: () => Promise.resolve({ error: { message: "bad", code: 400, status: "INVALID_ARGUMENT" } }),
      });
    }),
  );
  const localAssessment = await localPolicyAssessment(context, req);
  expect(localAssessment).toEqual("recaptcha-required");
  expect(context.exceptions[0].message).toEqual("bad");
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("evaluatePolicyAssessment-ok", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testlocal");
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.url).toEqual("https://recaptchaenterprise.googleapis.com/v1/projects/12345/assessments?key=abc123");
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        json: () =>
          Promise.resolve({
            name: "projects/12345/assessments/1234567890",
            firewallPolicyAssessment: {
              firewallPolicy: {
                actions: [{ block: {}, type: "block" }],
              },
            },
          }),
      });
    }),
  );
  const assessment = await evaluatePolicyAssessment(context, req);
  expect(isBlockAction(assessment[0]));
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("evaluatePolicyAssessment-failedRpc", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testlocal");
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.url).toEqual("https://recaptchaenterprise.googleapis.com/v1/projects/12345/assessments?key=abc123");
      return Promise.reject(new Error("test-error"));
    }),
  );
  const assessment = await evaluatePolicyAssessment(context, req);
  expect(isAllowAction(assessment[0]));
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("evaluatePolicyAssessment-badJson", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testlocal");
  vi.stubGlobal(
    "fetch",
    vi.fn((url) => {
      expect(url).toEqual("https://recaptchaenterprise.googleapis.com/v1/projects/12345/assessments?key=abc123");
      return Promise.resolve({
        status: 200,
        json: () => Promise.reject(new Error("test-error")),
      });
    }),
  );
  const assessment = await evaluatePolicyAssessment(context, req);
  expect(isAllowAction(assessment[0]));
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("evaluatePolicyAssessment-errJson", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testlocal");
  vi.stubGlobal(
    "fetch",
    vi.fn((req) => {
      expect(req.url).toEqual("https://recaptchaenterprise.googleapis.com/v1/projects/12345/assessments?key=abc123");
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        json: () => Promise.resolve({ error: { message: "bad", code: 400, status: "INVALID_ARGUMENT" } }),
      });
    }),
  );
  await evaluatePolicyAssessment(context, req);
  expect(context.exceptions[0].message).toEqual("bad");
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("processRequest-ok", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/teste2e");
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
  vi.stubGlobal("fetch", vi.fn());
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      json: () => Promise.resolve({ firewallPolicies: testPolicies }),
    }),
  );
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      json: () =>
        Promise.resolve({
          name: "projects/12345/assessments/1234567890",
          firewallPolicyAssessment: {
            firewallPolicy: {
              actions: [{ allow: {}, type: "allow" }],
            },
          },
        }),
    }),
  );
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      text: () => Promise.resolve("<HTML>Hello World</HTML>"),
    }),
  );
  const resp = await processRequest(context, req);
  expect(await resp.text()).toEqual("<HTML>Hello World</HTML>");
  expect(fetch).toHaveBeenCalledTimes(3);
});

test("processRequest-nomatch", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/teste2e");
  const testPolicies = [
    {
      name: "test-policy",
      description: "test-description",
      path: "/badpath1",
      condition: "recaptcha.score > 0.5",
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{ allow: {}, type: "allow" }],
    },
    {
      name: "test-policy2",
      description: "test-description2",
      path: "/badpath2",
      condition: "test-condition2",
      actions: [{ block: {}, type: "block" }],
    },
  ];
  vi.stubGlobal("fetch", vi.fn());
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      json: () => Promise.resolve({ firewallPolicies: testPolicies }),
    }),
  );
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      text: () => Promise.resolve("<HTML>Hello World</HTML>"),
    }),
  );
  const resp = await processRequest(context, req);
  expect(await resp.text()).toEqual("<HTML>Hello World</HTML>");
  expect(fetch).toHaveBeenCalledTimes(2);
});

test("processRequest-inject", async () => {
  const context = new TestContext(testConfig);
  context.config.sessionJsInjectPath = "/somepath;/some/other/path;/teste2e;/another/path";
  const req = new FetchApiRequest("https://www.example.com/teste2e");
  const testPolicies = [
    {
      name: "test-policy",
      description: "test-description",
      path: "/badpath1",
      condition: "recaptcha.score > 0.5",
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{ allow: {}, type: "allow" }],
    },
    {
      name: "test-policy2",
      description: "test-description2",
      path: "/badpath2",
      condition: "test-condition2",
      actions: [{ block: {}, type: "block" }],
    },
  ];
  vi.stubGlobal("fetch", vi.fn());
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      json: () => Promise.resolve({ firewallPolicies: testPolicies }),
    }),
  );
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      text: () => Promise.resolve("<HTML>Hello World</HTML>"),
    }),
  );
  const resp = await processRequest(context, req);
  expect(await resp.text()).toEqual('<HTML><script src="test.js"/>Hello World</HTML>');
  expect(fetch).toHaveBeenCalledTimes(2);
});

test("processRequest-noinject", async () => {
  const context = new TestContext(testConfig);
  context.config.sessionJsInjectPath = "/somepath;/some/other/path;/another/path";
  const req = new FetchApiRequest("https://www.example.com/teste2e");
  const testPolicies = [
    {
      name: "test-policy",
      description: "test-description",
      path: "/badpath1",
      condition: "recaptcha.score > 0.5",
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{ allow: {}, type: "allow" }],
    },
    {
      name: "test-policy2",
      description: "test-description2",
      path: "/badpath2",
      condition: "test-condition2",
      actions: [{ block: {}, type: "block" }],
    },
  ];
  vi.stubGlobal("fetch", vi.fn());
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      json: () => Promise.resolve({ firewallPolicies: testPolicies }),
    }),
  );
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      text: () => Promise.resolve("<HTML>Hello World</HTML>"),
    }),
  );
  const resp = await processRequest(context, req);
  expect(await resp.text()).toEqual("<HTML>Hello World</HTML>");
  expect(fetch).toHaveBeenCalledTimes(2);
});

test("processRequest-block", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/teste2e");
  const testPolicies = [
    {
      name: "test-policy",
      description: "test-description",
      path: "/teste2e",
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{ block: {}, type: "block" }],
    },
    {
      name: "test-policy2",
      description: "test-description2",
      path: "/badpath2",
      condition: "test-condition2",
      actions: [{ block: {}, type: "block" }],
    },
  ];
  vi.stubGlobal("fetch", vi.fn());
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      json: () => Promise.resolve({ firewallPolicies: testPolicies }),
    }),
  );
  const resp = await processRequest(context, req);
  expect(resp.status).toEqual(403);
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("processRequest-dump", async () => {
  const context = new TestContext({ ...testConfig, debug: true, unsafe_debug_dump_logs: true });
  const req = new FetchApiRequest("https://www.example.com/nomatch");
  req.addHeader("Content-Type", "application/json");
  req.addHeader("Hello", "World");
  const testPolicies = [
    {
      name: "test-policy",
      description: "test-description",
      path: "/teste2e",
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{ block: {}, type: "block" }],
    },
    {
      name: "test-policy2",
      description: "test-description2",
      path: "/badpath2",
      condition: "test-condition2",
      actions: [{ block: {}, type: "block" }],
    },
  ];
  vi.stubGlobal("fetch", vi.fn());
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers({ hello: "world", A: "B" }),
      json: () => Promise.resolve({ firewallPolicies: testPolicies }),
    }),
  );
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      text: () => Promise.resolve("<HTML>Hello World</HTML>"),
    }),
  );
  const resp = await processRequest(context, req);
  expect(await resp.json()).toEqual({
    logs: [
      ["debug", ["[rpc] listFirewallPolicies (ok)"]],
      ["debug", ["local assessment succeeded"]],
      ["debug", ["terminalAction: allow"]],
      ["debug", ["Applying response actions, ignoring request action"]],
    ],
    exceptions: [],
    create_assessment_headers: [],
    list_firewall_policies_headers: [
      ["a", "B"],
      ["hello", "world"],
    ],
  });
});

test("processRequest-raise", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/teste2e");
  vi.stubGlobal("fetch", vi.fn());
  (fetch as Mock).mockImplementationOnce(() => {
    throw "garbagelist";
  });
  (fetch as Mock).mockImplementationOnce(() => {
    throw "garbageassessment";
  });
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      text: () => Promise.resolve("<HTML>Hello World</HTML>"),
    }),
  );
  const resp = await processRequest(context, req);
  expect(resp.status).toEqual(200);
  expect(await resp.text()).toEqual("<HTML>Hello World</HTML>");
  expect(fetch).toHaveBeenCalledTimes(3);
});

test("createPartialEventWithSiteInfo-actionToken", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/teste2e");
  req.addHeader("X-Recaptcha-Token", "action-token");
  const site_info = await createPartialEventWithSiteInfo(context, req);
  const site_features = await context.buildEvent(req);
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    token: "action-token",
    siteKey: "action-site-key",
    userAgent: "test-user-agent",
    wafTokenAssessment: true,
    userIpAddress: "1.2.3.4",
  });
  expect(context.debug_trace.site_key_used).toEqual("action");
});

test("createPartialEventWithSiteInfo-regularActionToken-json", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest(
    new Request("https://www.example.com/teste2e", {
      body: JSON.stringify({
        "g-recaptcha-response": "regular-action-token",
      }),
      headers: {
        "content-type": "application/json;charset=UTF-8",
      },
      method: "POST",
    }),
  );
  const site_info = await createPartialEventWithSiteInfo(context, req);
  const site_features = await context.buildEvent(req);
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    token: "regular-action-token",
    siteKey: "enterprise-site-key",
    userAgent: "test-user-agent",
    wafTokenAssessment: false,
    userIpAddress: "1.2.3.4",
  });
  expect(context.debug_trace.site_key_used).toEqual("enterprise");
});

test("createPartialEventWithSiteInfo-regularActionToken-form-urlencoded", async () => {
  const context = new TestContext(testConfig);
  const formData = new URLSearchParams();
  formData.append("g-recaptcha-response", "regular-action-token-urlencoded");
  const req = new FetchApiRequest(
    new Request("https://www.example.com/teste2e", {
      body: formData.toString(),
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      method: "POST",
    }),
  );

  const site_info = await createPartialEventWithSiteInfo(context, req);
  const site_features = await context.buildEvent(req);
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    token: "regular-action-token-urlencoded",
    siteKey: "enterprise-site-key",
    userAgent: "test-user-agent",
    wafTokenAssessment: false,
    userIpAddress: "1.2.3.4",
  });
  expect(context.debug_trace.site_key_used).toEqual("enterprise");
});

test("createPartialEventWithSiteInfo-regularActionToken-multipart-form-data", async () => {
  const context = new TestContext(testConfig);
  // Create a mock multipart/form-data body.
  const crlf = "\r\n";
  const boundary = "----WebKitFormBoundary1234";
  let body = "";
  body += `--${boundary}${crlf}`;
  body += `Content-Disposition: form-data; name="g-recaptcha-response"${crlf}`;
  body += `Content-Type: text/plain${crlf}`;
  body += `${crlf}regular-action-token-multipart`;
  body += `--${boundary}--${crlf}`;

  const req = new FetchApiRequest(
    new Request("https://www.example.com/teste2e", {
      body: body,
      headers: {
        "content-type": `multipart/form-data; boundary=${boundary}`,
      },
      method: "POST",
    }),
  );

  const site_info = await createPartialEventWithSiteInfo(context, req);
  const site_features = await context.buildEvent(req);
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    token: "regular-action-token-multipart",
    siteKey: "enterprise-site-key",
    userAgent: "test-user-agent",
    wafTokenAssessment: false,
    userIpAddress: "1.2.3.4",
  });
  expect(context.debug_trace.site_key_used).toEqual("enterprise");
});

test("createPartialEventWithSiteInfo-sessionToken", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/test");
  req.addHeader("cookie", "blah=example; recaptcha-test-t=session=token; test=hithere");
  const site_info = await createPartialEventWithSiteInfo(context, req);
  const site_features = await context.buildEvent(req);
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    token: "session=token",
    siteKey: "session-site-key",
    userAgent: "test-user-agent",
    wafTokenAssessment: true,
    userIpAddress: "1.2.3.4",
  });
  expect(context.debug_trace.site_key_used).toEqual("session");
});

test("createPartialEventWithSiteInfo-strictSessionToken", async () => {
  const context = new TestContext(testConfig);
  context.config.strict_cookie = true;
  const req = new FetchApiRequest("https://www.example.com/test");
  req.addHeader("cookie", "recaptcha-example-t=session=token");
  const site_info = await createPartialEventWithSiteInfo(context, req);
  const site_features = await context.buildEvent(req);
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    siteKey: "express-site-key",
    express: true,
    userAgent: "test-user-agent",
    userIpAddress: "1.2.3.4",
  });
  expect(context.debug_trace.site_key_used).toEqual("express");
});

test("createPartialEventWithSiteInfo-nonStrictSessionToken", async () => {
  const context = new TestContext(testConfig);
  context.config.strict_cookie = false;
  const req = new FetchApiRequest("https://www.example.com/test");
  req.addHeader("cookie", "recaptcha-example-t=session=token");
  const site_info = await createPartialEventWithSiteInfo(context, req);
  const site_features = await context.buildEvent(req);
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    token: "session=token",
    siteKey: "session-site-key",
    userAgent: "test-user-agent",
    wafTokenAssessment: true,
    userIpAddress: "1.2.3.4",
  });
  expect(context.debug_trace.site_key_used).toEqual("session");
});

test("createPartialEventWithSiteInfo-challengeToken", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/test");
  req.addHeader("cookie", "recaptcha-test-e=challenge=token");
  const site_info = await createPartialEventWithSiteInfo(context, req);
  const site_features = await context.buildEvent(req);
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    token: "challenge=token",
    siteKey: "challenge-page-site-key",
    userAgent: "test-user-agent",
    wafTokenAssessment: true,
    userIpAddress: "1.2.3.4",
  });
  expect(context.debug_trace.site_key_used).toEqual("challenge");
});

test("createPartialEventWithSiteInfo-nonStrictChallengeToken", async () => {
  const context = new TestContext(testConfig);
  context.config.strict_cookie = false;
  const req = new FetchApiRequest("https://www.example.com/test");
  req.addHeader("cookie", "recaptcha-example-e=challenge=token");
  const site_info = await createPartialEventWithSiteInfo(context, req);
  const site_features = await context.buildEvent(req);
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    token: "challenge=token",
    siteKey: "challenge-page-site-key",
    userAgent: "test-user-agent",
    wafTokenAssessment: true,
    userIpAddress: "1.2.3.4",
  });
  expect(context.debug_trace.site_key_used).toEqual("challenge");
});

test("createPartialEventWithSiteInfo-express", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/test");
  const site_info = await createPartialEventWithSiteInfo(context, req);
  const site_features = await context.buildEvent(req);
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    siteKey: "express-site-key",
    userAgent: "test-user-agent",
    express: true,
    userIpAddress: "1.2.3.4",
  });
  expect(context.debug_trace.site_key_used).toEqual("express");
});

test("DebugTrace-format", () => {
  const context = new TestContext(testConfig);
  context.config.apiKey = "";
  context.config.recaptchaEndpoint = "";
  const trace = new DebugTrace(context);
  trace.list_firewall_policies_status = "ok";
  trace.policy_count = 10;
  trace.site_key_used = "session";
  expect(trace.formatAsHeaderValue()).toEqual(
    "list_firewall_policies_status=ok;policy_count=10;site_key_used=session;site_keys_present=asce;empty_config=apikey,endpoint;performance_counters=",
  );
});

test("getActions-localAssessment", async () => {
  const context = new TestContext(testConfig);
  context.config.sessionJsInjectPath = "/teste2e;/another/path";
  const req = new FetchApiRequest("https://www.example.com/teste2e");
  const testPolicies = [
    {
      name: "test-policy",
      description: "test-description",
      path: "/teste2e",
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{ block: {}, type: "block" }],
    },
    {
      name: "test-policy2",
      description: "test-description2",
      path: "/teste2e",
      actions: [{ block: {}, type: "redirect" }],
    },
  ];
  vi.stubGlobal("fetch", vi.fn());
  (fetch as Mock).mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      headers: new Headers(),
      json: () => Promise.resolve({ firewallPolicies: testPolicies }),
    }),
  );
  const actions = await getActions(context, req);
  expect(actions).toEqual([
    {
      injectjs: {},
    },
    {
      block: {},
      type: "block",
    },
  ]);
  expect(fetch).toHaveBeenCalledTimes(1);
});

test("getActions-createAssessment", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/testlocal");
  vi.stubGlobal("fetch", vi.fn());
  (fetch as Mock)
    .mockImplementationOnce((req) => {
      expect(req.url).toEqual("https://recaptchaenterprise.googleapis.com/v1/projects/12345/fetchFirewallPolicies");
      const testPolicies = [
        {
          name: "test-policy",
          description: "test-description",
          path: "/testlocal",
          // 'type' isn't a part of the interface, but is added for testing.
          condition: "test-condition",
          actions: [{ block: {}, type: "block" }],
        },
      ];
      Promise.resolve({
        status: 200,
        headers: new Headers(),
        json: () => Promise.resolve({ firewallPolicies: testPolicies }),
      });
    })
    .mockImplementationOnce((req) => {
      expect(req.url).toEqual("https://recaptchaenterprise.googleapis.com/v1/projects/12345/assessments?key=abc123");
      return Promise.resolve({
        status: 200,
        headers: new Headers(),
        json: () =>
          Promise.resolve({
            name: "projects/12345/assessments/1234567890",
            firewallPolicyAssessment: {
              firewallPolicy: {
                actions: [{ block: {}, type: "block" }],
              },
            },
          }),
      });
    });
  const actions = await getActions(context, req);
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(actions).toEqual([
    {
      block: {},
      type: "block",
    },
  ]);
});

test("applyPreRequestActions - terminal", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/teste2e");
  const resp = (await applyPreRequestActions(context, req, [{ block: {} }])) as EdgeResponse;
  expect(resp.status).toEqual(403);
});

test("applyPreRequestActions - non-terminal", async () => {
  const context = new TestContext(testConfig);
  const req = new FetchApiRequest("https://www.example.com/teste2e");
  expect(req.getHeader("my-custom-header")).toBeNull();
  const resp = await applyPreRequestActions(context, req, [
    {
      setHeader: {
        key: "my-custom-header",
        value: "test123",
      },
    },
  ]);
  expect(resp).toBeNull();
  expect(req.getHeader("my-custom-header")).toEqual("test123");
});

test("applyPostResponseActions", async () => {
  const context = new TestContext(testConfig);
  const inputResp: Promise<EdgeResponse> = Promise.resolve({
    status: 200,
    headers: new Headers(),
    text: () => "<HTML>Hello World</HTML>",
  });

  const resp = await applyPostResponseActions(context, await inputResp, [{injectjs: {}}]);
  expect(await resp.text()).toEqual('<HTML><script src="test.js"/>Hello World</HTML>');
});
