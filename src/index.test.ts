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
import {expect, test, vi} from 'vitest';

import {
  ActionSchema,
  applyActions,
  callCreateAssessment,
  callListFirewallPolicies,
  createPartialEventWithSiteInfo,
  evaluatePolicyAssessment,
  EventSchema,
  localPolicyAssessment,
  policyConditionMatch,
  policyPathMatch,
  processRequest,
  RecaptchaConfig,
  RecaptchaContext,
  SetHeaderAction,
} from './index';

import {ActionSchema, createBlockAction} from './action';

class TestContext extends RecaptchaContext {
  config: RecaptchaConfig = {
    recaptchaEndpoint: 'https://recaptchaenterprise.googleapis.com',
    projectNumber: '12345',
    apiKey: 'abc123',
    actionSiteKey: 'action-site-key',
    expressSiteKey: 'express-site-key',
    sessionSiteKey: 'session-site-key',
    challengePageSiteKey: 'challenge-page-site-key',
  };
  sessionPageCookie = 'recaptcha-test-t';
  challengePageCookie = 'recaptcha-test-e';
  httpGetCachingEnabled = true;
  logException = (e: any) => {
    // Do nothing.
  };
  log = (level: LogLevel, msg: string) => {
    // Do nothing.
  };
  buildEvent = (req: Request) => {
    return EventSchema.parse({
      'userIpAddress': '1.2.3.4',
      'userAgent': 'test-user-agent',
    });
  };
  injectRecaptchaJs = async (resp: Response) => {
    let html = await resp.text();
    html = html.replace('<HTML>', '<HTML><script src="test.js"/>');
    return new Response(html, resp);
  };
}

test('callCreateAssessment-ok', async () => {
  const baseEvent = {};
  const testEvent = {
    'token': 'test-token',
    'siteKey': 'action-site-key',
    'wafTokenAssessment': true,
  };
  const testAssessment = {
    event: testEvent,
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve({
        json: () => Promise.resolve(testAssessment),
      }),
    ),
  );

  const testContext = {
    ...new TestContext(),
    buildEvent: (req: Request) => {
      return baseEvent;
    },
    fetch: (req, options) => fetch(req, options),
  };

  const resp = await callCreateAssessment(
    testContext,
    new Request('https://www.google.com', {
      headers: {
        'X-Recaptcha-Token': 'test-token',
      },
    }),
    ['test-env', 'test-version'],
  );
  expect(fetch).toHaveBeenCalledWith(
    'https://recaptchaenterprise.googleapis.com/v1/projects/12345/assessments?key=abc123',
    {
      'body': JSON.stringify({
        event: testEvent,
        assessmentEnvironment: {client: 'test-env', version: 'test-version'},
      }),
      'headers': {
        'content-type': 'application/json;charset=UTF-8',
      },
      'method': 'POST',
    },
  );
  expect(resp).toEqual(testAssessment);
});

test('callListFirewallPolicies-ok', async () => {
  const testPolicies = [
    {
      name: 'test-policy',
      description: 'test-description',
      path: 'test-path',
      condition: 'test-condition',
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{allow: {}, type: 'allow'}],
    },
    {
      name: 'test-policy2',
      description: 'test-description2',
      path: 'test-path2',
      condition: 'test-condition2',
      actions: [{block: {}, type: 'block'}],
    },
  ];
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve({
        json: () =>
          Promise.resolve({
            firewallPolicies: testPolicies,
          }),
      }),
    ),
  );

  const resp = await callListFirewallPolicies(new TestContext());
  expect(fetch).toHaveBeenCalledWith(
    'https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000',
    {
      'headers': {
        'content-type': 'application/json;charset=UTF-8',
      },
      'method': 'GET',
    },
  );
  expect(resp).toEqual({
    firewallPolicies: testPolicies,
  });
});

test('ActionSchema-parseOk', () => {
  const allowaction: Action = ActionSchema.parse(JSON.parse('{"allow":{}}'));
  expect(allowaction.type).toEqual('allow');
  const shaction: Action = ActionSchema.parse(
    JSON.parse('{"setHeader":{"key":"test-key","value":"test-value"}}'),
  );
  expect(shaction.type).toEqual('setHeader');
  const shaction2 = shaction as SetHeaderAction;
  expect(shaction2.setHeader.key).toEqual('test-key');
  expect(shaction2.setHeader.value).toEqual('test-value');
});

test('ApplyActions-allow', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/doallow');
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve({status: 200, text: () => '<HTML>Hello World</HTML>'}),
    ),
  );
  const resp = await applyActions(context, req, [
    ActionSchema.parse({allow: {}}),
  ]);
  expect(resp.status).toEqual(200);
  expect(resp.text()).toEqual('<HTML>Hello World</HTML>');
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('ApplyActions-block', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/doblock');
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve({status: 200, text: () => '<HTML>Hello World</HTML>'}),
    ),
  );
  const resp = await applyActions(context, req, [createBlockAction()]);
  expect(resp).toEqual(new Response(null, {status: 403}));
  expect(resp.status).toEqual(403);
  // TODO: custom html
  expect(fetch).toHaveBeenCalledTimes(0);
});

test('ApplyActions-setHeader', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/setheader');
  vi.stubGlobal(
    'fetch',
    vi.fn((req) => {
      expect(req.headers.get('test-key')).toEqual('test-value');
      return Promise.resolve({
        status: 200,
        text: () => '<HTML>Hello World</HTML>',
      });
    }),
  );
  const resp = await applyActions(context, req, [
    ActionSchema.parse({setHeader: {key: 'test-key', value: 'test-value'}}),
  ]);
  expect(resp.status).toEqual(200);
  expect(resp.text()).toEqual('<HTML>Hello World</HTML>');
  expect(fetch).toHaveBeenCalledTimes(1);
});
test('ApplyActions-redirect', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/originalreq');
  req.headers.set('test-key', 'test-value');
  vi.stubGlobal(
    'fetch',
    vi.fn((req) => {
      expect(req.url).toEqual('https://www.google.com/recaptcha/challengepage');
      expect(req.headers.get('test-key')).toEqual(null);
      expect(req.headers.get('X-ReCaptcha-Soz')).toEqual(
        'CgQBAgMEKg93d3cuZXhhbXBsZS5jb20aF2NoYWxsZW5nZS1wYWdlLXNpdGUta2V5OLlg',
      );
      return Promise.resolve({
        status: 200,
        text: () => '<HTML>Hello World</HTML>',
      });
    }),
  );
  const resp = await applyActions(context, req, [
    ActionSchema.parse({redirect: {}}),
  ]);
  expect(resp.status).toEqual(200);
  expect(resp.text()).toEqual('<HTML>Hello World</HTML>');
  expect(fetch).toHaveBeenCalledTimes(1);
});
test('ApplyActions-substitute', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/substitute');
  vi.stubGlobal(
    'fetch',
    vi.fn((req) => {
      expect(req.url).toEqual('https://www.example.com/newdest');
      return Promise.resolve({
        status: 200,
        text: () => '<HTML>Hello World</HTML>',
      });
    }),
  );
  const resp = await applyActions(context, req, [
    ActionSchema.parse({substitute: {path: '/newdest'}}),
  ]);
  expect(resp.status).toEqual(200);
  expect(resp.text()).toEqual('<HTML>Hello World</HTML>');
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('ApplyActions-injectJs', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/testinject');
  vi.stubGlobal(
    'fetch',
    vi.fn((req) => {
      expect(req.url).toEqual('https://www.example.com/testinject');
      return Promise.resolve({
        status: 200,
        text: () => '<HTML>Hello World</HTML>',
      });
    }),
  );
  const resp = await applyActions(context, req, [
    ActionSchema.parse({injectjs: {}}),
  ]);
  expect(resp.status).toEqual(200);
  // calls the TestContext injectRecaptchaJs.
  expect(await resp.text()).toEqual(
    '<HTML><script src="test.js"/>Hello World</HTML>',
  );
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('ApplyActions-injectJsOnlyOnce', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/testinject');
  vi.stubGlobal(
    'fetch',
    vi.fn((req) => {
      expect(req.url).toEqual('https://www.example.com/testinject');
      return Promise.resolve({
        status: 200,
        text: () => '<HTML>Hello World</HTML>',
      });
    }),
  );
  const resp = await applyActions(context, req, [
    ActionSchema.parse({injectjs: {}}),
    ActionSchema.parse({injectjs: {}}),
  ]);
  expect(resp.status).toEqual(200);
  // calls the TestContext injectRecaptchaJs.
  expect(await resp.text()).toEqual(
    '<HTML><script src="test.js"/>Hello World</HTML>',
  );
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('localPolicyAssessment-matchTrivialCondition', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/testlocal');
  const testPolicies = [
    {
      name: 'projects/12345/firewallpolicies/100',
      description: 'test-description',
      path: '/badpath',
      condition: 'recaptcha.score > 0.5',
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{allow: {}, type: 'allow'}],
    },
    {
      name: 'projects/12345/firewallpolicies/200',
      description: 'test-description2',
      path: '/testlocal',
      condition: 'true',
      actions: [{block: {}, type: 'block'}],
    },
  ];
  vi.stubGlobal(
    'fetch',
    vi.fn((url) => {
      expect(url).toEqual(
        'https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000',
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
  expect(localAssessment as action.Action[]).toEqual([
    ActionSchema.parse({block: {}}),
  ]);
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('localPolicyAssessment-noMatch', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/testlocal');
  const testPolicies = [
    {
      name: 'projects/12345/firewallpolicies/100',
      description: 'test-description',
      path: '/badpath',
      condition: 'true',
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{block: {}, type: 'block'}],
    },
    {
      name: 'projects/12345/firewallpolicies/200',
      description: 'test-description2',
      path: '/blahblah',
      condition: 'true',
      actions: [{block: {}, type: 'block'}],
    },
  ];
  vi.stubGlobal(
    'fetch',
    vi.fn((url) => {
      expect(url).toEqual(
        'https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000',
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
  expect(localAssessment as action.Action[]).toEqual([
    ActionSchema.parse({allow: {}}),
  ]);
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('localPolicyAssessment-matchNontrivialCondition', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/testlocal');
  const testPolicies = [
    {
      name: 'projects/12345/firewallpolicies/100',
      description: 'test-description',
      path: '/badpath',
      condition: 'true',
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{allow: {}, type: 'allow'}],
    },
    {
      name: 'projects/12345/firewallpolicies/200',
      description: 'test-description2',
      path: '/testlocal',
      condition: 'recaptcha.score > 0.5',
      actions: [{block: {}, type: 'block'}],
    },
  ];
  vi.stubGlobal(
    'fetch',
    vi.fn((url) => {
      expect(url).toEqual(
        'https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000',
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
  expect(localAssessment).toEqual('recaptcha-required');
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('policyPathMatch', async () => {
  expect(
    policyPathMatch(
      {
        name: 'projects/12345/firewallpolicies/100',
        description: 'test-description',
        path: '/goodpath',
        condition: 'true',
        // 'type' isn't a part of the interface, but is added for testing.
        actions: [{allow: {}, type: 'allow'}],
      },
      new Request('https://www.example.com/goodpath'),
    ),
  ).toEqual(true);
  expect(
    policyPathMatch(
      {
        path: '/goo?path',
      },
      new Request('https://www.example.com/goodpath'),
    ),
  ).toEqual(true);
  expect(
    policyPathMatch({}, new Request('https://www.example.com/goodpath')),
  ).toEqual(true);
  expect(
    policyPathMatch(
      {
        path: '/goodppath',
      },
      new Request('https://www.example.com/goodpath'),
    ),
  ).toEqual(false);
  expect(
    policyPathMatch(
      {
        path: '/badppath',
      },
      new Request('https://www.example.com/badpath'),
    ),
  ).toEqual(false);
  expect(
    policyPathMatch(
      {
        path: '/wild/*/path',
      },
      new Request('https://www.example.com/wild/card/path'),
    ),
  ).toEqual(true);
  expect(
    policyPathMatch(
      {
        path: '/wild/card/*a*',
      },
      new Request('https://www.example.com/wild/card/path'),
    ),
  ).toEqual(true);
  expect(
    policyPathMatch(
      {
        path: '/wild/**/path',
      },
      new Request('https://www.example.com/wild/long/card/path'),
    ),
  ).toEqual(true);
});

test('policyConditionMatch', async () => {
  expect(
    policyConditionMatch(
      {
        name: 'projects/12345/firewallpolicies/100',
        description: 'test-description',
        path: '/goodpath',
        condition: 'true',
        // 'type' isn't a part of the interface, but is added for testing.
        actions: [{allow: {}, type: 'allow'}],
      },
      new Request('https://www.example.com/goodpath'),
    ),
  ).toEqual(true);

  expect(
    policyConditionMatch({}, new Request('https://www.example.com/goodpath')),
  ).toEqual(true);

  expect(
    policyConditionMatch(
      {
        condition: 'false',
      },
      new Request('https://www.example.com/goodpath'),
    ),
  ).toEqual(false);

  expect(
    policyConditionMatch(
      {
        condition: 'recaptcha.score > 0.5',
      },
      new Request('https://www.example.com/goodpath'),
    ),
  ).toEqual('unknown');
});

test('localPolicyAssessment-failedRpc', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/testlocal');
  vi.stubGlobal(
    'fetch',
    vi.fn((url) => {
      expect(url).toEqual(
        'https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000',
      );
      return Promise.reject(new Error('test-error'));
    }),
  );
  const localAssessment = await localPolicyAssessment(context, req);
  expect(localAssessment).toEqual('recaptcha-required');
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('localPolicyAssessment-badJson', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/testlocal');
  vi.stubGlobal(
    'fetch',
    vi.fn((url) => {
      expect(url).toEqual(
        'https://recaptchaenterprise.googleapis.com/v1/projects/12345/firewallpolicies?key=abc123&page_size=1000',
      );
      return Promise.resolve({
        status: 200,
        json: () => Promise.reject(new Error('test-error')),
      });
    }),
  );
  const localAssessment = await localPolicyAssessment(context, req);
  expect(localAssessment).toEqual('recaptcha-required');
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('evaluatePolicyAssessment-ok', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/testlocal');
  vi.stubGlobal(
    'fetch',
    vi.fn((url) => {
      expect(url).toEqual(
        'https://recaptchaenterprise.googleapis.com/v1/projects/12345/assessments?key=abc123',
      );
      return Promise.resolve({
        status: 200,
        json: () =>
          Promise.resolve({
            name: 'projects/12345/assessments/1234567890',
            firewallPolicyAssessment: {
              firewallPolicy: {
                actions: [{block: {}, type: 'block'}],
              },
            },
          }),
      });
    }),
  );
  const assessment = await evaluatePolicyAssessment(context, req);
  expect(assessment[0].type).toEqual('block');
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('evaluatePolicyAssessment-failedRpc', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/testlocal');
  vi.stubGlobal(
    'fetch',
    vi.fn((url) => {
      expect(url).toEqual(
        'https://recaptchaenterprise.googleapis.com/v1/projects/12345/assessments?key=abc123',
      );
      return Promise.reject(new Error('test-error'));
    }),
  );
  const assessment = await evaluatePolicyAssessment(context, req);
  expect(assessment[0].type).toEqual('allow');
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('evaluatePolicyAssessment-badJson', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/testlocal');
  vi.stubGlobal(
    'fetch',
    vi.fn((url) => {
      expect(url).toEqual(
        'https://recaptchaenterprise.googleapis.com/v1/projects/12345/assessments?key=abc123',
      );
      return Promise.resolve({
        status: 200,
        json: () => Promise.reject(new Error('test-error')),
      });
    }),
  );
  const assessment = await evaluatePolicyAssessment(context, req);
  expect(assessment[0].type).toEqual('allow');
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('processRequest-ok', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/teste2e');
  const testPolicies = [
    {
      name: 'test-policy',
      description: 'test-description',
      path: '/teste2e',
      condition: 'recaptcha.score > 0.5',
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{allow: {}, type: 'allow'}],
    },
    {
      name: 'test-policy2',
      description: 'test-description2',
      path: 'test-path2',
      condition: 'test-condition2',
      actions: [{block: {}, type: 'block'}],
    },
  ];
  vi.stubGlobal('fetch', vi.fn());
  fetch.mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      json: () => Promise.resolve({firewallPolicies: testPolicies}),
    }),
  );
  fetch.mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      json: () =>
        Promise.resolve({
          name: 'projects/12345/assessments/1234567890',
          firewallPolicyAssessment: {
            firewallPolicy: {
              actions: [{allow: {}, type: 'allow'}],
            },
          },
        }),
    }),
  );
  fetch.mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      text: () => Promise.resolve('<HTML>Hello World</HTML>'),
    }),
  );
  const resp = await processRequest(context, req);
  expect(await resp.text()).toEqual('<HTML>Hello World</HTML>');
  expect(fetch).toHaveBeenCalledTimes(3);
});

test('processRequest-nomatch', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/teste2e');
  const testPolicies = [
    {
      name: 'test-policy',
      description: 'test-description',
      path: '/badpath1',
      condition: 'recaptcha.score > 0.5',
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{allow: {}, type: 'allow'}],
    },
    {
      name: 'test-policy2',
      description: 'test-description2',
      path: '/badpath2',
      condition: 'test-condition2',
      actions: [{block: {}, type: 'block'}],
    },
  ];
  vi.stubGlobal('fetch', vi.fn());
  fetch.mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      json: () => Promise.resolve({firewallPolicies: testPolicies}),
    }),
  );
  fetch.mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      text: () => Promise.resolve('<HTML>Hello World</HTML>'),
    }),
  );
  const resp = await processRequest(context, req);
  expect(await resp.text()).toEqual('<HTML>Hello World</HTML>');
  expect(fetch).toHaveBeenCalledTimes(2);
});

test('processRequest-block', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/teste2e');
  const testPolicies = [
    {
      name: 'test-policy',
      description: 'test-description',
      path: '/teste2e',
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{block: {}, type: 'block'}],
    },
    {
      name: 'test-policy2',
      description: 'test-description2',
      path: '/badpath2',
      condition: 'test-condition2',
      actions: [{block: {}, type: 'block'}],
    },
  ];
  vi.stubGlobal('fetch', vi.fn());
  fetch.mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      json: () => Promise.resolve({firewallPolicies: testPolicies}),
    }),
  );
  const resp = await processRequest(context, req);
  expect(resp.status).toEqual(403);
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('processRequest-raise', async () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/teste2e');
  vi.stubGlobal('fetch', vi.fn());
  fetch.mockImplementationOnce(() => {
    throw 'garbagelist';
  });
  fetch.mockImplementationOnce(() => {
    throw 'garbageassessment';
  });
  fetch.mockImplementationOnce(() =>
    Promise.resolve({
      status: 200,
      text: () => Promise.resolve('<HTML>Hello World</HTML>'),
    }),
  );
  const resp = await processRequest(context, req);
  expect(resp.status).toEqual(200);
  expect(await resp.text()).toEqual('<HTML>Hello World</HTML>');
  expect(fetch).toHaveBeenCalledTimes(3);
});

test('insertFeaturesIntoEvent-actionToken', () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/teste2e', {
    headers: {'X-Recaptcha-Token': 'action-token'},
  });
  const site_info = createPartialEventWithSiteInfo(context, req);
  const site_features = EventSchema.parse(context.buildEvent(req));
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    token: 'action-token',
    siteKey: 'action-site-key',
    userAgent: 'test-user-agent',
    wafTokenAssessment: true,
    userIpAddress: '1.2.3.4',
  });
});

test('insertFeaturesIntoEvent-sessionToken', () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/test', {
    headers: {'cookie': 'recaptcha-test-t=session-token'},
  });
  const site_info = createPartialEventWithSiteInfo(context, req);
  const site_features = EventSchema.parse(context.buildEvent(req));
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    token: 'session-token',
    siteKey: 'session-site-key',
    userAgent: 'test-user-agent',
    wafTokenAssessment: true,
    userIpAddress: '1.2.3.4',
  });
});

test('insertFeaturesIntoEvent-challengeToken', () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/test', {
    headers: {'cookie': 'recaptcha-test-e=challenge-token'},
  });
  const site_info = createPartialEventWithSiteInfo(context, req);
  const site_features = EventSchema.parse(context.buildEvent(req));
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    token: 'challenge-token',
    siteKey: 'challenge-page-site-key',
    userAgent: 'test-user-agent',
    wafTokenAssessment: true,
    userIpAddress: '1.2.3.4',
  });
});

test('insertFeaturesIntoEvent-express', () => {
  const context = new TestContext();
  const req = new Request('https://www.example.com/test', {});
  const site_info = createPartialEventWithSiteInfo(context, req);
  const site_features = EventSchema.parse(context.buildEvent(req));
  const event = {
    ...site_info,
    ...site_features,
  };
  expect(event).toEqual({
    siteKey: 'express-site-key',
    userAgent: 'test-user-agent',
    express: true,
    userIpAddress: '1.2.3.4',
  });
});
