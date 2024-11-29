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

import { afterAll, afterEach, beforeAll, expect, test, vi } from "vitest";
import {responseProvider} from './edge_worker';


// Helper to convert a string to a Akamai Request/Response body.
function stringToStream(str: string): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  const encodedString = encoder.encode(str);

  return new ReadableStream({
    start(controller) {
      controller.enqueue(encodedString);
      controller.close();
    },
  });
}

async function readStream(stream: ReadableStream): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let result = await reader.read();
  let out = "";
  while (!result.done) {
    out += decoder.decode(new Uint8Array(result.value).buffer);
    result = await reader.read();
  }
  return out;
}

// Akamai IngressClientRequests conform to this structure.
const MockRequest = {
  url: "http://www.example.com",
  host: "example.com",
  method: "GET",
  path: "/",
  scheme: "http",
  query: "",
  userLocation: undefined,
  device: undefined,
  cpCode: 12345,
  clientIp: "192.168.0.1",
  wasTerminated: () => false,
  cacheKey: {
    excludeQueryString: () => { throw "unimplemented" },
    includeQueryString: () => { throw "unimplemented" },
    includeQueryArgument: () => { throw "unimplemented" },
    includeCookie: () => { throw "unimplemented" },
    includeHeader: () => { throw "unimplemented" },
    includeVariable: () => { throw "unimplemented" },
  },
  route: () => { throw "unimplemented" },
  getVariable: () => { return "" },
  setVariable: () => { return "" },
  respondWith: () => {throw "unimplemented" },
  getHeader: () => { throw "unimplemented" },
  getHeaders: () => { throw "unimplemented" },
  setHeader: () => { throw "unimplemented" },
  addHeader: () => { throw "unimplemented" },
  removeHeader: () => { throw "unimplemented" },
};

// Create a mock for httpRequest function. Needs to be 'hoisted' due to the way
// vi.mock works. See: https://vitest.dev/api/vi.html#vi-hoisted
const { mockHttpRequest } = vi.hoisted(() => {
  return { mockHttpRequest: vi.fn() }
})

beforeAll(() => {
  vi.mock('log', () => {
      return {
        logger: {
          log: vi.fn(() => {return {}})
        }
      }
  });
  vi.mock('streams', () => { return {}});
  vi.mock('html-rewriter', () => { return {}});
  vi.mock('http-request', () => { return {
    httpRequest: mockHttpRequest
  }});
  vi.mock('create-response', () => { 
    return { 
      createResponse: (status: number, headers: any, body: any) => { return Promise.resolve({status, headers, body}); }
    }
  });
});

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

  mockHttpRequest.mockImplementationOnce(() => { 
    const encoder = new TextEncoder();
    return Promise.resolve(
      {
        body: JSON.stringify({ firewallPolicies: testPolicies }),
        json: () => Promise.resolve({ firewallPolicies: testPolicies }),
        ok: true,
        status: 200,
        getHeader: () => undefined,
        getHeaders: () => [],
      });
    }
  ).mockImplementationOnce(() => { 
    const encoder = new TextEncoder();
    return Promise.resolve(
      {
        body: stringToStream("<HTML>HELLO WORLD!</HTML>"),
        ok: true,
        status: 200,
        getHeader: () => undefined,
        getHeaders: () => [],
      });
    }
  );

  let resp = await responseProvider(vi.mocked(MockRequest));
  expect(await readStream(resp.body as ReadableStream)).toEqual("<HTML>HELLO WORLD!</HTML>");
});

test("localmatch-ok", async () => {
  const testPolicies = [
    {
      name: "test-policy",
      description: "test-description",
      path: "/block",
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{ block: {}, type: "block" }],
    },
  ];

  mockHttpRequest.mockImplementationOnce(() => { 
    const encoder = new TextEncoder();
    return Promise.resolve(
      {
        body: JSON.stringify({ firewallPolicies: testPolicies }),
        json: () => Promise.resolve({ firewallPolicies: testPolicies }),
        ok: true,
        status: 200,
        getHeader: () => undefined,
        getHeaders: () => [],
      });
    }
  );

  let req = vi.mocked({
    ...MockRequest,
    url: "http://www.example.com/block",
    path: "/block",
  });
  let resp = await responseProvider(req);
  expect(resp.status).toEqual(403);
});