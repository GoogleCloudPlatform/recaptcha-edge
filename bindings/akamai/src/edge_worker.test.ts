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

import { afterEach, beforeAll, expect, test, vi } from "vitest";
vi.mock('http-request');
import {responseProvider} from './edge_worker'

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
    httpRequest: () => { throw "unimplemented "}
  }});
  vi.mock('create-response', () => { return {}});
});
// Ensure we matched every mock we defined
afterEach(() => {});

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

  vi.mock('http-request', () => { return {
    httpRequest: () => { return Promise.resolve(new Response("<html>body</html>")); }
  }});

  let mock_req = vi.mocked({
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
  });
  responseProvider(mock_req);
});
