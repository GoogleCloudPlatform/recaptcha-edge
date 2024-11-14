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

import { AkamaiContext, RecaptchaConfig, recaptchaConfigFromRequest } from './index'
import { responseProvider } from './edge_worker'
import { createResponse } from 'create-response'
import { httpRequest, HttpResponse } from 'http-request'
import { Readable } from 'stream'
import 'whatwg-fetch'

describe('injectRecaptchaJs', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should inject the reCAPTCHA script into HTML <head>', async () => {
    const recaptchaConfig: RecaptchaConfig = {
      projectNumber: 123,
      apiKey: "apikey",
      recaptchaEndpoint: 'www.recaptchaenterprise.googleapis.com',
      sessionSiteKey: "sessionkey"
    };
    const MockAkamaiInstance = new AkamaiContext(recaptchaConfig)
    // Mock the response from httpRequest
    const mockHtml = `<!DOCTYPE html><html><head><h1>WAF TEST</h1></head><body></body></html>`;
    (httpRequest as jest.Mock).mockResolvedValue({
      body: Readable.from(mockHtml)
    })

    // Create a sample input Response
    const inputResponse = new Response(mockHtml, {
      status: 200,
      headers: { 'Content-Type': 'text/html' }
    })

    const outputResponse = await MockAkamaiInstance.injectRecaptchaJs(inputResponse)
    const bodyResponse = `<!DOCTYPE html>
    <html>
      <head>
        <h1>WAF TEST</h1>
        <script src="https://www.google.com/recaptcha/enterprise.js?render=123&waf=session" async defer></script>
      </head>
      <body>
      </body>
    </html>
    `;
    expect(await outputResponse.text()).toBe(bodyResponse);
    // expect(outputResponse).toEqual({status: 200, headers: {}, body: bodyResponse});
  })
})


// Mock the createResponse function (replace with your actual implementation)
// jest.mock('create-response', () => ({
//   createResponse: jest.fn()
// }));

describe('Akamai reCAPTCHA Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should assess the request and allow it based on firewall policies', async () => {
    const request = new Request('http://example.com/teste2e', {
      headers: {
        'X-Recaptcha-Token': 'action-token',
        'True-Connecting-IP': '1.2.3.4',
        'user-agent': 'test-user-agent'
      }
    });

    const recaptchaConfig: RecaptchaConfig = {
      projectNumber: 123,
      apiKey: "apikey",
      recaptchaEndpoint: 'www.recaptchaenterprise.googleapis.com',
      sessionSiteKey: "sessionkey"
    };
    // const mockAkamaiInstance = new AkamaiContext(recaptchaConfig);

    // Mock httpRequest to simulate fetching firewall policies
    const testPolicies = [
      {
        name: "test-policy",
        description: "test-description",
        path: "/action/allow",
        condition: "recaptcha.score > 0.5",
        // 'type' isn't a part of the interface, but is added for testing.
        actions: [{ allow: {}, type: "allow" }],
      },
      {
        name: "test-policy2",
        description: "test-description2",
        path: "/action/block",
        actions: [{ block: {}, type: "block" }],
      },
      {
        name: "test-policy3",
        description: "test-description3",
        path: "/action/redirect",
        condition: "recaptcha.score > 0.5",
        actions: [{ redirect: {}, type: "redirect" }],
      },
    ];

    (httpRequest as jest.Mock).mockResolvedValueOnce({
      status: 200,
      body: Readable.from(JSON.stringify({ firewallPolicies: testPolicies })),
      getHeaders: () => ({ 'Content-Type': 'application/json' })
    });

    (httpRequest as jest.Mock).mockResolvedValueOnce({
      status: 200,
      body: Readable.from(JSON.stringify({ firewallPolicyAssessment: {} })),
      getHeaders: () => ({ 'Content-Type': 'application/json' })
    });

    const mockHtml = '<HTML>Hello World</HTML>';
    (httpRequest as jest.Mock).mockResolvedValueOnce({
      status: 200,
      body: Readable.from(mockHtml),
      getHeaders: () => ({ 'Content-Type': 'text/html' })
    });

    // const response = await mockAkamaiInstance.fetch(request);
    const response = await responseProvider(request as any);

    expect(httpRequest).toHaveBeenCalledTimes(3);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('<HTML>Hello World</HTML>');
  });
});
