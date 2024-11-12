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

import { AkamaiContext, recaptchaConfigFromEnv } from './index'
import { createResponse } from 'create-response'
import { httpRequest, HttpResponse } from 'http-request'
import { Readable } from 'stream'
import 'whatwg-fetch'

type Env = any

describe('injectRecaptchaJs', () => {
  it('should inject the reCAPTCHA script into HTML <head>', async () => {
    const recaptchaConfig = recaptchaConfigFromEnv({} as Env)
    recaptchaConfig.sessionSiteKey = 123;
    const MockAkamaiInstance = new AkamaiContext({} as Env, recaptchaConfig)
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

it('should not inject the reCAPTCHA script if <head> tag is not within <html> tags', async () => {
  const recaptchaConfig = recaptchaConfigFromEnv({} as Env);
  recaptchaConfig.sessionSiteKey = 123;
  const MockAkamaiInstance = new AkamaiContext({} as Env, recaptchaConfig);

  const mockHtml = `<head><h1>WAF TEST</h1></head>`;

  (httpRequest as jest.Mock).mockResolvedValue({
    body: Readable.from(mockHtml)
  });

  const inputResponse = new Response(mockHtml, {
    status: 200,
    headers: { 'Content-Type': 'text/html' }
  });

  const outputResponse = await MockAkamaiInstance.injectRecaptchaJs(inputResponse);

  expect(outputResponse.status).toBe(200);
  expect(outputResponse.headers.get('Content-Type')).toBe('text/html');

  // Check if the reCAPTCHA script is not present in the <head>
  expect(outputResponse).not.toContain(
    `<script src="https://www.google.com/recaptcha/enterprise.js?render=123&waf=session" async defer></script>`
  );
});

})


// Mock the createResponse function (replace with your actual implementation)
// jest.mock('create-response', () => ({
//   createResponse: jest.fn()
// }));

describe('Akamai reCAPTCHA Firewall Policy Tests', () => {
  it('should assess the request and allow it based on firewall policies', async () => {
    const recaptchaConfig = recaptchaConfigFromEnv({} as Env);
    const mockAkamaiInstance = new AkamaiContext({} as Env, recaptchaConfig);

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

    // Mock httpRequest to simulate fetching the original HTML
    const mockHtml = '<HTML>Hello World</HTML>';
    (httpRequest as jest.Mock).mockResolvedValueOnce({ 
      status: 200, 
      body: Readable.from(mockHtml),
      getHeaders: () => ({ 'Content-Type': 'text/html' }) 
    });

    // Create a sample request
    const request = new Request('http://example.com/teste2e', {
      headers: {
        'X-Recaptcha-Token': 'action-token',
        'True-Client-IP': '1.2.3.4',
        'user-agent': 'test-user-agent'
      }
    });

    // Call the AkamaiContext's fetch method
    const response = await mockAkamaiInstance.fetch(request);

    // Assertions
    expect(httpRequest).toHaveBeenCalledTimes(1);
    // expect(response.status).toBe(200);
    // expect(response.text()).toBe('<HTML>Hello World</HTML>');
  });

});
