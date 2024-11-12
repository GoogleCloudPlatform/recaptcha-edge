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
import { httpRequest, HttpResponse } from 'http-request'
import { Readable } from 'stream'
import 'whatwg-fetch'

type Env = any

describe('injectRecaptchaJs', () => {
  it('should inject the reCAPTCHA script into HTML <head>', async () => {
    const recaptchaConfig = recaptchaConfigFromEnv({} as Env)
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

    // inputResponse.body = mockHtml

    const outputResponse = await MockAkamaiInstance.injectRecaptchaJs(inputResponse)

    // Assertions - http
    expect(outputResponse.status).toBe(200)
    expect(outputResponse.headers.get('Content-Type')).toBe('text/html')

    // Check if the reCAPTCHA script is present in the HTML <head>
    expect(outputResponse).toContain(
      `<script src="https://www.google.com/recaptcha/enterprise.js?render=${recaptchaConfig.sessionSiteKey}&waf=session" async defer></script>`
    );
  })

it('should handle different headers', async () => {
  const recaptchaConfig = recaptchaConfigFromEnv({} as Env);
  const MockAkamaiInstance = new AkamaiContext({} as Env, recaptchaConfig);
  const mockHtml = `<!DOCTYPE html><html><head><h1>WAF TEST</h1></head><body></body></html>`;

  const inputResponse = new Response(mockHtml, {
    status: 200,
    headers: { 
      'Content-Type': 'text/html',
      'X-Custom-Header': 'test-value' // Additional header
    },
  });

  const outputResponse = await MockAkamaiInstance.injectRecaptchaJs(inputResponse);

  expect(outputResponse.headers.get('X-Custom-Header')).toBe('test-value');

});

it('should not inject the reCAPTCHA script if <head> tag is not within <html> tags', async () => {
  const recaptchaConfig = recaptchaConfigFromEnv({} as Env);
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

  // Read the modified HTML from the response body
  // let injectedHtml = '';
  // for await (const chunk of outputResponse as any) {
  //   injectedHtml += chunk;
  // }

  // Check if the reCAPTCHA script is present in the <head>
  expect(outputResponse).not.toContain(
    `<script src="https://www.google.com/recaptcha/enterprise.js?render=${recaptchaConfig.sessionSiteKey}&waf=session" async defer></script>`
  );
});

})
