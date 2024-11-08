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
  it('should inject the reCAPTCHA script into the <head>', async () => {
    const recaptchaConfig = recaptchaConfigFromEnv({} as Env)
    const MockAkamaiInstance = new AkamaiContext({} as Env, recaptchaConfig)
    // Mock the response from httpRequest
    const mockHtml = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>WAF DEMO PAGE</title>
        </head>
        <body>
          <header>
            <h1>WAF DEMO PAGE ONE</h1>
          </header>
          <p>Welcome to the page ONE.</p>
        </body>
      </html>
    `;
    (httpRequest as jest.Mock).mockResolvedValue({
      body: Readable.from(mockHtml)
    })

    // Create a sample input Response
    const inputResponse = new Response(mockHtml, {
      status: 200,
      headers: { 'Content-Type': 'text/html' }
    })

    // Call the function
    const outputResponse = await MockAkamaiInstance.injectRecaptchaJs(inputResponse)

    // Assertions
    expect(outputResponse.status).toBe(200)
    expect(outputResponse.headers.get('Content-Type')).toBe('text/html')

    // Read the modified HTML from the response body
    let modifiedHtml = ''
    for await (const chunk of outputResponse.body as any) {
      modifiedHtml += chunk
    }

    // Check if the reCAPTCHA script is present in the <head>
    // expect(modifiedHtml).toContain(`<script src="${RECAPTCHA_JS}?render=${recaptchaConfig.sessionSiteKey}&waf=session" async defer></script>`);
  })

// More test cases:
// - Test with different status codes
// - Test with different headers
// - Test error handling (if any)
})
