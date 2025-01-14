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
 * @fileoverview pre-written Cloudflare Worker.
 */

type Env = any;

import { CloudflareContext, processRequest, recaptchaConfigFromEnv } from "./index";
import { PasswordCheckVerification } from 'recaptcha-password-check-helpers';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const cfctx = new CloudflareContext(env, ctx, recaptchaConfigFromEnv(env));

    // Only perform password check if the request is a POST to a specific path (login event).
    // The action token should be attached.
    if (request.method === 'POST' && new URL(request.url).pathname === '/verify-password') {
      const { username, password } = await request.json();
      try {
        const verification = await PasswordCheckVerification.create(
          username,
          password,
        );
        // Then use verifcation when calling CreateAssessment for a login event.
        // 1. Convert to lookupHashPrefix and encryptedUserCredentialsHash.
        // 2. make requests to `${BASE_URL}/v1/projects/${this.projectId}/assessments?key=${this.apiKey}`
        // 3. get the API response?
        return new Response(JSON.stringify({ success: true, verification }));
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }));
      }
    } else {
      // For other requests, process them normally without password verification.
      return processRequest(cfctx, request);
    }
  },
} satisfies ExportedHandler;
