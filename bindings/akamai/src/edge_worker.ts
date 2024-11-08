/**
 * @fileoverview pre-written Akamai Edge Worker.
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

import {
  AkamaiContext,
  processRequest,
  recaptchaConfigFromEnv
} from './index'

type Env = any

/**
 * The Akamai Edge Worker function.
 *
 * This function is called by Akamai Edge to process incoming requests. It
 * creates an AkamaiContext object and then calls the processRequest function
 * to handle the request.
 */
export const edgeWorker = {
  async fetch (
    request: Request,
    env: Env
  ): Promise<Response> {
    const akamctx = new AkamaiContext(env, recaptchaConfigFromEnv(env))
    return await processRequest(akamctx, request)
  }
}
