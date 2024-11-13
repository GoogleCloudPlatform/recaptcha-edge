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
import { HtmlRewritingStream } from "html-rewriter";
import { httpRequest } from "http-request";
import { createResponse } from "create-response";

type Env = any

/**
 * The Akamai Edge Worker event handler.
 *
 * This function is called by Akamai Edge to process incoming requests. It
 * creates an AkamaiContext object and then calls the processRequest function
 * to handle the request.
 */

export async function responseProvider(request: EW.IngressClientRequest) {
  const recaptchaConfig = recaptchaConfigFromEnv(request);
  // convert the Akamai request to Request
  const akamaiContext = new AkamaiContext(recaptchaConfig);

  // Use the akamaiContext and its methods to handle the request
  const response = await processRequest(akamaiContext, request as any);

  // convert Response back to createResponse
  return createResponse(200, {}, response.body as any);
}
