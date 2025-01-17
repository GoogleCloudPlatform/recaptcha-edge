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

import { AkamaiContext, AkamaiRequest, AkamaiResponse, processRequest, recaptchaConfigFromRequest } from "./index";

/**
 * The Akamai Edge Worker event handler.
 *
 * This function is called by Akamai Edge to process incoming requests. It
 * creates an AkamaiContext object and then calls the processRequest function
 * to handle the request.
 */
import { createResponse } from "create-response";
export async function responseProvider(inreq: EW.ResponseProviderRequest) {
  const akamaiContext = new AkamaiContext(recaptchaConfigFromRequest(inreq));
  let resp = await processRequest(akamaiContext, new AkamaiRequest(inreq));
  return createResponse(resp.status, Object.fromEntries(resp.getHeaders()), (resp as AkamaiResponse).body);
}
