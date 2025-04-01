/**
 * Copyright 2025 Google LLC
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

import { create } from "@bufbuild/protobuf";
import {
  ProcessingResponseSchema,
  ExternalProcessor,
  ProcessingRequest,
  ProcessingResponse,
} from "../gen/envoy/service/ext_proc/v3/external_processor_pb.js";
import { ConnectRouter, ServiceImpl } from "@connectrpc/connect";

import {
  fetchActions,
  applyPreRequestActions,
  applyPostResponseActions,
  Action,
  RecaptchaConfig,
} from "@google-cloud/recaptcha-edge";

import * as http2 from "http2";
import { connectNodeAdapter } from "@connectrpc/connect-node";
import { CalloutHeadersRequest, CalloutBodyResponse, XlbContext } from "./edge_binding.js";

class CalloutProcessor implements ServiceImpl<typeof ExternalProcessor> {
  ctx: XlbContext;

  constructor(ctx: XlbContext) {
    this.ctx = ctx;
  }

  async *process(requests: AsyncIterable<ProcessingRequest>): AsyncIterable<ProcessingResponse> {
    let actions: Action[] = [];
    for await (const req of requests) {
      switch (req.request.case) {
        case "requestHeaders":
          const headersRequest = new CalloutHeadersRequest(this.ctx, req.request.value);
          actions = await fetchActions(this.ctx, headersRequest);
          yield await this.handleRequestHeaders(headersRequest, actions);
          break;
        case "responseBody":
          const bodyResponse = new CalloutBodyResponse(this.ctx, req.request.value);
          yield await this.handleResponseBody(bodyResponse, actions);
          break;
        default:
          // Returning a default empty result for requestTrailers and responseTrailers.
          yield create(ProcessingResponseSchema, {
            response: {
              case: req.request.case ?? "immediateResponse",
              value: {},
            },
          });
      }
    }
  }

  async handleRequestHeaders(headersRequest: CalloutHeadersRequest, actions: Action[]): Promise<ProcessingResponse> {
    const resp = await applyPreRequestActions(this.ctx, headersRequest, actions);
    if (resp === null) {
      return headersRequest.toResponse();
    }
    return resp.toResponse();
  }

  async handleResponseBody(resp: CalloutBodyResponse, actions: Action[]): Promise<ProcessingResponse> {
    resp = await applyPostResponseActions(this.ctx, resp, actions);
    return resp.toResponse();
  }
}

function getPort(defaultPort: number): number {
  const asString = process.env.PORT || "";
  return parseInt(asString) || defaultPort;
}

export async function start(config: RecaptchaConfig, defaultPort: number, listeningListener?: () => void) {
  const ctx = new XlbContext(config);
  const routes = (router: ConnectRouter) => {
    router.service(ExternalProcessor, new CalloutProcessor(ctx));
  };

  http2
    .createServer(
      connectNodeAdapter({ routes }), // responds with 404 for other requests
    )
    .listen(getPort(defaultPort), "0.0.0.0", listeningListener);
}
