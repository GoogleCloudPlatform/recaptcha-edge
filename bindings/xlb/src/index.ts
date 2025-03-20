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
  HttpHeaders,
  HttpBody,
} from "../gen/envoy/service/ext_proc/v3/external_processor_pb.js";
import { ConnectRouter, ServiceImpl } from "@connectrpc/connect";

import * as http2 from "http2";
import { connectNodeAdapter } from "@connectrpc/connect-node";

class CalloutProcessor implements ServiceImpl<typeof ExternalProcessor> {
  async *process(requests: AsyncIterable<ProcessingRequest>): AsyncIterable<ProcessingResponse> {
    for await (const req of requests) {
      switch (req.request.case) {
        case "requestHeaders":
          yield await this.handleRequestHeaders(req.request.value);
          break;
        case "requestBody":
          yield await this.handleRequestBody(req.request.value);
          break;
        case "responseHeaders":
          yield await this.handleResponseHeaders(req.request.value);
          break;
        case "responseBody":
          yield await this.handleResponseBody(req.request.value);
          break;
        default:
          yield create(ProcessingResponseSchema, {
            response: {
              case: req.request.case ?? "immediateResponse",
              value: {},
            },
          });
      }
    }
  }

  async handleRequestHeaders(httpHeaders: HttpHeaders): Promise<ProcessingResponse> {
    return create(ProcessingResponseSchema, {
      response: {
        case: "requestHeaders",
        value: {},
      },
    });
  }

  async handleRequestBody(httpBody: HttpBody): Promise<ProcessingResponse> {
    return create(ProcessingResponseSchema, {
      response: {
        case: "requestBody",
        value: {},
      },
    });
  }

  async handleResponseHeaders(headers: HttpHeaders): Promise<ProcessingResponse> {
    return create(ProcessingResponseSchema, {
      response: {
        case: "responseHeaders",
        value: {},
      },
    });
  }

  async handleResponseBody(httpBody: HttpBody): Promise<ProcessingResponse> {
    return create(ProcessingResponseSchema, {
      response: {
        case: "responseBody",
        value: {},
      },
    });
  }
}

function getPort(defaultPort: number) {
  const asString = process.env.PORT || "";
  return parseInt(asString) || defaultPort;
}

export async function start(defaultPort: number, listeningListener?: () => void) {
  const routes = (router: ConnectRouter) => {
      router.service(ExternalProcessor, new CalloutProcessor());
  };

  http2.createServer(
      connectNodeAdapter({ routes }) // responds with 404 for other requests
    ).listen(getPort(defaultPort), '0.0.0.0', listeningListener);
}