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

import { createClient } from "@connectrpc/connect";
import { create, MessageInitShape } from "@bufbuild/protobuf";
import { createGrpcTransport } from "@connectrpc/connect-node";
import { describe, test, it, expect } from "vitest";
import * as calloutServer from "./index";
import express from "express";

import {
  ExternalProcessor,
  ProcessingRequestSchema,
  ProcessingResponse,
  ProcessingResponseSchema,
} from "../gen/envoy/service/ext_proc/v3/external_processor_pb.js";

type CalloutEvent =
  | "requestHeaders"
  | "requestBody"
  | "requestTrailers"
  | "responseHeaders"
  | "responseBody"
  | "responseTrailers";

describe("WAF Callouts Suite", async function () {
  // Start the callout server.
  const _ = await calloutServer.start(10023, () => {
    console.log("started server!");
  });

  // Create the client to talk to the callout server.
  const transport = createGrpcTransport({
    baseUrl: "http://127.0.0.1:10023",
    interceptors: [],
  });
  const client = createClient(ExternalProcessor, transport);

  it.each([
    { type: "requestHeaders" },
    { type: "requestBody" },
    { type: "requestTrailers" },
    { type: "responseHeaders" },
    { type: "responseBody" },
    { type: "responseTrailers" },
  ])("can handle event: $type", async (event) => {
    const resp = await sendRequest(client, {
      request: {
        case: event.type as CalloutEvent,
        value: {},
      },
    });
    const processingResponse = resp[0];
    // Ensure headers are preserved.
    expect(processingResponse).toStrictEqual(
      create(ProcessingResponseSchema, {
        response: {
          case: event.type as CalloutEvent,
          value: {},
        },
      }),
    );
  });
});

async function* genRequests(
  ...requests: MessageInitShape<typeof ProcessingRequestSchema>[]
): AsyncIterable<MessageInitShape<typeof ProcessingRequestSchema>> {
  for (const request of requests) {
    yield request;
  }
}

async function sendRequest(
  client,
  ...requests: MessageInitShape<typeof ProcessingRequestSchema>[]
): Promise<ProcessingResponse[]> {
  let count = 0;
  const ret: ProcessingResponse[] = [];

  const responses = client.process(genRequests(...requests));
  for await (const resp of responses) {
    ret.push(resp);
    count++;
    if (ret.length === requests.length) {
      return ret;
    }
  }
  return ret;
}
