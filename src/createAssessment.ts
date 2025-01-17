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
 * @fileoverview Helper functions and types related to the CreateAssessment RPC.
 */

import * as action from "./action";
import { Assessment, AssessmentSchema, Event, EventSchema, RpcErrorSchema } from "./assessment";
import * as error from "./error";
import { EdgeRequest, EdgeResponse, RecaptchaContext } from "./index";
import picomatch from "picomatch";

/**
 * Adds reCAPTCHA specific values to an Event strucutre.
 * This includes, the siteKey, the token, cookies, and flags like express.
 */
export function createPartialEventWithSiteInfo(context: RecaptchaContext, req: EdgeRequest): Event {
  const event: Event = {};
  const actionToken = req.getHeader("X-Recaptcha-Token");
  if (context.config.actionSiteKey && actionToken) {
    event.token = actionToken;
    event.siteKey = context.config.actionSiteKey;
    event.wafTokenAssessment = true;
    context.debug_trace.site_key_used = "action";
    context.log("debug", "siteKind: action");
  } else {
    const cookieMap = new Map<string, string>();
    let challengeToken: string | undefined;
    let sessionToken: string | undefined;
    for (const cookie of req.getHeader("cookie")?.split(";") ?? []) {
      const [key, value] = cookie.split("=");
      cookieMap.set(key.trim(), value.trim());

      // Non-strict cookie parsing will match any 'recaptcha-*-t' token.
      // This is useful for using an existing key in a different WAF than registered
      // specifically for testing.
      if (!context.config.strict_cookie) {
        if (picomatch.isMatch(key.trim(), "recaptcha-*-t")) {
          sessionToken = value.trim();
        } else if (picomatch.isMatch(key.trim(), "recaptcha-*-e")) {
          challengeToken = value.trim();
        }
      }
    }

    if (!challengeToken) {
      challengeToken = cookieMap.get(context.challengePageCookie);
    }
    if (!sessionToken) {
      sessionToken = cookieMap.get(context.sessionPageCookie);
    }
    if (context.config.debug) {
      // eslint-disable-next-line  @typescript-eslint/no-unused-vars
      for (const [key, value] of cookieMap.entries()) {
        if (key.startsWith("recaptcha") && key !== context.challengePageCookie && key !== context.sessionPageCookie) {
          context.log(
            "info",
            "An unused reCAPTCHA cookie in the request matches a different environment: " +
              key +
              ". This may signify a misconfiguration.",
          );
        }
      }
    }

    if (context.config.challengePageSiteKey && challengeToken) {
      event.token = challengeToken;
      event.siteKey = context.config.challengePageSiteKey;
      event.wafTokenAssessment = true;
      context.debug_trace.site_key_used = "challenge";
      context.log("debug", "siteKind: challenge");
    } else if (context.config.sessionSiteKey && sessionToken) {
      event.token = sessionToken;
      event.siteKey = context.config.sessionSiteKey;
      event.wafTokenAssessment = true;
      context.debug_trace.site_key_used = "session";
      context.log("debug", "siteKind: session");
    } else if (context.config.expressSiteKey) {
      event.siteKey = context.config.expressSiteKey;
      event.express = true;
      context.debug_trace.site_key_used = "express";
      context.log("debug", "siteKind: express");
    } else {
      context.debug_trace.site_key_used = "none";
      throw new error.RecaptchaError(
        "No site key was found matching the incoming request token, and express is not enabled.",
        action.createAllowAction(),
      );
    }
  }
  return event;
}

/**
 * Call the reCAPTCHA API to create an assessment.
 */
export async function callCreateAssessment(
  context: RecaptchaContext,
  req: EdgeRequest,
  environment?: [string, string],
  additionalParams?: Event,
): Promise<Assessment> {
  // TODO: this should use a builder pattern. with a CreateAssessmentRequest
  // type.
  const site_info = createPartialEventWithSiteInfo(context, req);
  const site_features = EventSchema.parse(context.buildEvent(req));
  const event = {
    ...site_info,
    ...site_features,
    ...additionalParams,
  };
  const assessment: Assessment = { event };
  if (environment) {
    assessment.assessmentEnvironment = {
      client: environment[0],
      version: environment[1],
    };
  }
  const options: RequestInit = {
    method: "POST",
    body: JSON.stringify(assessment),
    headers: {
      "content-type": "application/json;charset=UTF-8",
    },
  };

  const endpoint = context.config.recaptchaEndpoint;
  const projectNumber = context.config.projectNumber;
  const apiKey = context.config.apiKey;
  const assessmentUrl = `${endpoint}/v1/projects/${projectNumber}/assessments?key=${apiKey}`;

  return context
    .fetch_create_assessment(assessmentUrl, options)
    .then((response) => {
      return response
        .json()
        .then((json) => {
          const ret = AssessmentSchema.safeParse(json);
          if (ret.success && Object.keys(ret.data).length > 0) {
            context.debug_trace.create_assessment = "ok";
            return ret.data;
          }
          const err_ret = RpcErrorSchema.required().safeParse(json);
          if (err_ret.success) {
            throw err_ret.data.error;
          }
          throw { message: "Response does not conform to Assesment schema: " + json };
        })
        .catch((reason) => {
          throw new error.ParseError(reason.message, action.createAllowAction());
        });
    })
    .catch((reason) => {
      context.log("debug", "[rpc] createAssessment (fail)");
      context.debug_trace.create_assessment = "err";
      if (reason instanceof error.RecaptchaError) {
        throw reason;
      }
      throw new error.NetworkError(reason.message, action.createAllowAction());
    });
}
