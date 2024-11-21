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
import { RecaptchaContext } from "./index";

/**
 * Adds reCAPTCHA specific values to an Event strucutre.
 * This includes, the siteKey, the token, cookies, and flags like express.
 */
export function createPartialEventWithSiteInfo(
  context: RecaptchaContext,
  req: Request,
): Event {
  const event: Event = {};
  const actionToken = req.headers.get("X-Recaptcha-Token");
  if (context.config.actionSiteKey && actionToken) {
    event.token = actionToken;
    event.siteKey = context.config.actionSiteKey;
    event.wafTokenAssessment = true;
    context.log("debug", "siteKind: action");
  } else {
    const cookieMap = new Map<string, string>();
    for (const cookie of req.headers.get("cookie")?.split(";") ?? []) {
      const [key, value] = cookie.split("=");
      cookieMap.set(key.trim(), value.trim());
    }

    const sessionToken = cookieMap.get(context.sessionPageCookie);
    const challengeToken = cookieMap.get(context.challengePageCookie);
    if (context.config.debug) {
      for (const [key, value] of cookieMap.entries()) {
        if (
          key.startsWith("recaptcha") &&
          key !== context.sessionPageCookie &&
          key !== context.challengePageCookie
        ) {
          context.log(
            "info",
            "An unused reCAPTCHA cookie in the request matches a different environment: " +
              key +
              ". This may signify a misconfiguration.",
          );
        }
      }
    }

    if (context.config.sessionSiteKey && sessionToken) {
      event.token = cookieMap.get(context.sessionPageCookie);
      event.siteKey = context.config.sessionSiteKey;
      event.wafTokenAssessment = true;
      context.log("debug", "siteKind: session");
    } else if (context.config.challengePageSiteKey && challengeToken) {
      event.token = cookieMap.get(context.challengePageCookie);
      event.siteKey = context.config.challengePageSiteKey;
      event.wafTokenAssessment = true;
      context.log("debug", "siteKind: challenge");
    } else if (context.config.expressSiteKey) {
      event.siteKey = context.config.expressSiteKey;
      event.express = true;
      context.log("debug", "siteKind: express");
    } else {
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
  req: Request,
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
          let ret = AssessmentSchema.safeParse(json);
          if (ret.success && Object.keys(ret.data).length > 0) {
            return ret.data;
          }
          let err_ret = RpcErrorSchema.required().safeParse(json);
          if (err_ret.success) {
            throw err_ret.data.error;
          }
          throw {message: "Response does not conform to Assesment schema: " + json};
        })
        .catch((reason) => {
          throw new error.ParseError(
            reason.message,
            action.createAllowAction(),
          );
        });
    })
    .catch((reason) => {
      context.log("debug", "[rpc] createAssessment (fail)");
      throw new error.NetworkError(reason.message, action.createAllowAction());
    });
}
