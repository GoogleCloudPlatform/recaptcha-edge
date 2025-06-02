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
import { Assessment, Event, UserInfo } from "./assessment";
import * as error from "./error";
import { EdgeRequest, EdgeRequestInit, RecaptchaContext } from "./index";
import picomatch from "picomatch";
import { extractBoundary, parse } from "parse-multipart-form-data";

/**
 * Get reCAPTCHA regular token from POST request body,
 * which is a ReadableStream
 */
async function getTokenFromBody(context: RecaptchaContext, request: EdgeRequest): Promise<string | null> {
  const contentType = request.getHeader("content-type");
  // The name of a regular token is `g-recaptcha-response` in POST parameteres (viewed in Request Playload).
  if (contentType && contentType.includes("application/json")) {
    try {
      // Clone to avoid consuming the original body.
      const body = await request.getBodyJson();
      return body["g-recaptcha-response"] || null;
    } catch (error) {
      context.log("error", "Error parsing data");
      return null;
    }
  } else if (contentType && contentType.includes("application/x-www-form-urlencoded")) {
    try {
      const bodyText = await request.getBodyText();
      const formData = new URLSearchParams(bodyText);
      return formData.get("g-recaptcha-response");
    } catch (error) {
      context.log("error", "Error parsing data");
      return null;
    }
  } else if (contentType && contentType.includes("multipart/form-data")) {
    try {
      const boundary = extractBoundary(contentType);
      const bodyText = await request.getBodyText();
      const body = Buffer.from(bodyText);
      const parts = parse(body, boundary);

      for (const part of parts) {
        // Check filename directly, or a custom header if controlling the upload.
        if (part.filename === "g-recaptcha-response" || (part.type && part.type.includes("text/plain") && part.data)) {
          return part.data.toString("utf-8");
        }
      }
      return null;
    } catch (error) {
      if (error instanceof TypeError) {
        context.log("error", "Unsupported operations");
        return null;
      } else {
        context.log("error", "Error parsing data");
        return null;
      }
    }
  } else {
    context.log("error", "Unsupported Content-Type or no Content-Type header found.");
    return null;
  }
}

/**
 * Get UserInfo from the default login event.
 */
async function getUserInfo(req: EdgeRequest, accountIdField?: string, usernameField?: string): Promise<UserInfo> {
  const contentType = req.getHeader("content-type");
  let userInfo: UserInfo = { accountId: "", userIds: [] };
  if (contentType && contentType.includes("application/json")) {
    try {
      const body = await req.getBodyJson();
      const accountId = accountIdField ? (body[accountIdField] ?? undefined) : undefined;
      const username = usernameField ? (body[usernameField] ?? undefined) : undefined;

      if (accountId) {
        userInfo = {
          accountId,
          userIds: [{ username: username }],
        };
      }
    } catch (error) {
      console.error("Error parsing json when getting UserInfo:", error);
    }
  } else if (contentType && contentType.includes("application/x-www-form-urlencoded")) {
    try {
      const bodyText = await req.getBodyText();
      const formData = new URLSearchParams(bodyText);
      const accountId = accountIdField ? (formData.get(accountIdField) ?? undefined) : undefined;
      const username = usernameField ? (formData.get(usernameField) ?? undefined) : undefined;

      if (accountId) {
        userInfo = {
          accountId,
          userIds: username ? [{ username }] : [],
        };
      }
    } catch (error) {
      console.error("Error parsing form data when getting UserInfo:", error);
    }
  }
  return userInfo;
}

/**
 * Adds reCAPTCHA specific values to an Event strucutre.
 * This includes, the siteKey, the token, cookies, and flags like express.
 */
export async function addTokenAndSiteKeyToEvent(context: RecaptchaContext, req: EdgeRequest, base?: Event): Promise<Event> {
  const event: Event = base ?? {};
  const actionToken = req.getHeader("X-Recaptcha-Token");
  if (context.config.actionSiteKey && actionToken) {
    // WAF action token in the header.
    event.token = actionToken;
    event.siteKey = context.config.actionSiteKey;
    event.wafTokenAssessment = true;
    context.debug_trace.site_key_used = "action";
    context.log("debug", "siteKind: action");
    return event;
  }
  const cookieMap = new Map<string, string>();
  let challengeToken: string | undefined;
  let sessionToken: string | undefined;
  for (const cookie of req.getHeader("cookie")?.split(";") ?? []) {
    const delim = cookie.indexOf("=");
    const key = cookie.substring(0, delim);
    const value = cookie.substring(delim + 1);
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

  if (context.config.enterpriseSiteKey && req.method === "POST") {
    const recaptchaToken = event.token ?? await getTokenFromBody(context, req);
    if (recaptchaToken) {
      event.token = recaptchaToken;
      event.siteKey = context.config.enterpriseSiteKey;
      event.wafTokenAssessment = false;
      context.debug_trace.site_key_used = "enterprise";
      context.log("debug", "siteKind: action-regular");
    } else {
      // TODO: Handle the case where the token is not found or malformed.
      context.log("error", "g-recaptcha-response not found in the request body.");
    }
  } else if (context.config.challengePageSiteKey && challengeToken) {
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
  // TODO: this should use a builder pattern. with a CreateAssessmentRequest type.
  const site_info = await addTokenAndSiteKeyToEvent(context, req, additionalParams);
  const site_features = await context.buildEvent(req);
  if (req.method === "POST" && new URL(req.url).pathname === context.config.credentialPath) {
    site_features.userInfo = await getUserInfo(req, context.config.accountId, context.config.username);
  }

  const event = {
    ...site_info,
    ...site_features
  };
  const assessment: Assessment = { event };
  assessment.assessmentEnvironment = {
    client: (environment ?? context.environment)[0],
    version: (environment ?? context.environment)[1],
  };
  const options: EdgeRequestInit = {
    method: "POST",
    body: JSON.stringify(assessment),
    headers: {
      "content-type": "application/json;charset=UTF-8",
    },
  };

  return context
    .fetch_create_assessment(options)
    .catch((reason) => {
      context.log("debug", "[rpc] createAssessment (fail)");
      context.debug_trace.create_assessment_status = "err";
      if (reason instanceof error.RecaptchaError) {
        throw reason;
      }
      throw new error.NetworkError(reason.message, action.createAllowAction());
    });
}
