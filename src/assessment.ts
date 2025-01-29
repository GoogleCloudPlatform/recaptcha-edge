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
 * @fileoverview Assessment type and subtypes.
 */

import { z } from "zod";
import * as action from "./action";

export const ErrorSchema = z.object({
  code: z.number().optional(),
  message: z.string().optional(),
  status: z.number().or(z.string()).optional(),
});

export const RpcErrorSchema = z.object({ error: ErrorSchema.required() });

/** Zod Schema for FirewallPolicy type. */
export const FirewallPolicySchema = z.object({
  name: z.string().optional(),
  description: z.string().optional(),
  path: z.string().optional(),
  condition: z.string().optional(),
  actions: z.array(action.ActionSchema).optional(),
});

/** FirewallPolicy type used in CreateAssessment RPCs. */
export type FirewallPolicy = z.infer<typeof FirewallPolicySchema>;

/** Zod schema for Event type. */
export const EventSchema = z.object({
  token: z.string().optional(),
  siteKey: z.string().optional(),
  userAgent: z.string().optional(),
  userIpAddress: z.string().optional(),
  expectedAction: z.string().optional(),
  express: z.boolean().optional(),
  requestedUri: z.string().optional(),
  wafTokenAssessment: z.boolean().optional(),
  ja3: z.string().optional(),
  headers: z.array(z.string()).optional(),
  firewallPolicyEvaluation: z.boolean().optional(),
  userInfo: z
    .object({
      createAccountTime: z.string().datetime().optional(),
      accountId: z.string().optional(),
      userIds: z
        .array(
          z.object({
            email: z.string().email().optional(),
            phoneNumber: z.string().optional(),
            username: z.string().optional(),
          }),
        )
        .optional(),
    })
    .optional(),
  additionalTokens: z
    .array(
      z.object({
        token: z.string(),
        siteKey: z.string(),
      }),
    )
    .optional(),
});

/** Event type used in CreateAssessment RPCs. */
export type Event = z.infer<typeof EventSchema>;

/** Result of the account verification as contained in the verdict token
 * issued at the end of the verification flow. */
const AccountVerificationResultEnum = z.enum([
  "RESULT_UNSPECIFIED",
  "SUCCESS_USER_VERIFIED",
  "ERROR_USER_NOT_VERIFIED",
  "ERROR_SITE_ONBOARDING_INCOMPLETE",
  "ERROR_RECIPIENT_NOT_ALLOWED",
  "ERROR_RECIPIENT_ABUSE_LIMIT_EXHAUSTED",
  "ERROR_CRITICAL_INTERNAL",
  "ERROR_CUSTOMER_QUOTA_EXHAUSTED",
  "ERROR_VERIFICATION_BYPASSED",
  "ERROR_VERDICT_MISMATCH",
]);

/** Endpoints that can be used for identity verification. */
const EndpointVerificationInfoSchema = z.object({
  emailAddress: z.string().email().optional(),
  phoneNumber: z.string().optional(),
  requestToken: z.string().optional(),
  lastVerficationTime: z.string().time().optional(),
});

/** Account verification information for identity verification.
 * The assessment event must include a token and site key to use this feature. */
const AccountVerificationInfoSchema = z.object({
  endpoints: z.array(EndpointVerificationInfoSchema).optional(),
  languageCode: z.string().optional(),
  latestVerificationResult: AccountVerificationResultEnum.optional(),
});

/** Labels returned by account defender for this request. */
const AccountDefenderLabelEnum = z.enum([
  "ACCOUNT_DEFENDER_LABEL_UNSPECIFIED",
  "PROFILE_MATCH",
  "SUSPICIOUS_LOGIN_ACTIVITY",
  "SUSPICIOUS_ACCOUNT_CREATION",
  "RELATED_ACCOUNTS_NUMBER_HIGH",
]);

/** RBA recommended actions. Based on the request parameters, account defender
 evaluates the risk and suggests an action to the client. */
const RecommendedActionEnum = z.enum(["RECOMMENDED_ACTION_UNSPECIFIED", "REQUEST_2FA", "SKIP_2FA"]);

/** Account takeover risk assessment. */
const AccountTakeoverVerdictSchema = z.object({
  risk: z.number().min(0.0).max(1.0).optional(),
});

/** Fake account risk assessment. */
const FakeAccountVerdictSchema = z.object({
  risk: z.number().min(0.0).max(1.0).optional(),
});

/** Assessment returned by account defender when an account identifier is provided. */
const AccountDefenderAssessmentSchema = z.object({
  labels: z.array(AccountDefenderLabelEnum).optional(),
  recommended_action: RecommendedActionEnum.optional(),
  account_takeover_verdict: AccountTakeoverVerdictSchema.optional(),
  fake_account_verdict: FakeAccountVerdictSchema.optional(),
});

/** Zod schema for Assessment type. */
export const AssessmentSchema = z.object({
  name: z.string().optional(),
  event: EventSchema.optional(),
  riskAnalysis: z
    .object({
      score: z.number().min(0).max(1).optional(),
    })
    .optional(),
  firewallPolicyAssessment: z
    .object({
      error: ErrorSchema.optional(),
      firewallPolicy: FirewallPolicySchema.optional(),
    })
    .optional(),
  accountVerificationInfo: AccountVerificationInfoSchema.optional(),
  accountDefenderAssessment: AccountDefenderAssessmentSchema.optional(),
  assessmentEnvironment: z
    .object({
      client: z.string().optional(),
      version: z.string().optional(),
    })
    .optional(),
});

/** Assessment type used in CreateAssessment RPCs. */
export type Assessment = z.infer<typeof AssessmentSchema>;

/** Zod schema for Account Defender Annotation type. */
export const AnnotationSchema = z.object({
  name: z
    .object({
      projectId: z.string().optional(),
      assessmentId: z.string().optional(),
    })
    .optional(),
  accountId: z.string().optional(),
  annotation: z.string().optional(),
  reasons: z.array(z.string()).optional(),
});

export type Annotation = z.infer<typeof AnnotationSchema>;
