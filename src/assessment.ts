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

import * as action from "./action";

export interface RpcError {
  error: {
    code?: number;
    message?: string;
    status?: number | string;
  };
}

export function isRpcError(o: unknown): o is RpcError {
  return typeof o == "object" && (o as RpcError).error !== undefined;
}

export interface FirewallPolicy {
  name?: string;
  description?: string;
  path?: string;
  condition?: string;
  actions?: action.Action[];
}

export interface UserId {
  email?: string;
  phoneNumber?: string;
  username?: string;
}

export interface UserInfo {
  createAccountTime?: string;
  accountId?: string;
  userIds?: UserId[];
}

export interface Event {
  token?: string;
  siteKey?: string;
  userAgent?: string;
  userIpAddress?: string;
  expectedAction?: string;
  express?: boolean;
  requestedUri?: string;
  wafTokenAssessment?: boolean;
  ja3?: string;
  headers?: string[];
  firewallPolicyEvaluation?: boolean;
  userInfo?: UserInfo;
}

/** Result of the account verification as contained in the verdict token
 * issued at the end of the verification flow. */
type AccountVerificationResultEnum =
  | "RESULT_UNSPECIFIED"
  | "SUCCESS_USER_VERIFIED"
  | "ERROR_USER_NOT_VERIFIED"
  | "ERROR_SITE_ONBOARDING_INCOMPLETE"
  | "ERROR_RECIPIENT_NOT_ALLOWED"
  | "ERROR_RECIPIENT_ABUSE_LIMIT_EXHAUSTED"
  | "ERROR_CRITICAL_INTERNAL"
  | "ERROR_CUSTOMER_QUOTA_EXHAUSTED"
  | "ERROR_VERIFICATION_BYPASSED"
  | "ERROR_VERDICT_MISMATCH";

/** Endpoints that can be used for identity verification. */
interface EndpointVerificationInfo {
  emailAddress?: string;
  phoneNumber?: string;
  requestToken?: string;
  lastVerficationTime?: string;
}

/** Account verification information for identity verification.
 * The assessment event must include a token and site key to use this feature. */
interface AccountVerificationInfo {
  endpoints?: EndpointVerificationInfo[];
  languageCode?: string;
  latestVerificationResult?: AccountVerificationResultEnum;
}

/** Labels returned by account defender for this request. */
type AccountDefenderLabelEnum =
  | "ACCOUNT_DEFENDER_LABEL_UNSPECIFIED"
  | "PROFILE_MATCH"
  | "SUSPICIOUS_LOGIN_ACTIVITY"
  | "SUSPICIOUS_ACCOUNT_CREATION"
  | "RELATED_ACCOUNTS_NUMBER_HIGH";

/** RBA recommended actions. Based on the request parameters, account defender
 evaluates the risk and suggests an action to the client. */
type RecommendedActionEnum = "RECOMMENDED_ACTION_UNSPECIFIED" | "REQUEST_2FA" | "SKIP_2FA";

/** Account takeover risk assessment. */
interface AccountTakeoverVerdict {
  risk?: number;
}

/** Fake account risk assessment. */
interface FakeAccountVerdict {
  risk?: number;
}

/** Assessment returned by account defender when an account identifier is provided. */
interface AccountDefenderAssessment {
  labels?: AccountDefenderLabelEnum[];
  recommended_action?: RecommendedActionEnum;
  account_takeover_verdict?: AccountTakeoverVerdict;
  fake_account_verdict?: FakeAccountVerdict;
}

/** Zod schema for Assessment type. */
export interface Assessment {
  name?: string;
  event?: Event;
  riskAnalysis?: {
    score?: number;
  };
  firewallPolicyAssessment?: {
    error?: {
      code?: number;
      message?: string;
      status?: number | string;
    };
    firewallPolicy: FirewallPolicy;
  };
  accountVerificationInfo?: AccountVerificationInfo;
  accountDefenderAssessment?: AccountDefenderAssessment;
  assessmentEnvironment?: {
    client?: string;
    version?: string;
  };
}

/** Zod schema for Account Defender Annotation type. */
export interface Annotation {
  name: {
    projectId?: string;
    assessmentId?: string;
  };
  accountId?: string;
  annotation?: string;
  reasons?: string[];
}
