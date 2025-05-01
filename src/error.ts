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
 * Library specific errors.
 */

import { Action, AllowAction, BlockAction, createAllowAction, isBlockAction } from "./action";

/**
 * Error type for reCAPTCHA processing.
 */
export class RecaptchaError extends Error {
  recommendedAction?: AllowAction | BlockAction;

  constructor(message: string, recommendedAction?: AllowAction | BlockAction) {
    super(message);
    this.recommendedAction = recommendedAction;
  }

  recommended_action_enum(): "block" | "allow" {
    let action = this.recommendedAction ?? createAllowAction();
    return isBlockAction(action) ? "block" : "allow"
  }

  toJSON(): object {
    return {
      name: this.name,
      message: this.message,
      recommendedAction: this.recommendedAction,
    };
  }
}

/** An Error that occurs during initialization. */
export class InitError extends RecaptchaError {
  constructor(message: string, recommendedAction?: AllowAction | BlockAction) {
    super(message, recommendedAction ?? createAllowAction());
  }
}

/** An Error that occurs during response parsing. */
export class ParseError extends RecaptchaError {
  constructor(message: string, recommendedAction?: AllowAction | BlockAction) {
    super(message, recommendedAction);
  }
}

/** An Error that occurs when reCAPTCHA is unreachable. */
export class NetworkError extends RecaptchaError {
  constructor(message: string, recommendedAction?: AllowAction | BlockAction) {
    super(message, recommendedAction);
  }
}
