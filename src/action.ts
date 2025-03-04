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
 * @fileoverview Schema and types representing reCAPTCHA FirewallPolicy actions.
 */

export interface AllowAction {
  allow: object;
}

export interface BlockAction {
  block: object;
}

export interface SetHeaderAction {
  setHeader: {
    key?: string;
    value?: string;
  };
}

export interface RedirectAction {
  redirect: object;
}

export interface SubstituteAction {
  substitute: {
    path: string;
  };
}

export interface InjectJsAction {
  injectjs: object;
}

export type Action = AllowAction | BlockAction | SetHeaderAction | RedirectAction | SubstituteAction | InjectJsAction;

/** Helper function to create an AllowAction */
export function createAllowAction(): AllowAction {
  return { allow: {} };
}

export function isAllowAction(o: object): o is AllowAction {
  return (o as AllowAction).allow !== undefined;
}

/** Helper function to create a BlockAction */
export function createBlockAction(): BlockAction {
  return { block: {} };
}

export function isBlockAction(o: object): o is BlockAction {
  return (o as BlockAction).block !== undefined;
}

/** Helper function to create a Redirect */
export function createRedirectAction(): RedirectAction {
  return { redirect: {} };
}

export function isRedirectAction(o: object): o is RedirectAction {
  return (o as RedirectAction).redirect !== undefined;
}

/** Helper function to create a InjectJs */
export function createInjectJsAction(): InjectJsAction {
  return { injectjs: {} };
}

export function isInjectJsAction(o: object): o is InjectJsAction {
  return (o as InjectJsAction).injectjs !== undefined;
}

export function isSubstituteAction(o: object): o is SubstituteAction {
  return (o as SubstituteAction).substitute !== undefined;
}

export function isSetHeaderAction(o: object): o is SetHeaderAction {
  return (o as SetHeaderAction).setHeader !== undefined;
}

export function isTerminalAction(o: object): o is AllowAction | BlockAction | RedirectAction {
  return isAllowAction(o) || isBlockAction(o) || isRedirectAction(o);
}

export type RequestNonTerminalAction = SetHeaderAction | SubstituteAction;
export type ResponseNonTerminalAction = InjectJsAction;

export function isRequestNonTerminalAction(o: object): o is SetHeaderAction | SubstituteAction {
  return isSetHeaderAction(o) || isSubstituteAction(o);
}

export function isResponseNonTerminalAction(o: object): o is InjectJsAction {
  return isInjectJsAction(o);
}
