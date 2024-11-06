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

import { z } from "zod";

/** Zod Schema for Allow action */
export const AllowActionSchema = z.object({
  allow: z.object({}),
  type: z.literal("allow").default("allow"),
});
/** Zod Schema for Block action */
export const BlockActionSchema = z.object({
  block: z.object({}),
  type: z.literal("block").default("block"),
});
/** Zod Schema for ChallengePage action */
export const ChallengePageActionSchema = z.object({
  challengepage: z.object({}),
  type: z.literal("challengepage").default("challengepage"),
});
/** Zod Schema for SetHeader action */
export const SetHeaderActionSchema = z.object({
  setHeader: z.object({
    key: z.string(),
    value: z.string(),
  }),
  type: z.literal("setHeader").default("setHeader"),
});
/** Zod Schema for Redirect action */
export const RedirectActionSchema = z.object({
  redirect: z.object({}),
  type: z.literal("redirect").default("redirect"),
});
/** Zod Schema for Substitute action */
export const SubstituteActionSchema = z.object({
  substitute: z.object({
    path: z.string(),
  }),
  type: z.literal("substitute").default("substitute"),
});
/** Zod Schema for InjectJs action */
export const InjectJsActionSchema = z.object({
  injectjs: z.object({}),
  type: z.literal("injectjs").default("injectjs"),
});

/** Type representing an Allow action */
export type AllowAction = z.infer<typeof AllowActionSchema>;
/** Type representing a Block action */
export type BlockAction = z.infer<typeof BlockActionSchema>;
/** Type representing a ChallengePage action */
export type ChallengePageAction = z.infer<typeof ChallengePageActionSchema>;
/** Type representing a SetHeader action */
export type SetHeaderAction = z.infer<typeof SetHeaderActionSchema>;
/** Type representing a Redirect action */
export type RedirectAction = z.infer<typeof RedirectActionSchema>;
/** Type representing a Substitute action */
export type SubstituteAction = z.infer<typeof SubstituteActionSchema>;
/** Type representing an InjectJs action */
export type InjectJsAction = z.infer<typeof InjectJsActionSchema>;

/** Helper function to create an AllowAction */
export function createAllowAction(): AllowAction {
  return AllowActionSchema.parse({ allow: {} });
}

/** Helper function to create a BlockAction */
export function createBlockAction(): BlockAction {
  return BlockActionSchema.parse({ block: {} });
}

/** Helper function to create a InjectJs */
export function createInjectJsAction(): InjectJsAction {
  return InjectJsActionSchema.parse({ injectjs: {} });
}

/** Zod schema for a terminal action */
export const TerminalActionSchema = AllowActionSchema.or(BlockActionSchema).or(
  ChallengePageActionSchema,
);

/** Zod schema for a non-terminal action that modifies the backend Request */
export const RequestNonTerminalActionSchema = SetHeaderActionSchema.or(
  RedirectActionSchema,
).or(SubstituteActionSchema);
/** Zod schema for a non-terminal action that modifies the backend Response */
export const ResponseNonTerminalActionSchema = InjectJsActionSchema;
/** Zod schema for any action */
export const ActionSchema = TerminalActionSchema.or(
  RequestNonTerminalActionSchema,
).or(ResponseNonTerminalActionSchema);
/**
 * Type representing a terminal action.
 * A terminal action is one that conceptually ends reCAPTCHA processing,
 * and only one may occur in a single request.
 * For example, it would not make sense to have both an 'allow' and 'block'
 * action in the same request.
 */
export type TerminalAction = z.infer<typeof TerminalActionSchema>;
/** A non-terminal action that modifies the request */
export type RequestNonTerminalAction = z.infer<
  typeof RequestNonTerminalActionSchema
>;
/** A non-terminal action that modifies the response */
export type ResponseNonTerminalAction = z.infer<
  typeof ResponseNonTerminalActionSchema
>;
/** An action determined by the FirewallPolicy system */
export type Action = z.infer<typeof ActionSchema>;
