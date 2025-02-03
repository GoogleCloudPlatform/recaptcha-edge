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
 * Tests for sozencode.ts
 */
import { expect, test } from "vitest";

import { createSoz } from "./soz";
import { RecaptchaContext } from "../dist/index.esm";

test("createSoz-ok", async () => {
  let context = {
    encodeString: (st) => {
      return new TextEncoder().encode(st);
    },
  };
  // Ignore type-checking for context.
  // @ts-expect-error
  expect(createSoz(context, "example.com", "1.2.3.4", 12345, "challengeSiteKey")).toEqual(
    "eyJob3N0IjoiZXhhbXBsZS5jb20iLCJwcm9qZWN0TnVtYmVyIjoxMjM0NSwic2l0ZUtleSI6ImNoYWxsZW5nZVNpdGVLZXkiLCJ1c2VySXAiOiJBUUlEQkEifQ",
  );
});
