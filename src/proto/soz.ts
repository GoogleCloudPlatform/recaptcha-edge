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
 * @fileoverview Creates a base64 encoded of reCaptchaSoz message
 * @suppress {missingProperties}
 */

import ipaddr from "ipaddr.js";
import { ReCaptchaSoz } from "../generated/soz";

function base64UrlEncode(bytes: Uint8Array) {
  let base64 = "";
  const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  for (let i = 0; i < bytes.length; i += 3) {
    const byte1 = bytes[i];
    const byte2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const byte3 = i + 2 < bytes.length ? bytes[i + 2] : 0;

    const triplet = (byte1 << 16) | (byte2 << 8) | byte3;

    for (let j = 0; j < 4; j++) {
      if (i * 8 + j * 6 <= bytes.length * 8) {
        base64 += base64Chars.charAt((triplet >>> (6 * (3 - j))) & 0x3f);
      }
    }
  }

  return base64;
}

/**
 * Creates a base64 encoded reCaptchaSoz message
 *
 * @param {string} host - The host of the request.
 * @param {string} userIp - The user's IP address.
 * @param {number} projectNumber - Google Cloud project number.
 * @param {string} siteKey - The reCAPTCHA Enterprise site key.
 * @return {string} - The base64 encoded reCaptchaSoz message.
 */
export function createSoz(host: string, userIp: string, projectNumber: number, siteKey: string): string {
  const message: ReCaptchaSoz = {
    host,
    projectNumber: BigInt(projectNumber),
    siteKey,
  };
  try {
    message.userIp = new Uint8Array(ipaddr.parse(userIp).toByteArray());
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (e) {
    // Invalid IP address. Ignore it.
  }
  const bytes = ReCaptchaSoz.toBinary(message);
  return base64UrlEncode(bytes);
}
