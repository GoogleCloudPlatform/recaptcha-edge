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

import {Buffer} from 'buffer';
import ipaddr from 'ipaddr.js';
import {ReCaptchaSoz} from '../generated/soz';

/**
 * Creates a base64 encoded reCaptchaSoz message
 *
 * @param {string} host - The host of the request.
 * @param {string} userIp - The user's IP address.
 * @param {number} projectNumber - Google Cloud project number.
 * @param {string} siteKey - The reCAPTCHA Enterprise site key.
 * @return {string} - The base64 encoded reCaptchaSoz message.
 */
export function createSoz(
  host: string,
  userIp: string,
  projectNumber: number,
  siteKey: string,
): string {
  const message: ReCaptchaSoz = {
    host,
    userIp: new Uint8Array(ipaddr.parse(userIp).toByteArray()),
    projectNumber: BigInt(projectNumber),
    siteKey,
  };
  const bytes = ReCaptchaSoz.toBinary(message);
  return Buffer.from(String.fromCharCode(...bytes), 'binary').toString(
    'base64url',
  );
}
