/**
 * Copyright 2025 Google LLC
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

import { RecaptchaConfig } from "@google-cloud/recaptcha-edge";
import * as server from "./index";

function getConfig(): RecaptchaConfig {
    return {
        projectNumber: parseInt(process.env.PROJECT_NUMBER || "0"),
        apiKey: process.env.API_KEY || "",
        actionSiteKey: process.env.ACTION_SITE_KEY || undefined,
        expressSiteKey: process.env.EXPRESS_SITE_KEY || undefined,
        sessionSiteKey: process.env.SESSION_SITE_KEY || undefined,
        challengePageSiteKey: process.env.CHALLENGE_PAGE_SITE_KEY || undefined,
        enterpriseSiteKey: process.env.ENTERPRISE_SITE_KEY || undefined,
        recaptchaEndpoint: process.env.RECAPTCHA_ENDPOINT || undefined,
        sessionJsInjectPath: process.env.SESSION_JS_INSTALL_PATH || undefined,
        debug: (process.env.DEBUG ?? "false") == "true",
        unsafe_debug_dump_logs: false,
        strict_cookie: false
      };
}

server.start(getConfig(), 8080);