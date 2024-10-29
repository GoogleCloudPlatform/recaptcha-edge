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
 * @fileoverview reCAPTCHA Enterprise Library for Cloudflare Workers.
 */

type Env = any;

const RECAPTCHA_JS = 'https://www.google.com/recaptcha/enterprise.js';
// Firewall Policies API is currently only available in the public preview.
const DEFAULT_RECAPTCHA_ENDPOINT =
  'https://public-preview-recaptchaenterprise.googleapis.com';

import {
  processRequest,
  RecaptchaConfig,
  RecaptchaContext,
} from '@google-cloud/recaptcha';
import {HTMLRewriter} from '@worker-tools/html-rewriter';
import pkg from '../package.json';

export {
  callCreateAssessment,
  callListFirewallPolicies,
  NetworkError,
  ParseError,
  processRequest,
  RecaptchaConfig,
  RecaptchaError,
} from '@google-cloud/recaptcha';

export class CloudflareContext extends RecaptchaContext {
  readonly sessionPageCookie = 'recaptcha-cf-t';
  readonly challengePageCookie = 'recaptcha-cf-e';
  readonly environment: [string, string] = [pkg.name, pkg.version];
  readonly httpGetCachingEnabled = true;
  start_time: number;
  performance_counters: Array<[string, number]> = [];

  constructor(
    private env: Env,
    private ctx: ExecutionContext,
    cfg: RecaptchaConfig,
  ) {
    super(cfg);
    this.start_time = performance.now();
  }

  /**
   * Log performance debug information.
   *
   * This method should conditionally log performance only if the
   * config.debug flag is set to true.
   */
  log_performance_debug(event: string) {
    if (this.config.debug) {
      this.performance_counters.push([
        event,
        performance.now() - this.start_time,
      ]);
    }
  }

  buildEvent(req: Request): object {
    return {
      // extracting common signals
      userIpAddress: req.headers.get('CF-Connecting-IP'),
      headers: Array.from(req.headers.entries()).map(([k, v]) => `${k}:${v}`),
      ja3: (req as any)?.['cf']?.['bot_management']?.['ja3_hash'] ?? undefined,
      requestedUri: req.url,
      userAgent: req.headers.get('user-agent'),
    };
  }

  injectRecaptchaJs(resp: Response): Promise<Response> {
    const sessionKey = this.config.sessionSiteKey;
    const RECAPTCHA_JS_SCRIPT = `<script src="${RECAPTCHA_JS}?render=${sessionKey}&waf=session" async defer></script>`;
    return Promise.resolve(
      new HTMLRewriter()
        .on('head', {
          element(element: any) {
            element.append(RECAPTCHA_JS_SCRIPT, {html: true});
          },
        })
        .transform(new Response(resp.body, resp)),
    );
  }

  async fetch_list_firewall_policies(req: RequestInfo, options?: RequestInit): Promise<Response> {
    return this.fetch(req,
      {
        ...options,
        cf: {
          cacheEverything: true,
          cacheTtlByStatus: {'200-299': 600, 404: 1, '500-599': 0},
        },
      });
  }
}

export function recaptchaConfigFromEnv(env: Env): RecaptchaConfig {
  return {
    projectNumber: env.PROJECT_NUMBER,
    apiKey: env.API_KEY,
    actionSiteKey: env.ACTION_SITE_KEY,
    expressSiteKey: env.EXPRESS_SITE_KEY,
    sessionSiteKey: env.SESSION_SITE_KEY,
    challengePageSiteKey: env.CHALLENGE_PAGE_SITE_KEY,
    recaptchaEndpoint: env.RECAPTCHA_ENDPOINT ?? DEFAULT_RECAPTCHA_ENDPOINT,
    sessionJsInjectPath: env.SESSION_JS_INSTALL_PATH,
    debug: env.DEBUG ?? false,
  };
}
