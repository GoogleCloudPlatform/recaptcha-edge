/**
 * @fileoverview reCAPTCHA Enterprise Library for Akamai Edge Workers.
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

import {
  processRequest,
  RecaptchaConfig,
  RecaptchaContext
} from '@google-cloud/recaptcha'
import { createResponse } from 'create-response'
import { HtmlRewritingStream } from 'html-rewriter'
import { httpRequest } from 'http-request'
import { ReadableStream, WritableStream } from 'streams';
import pkg from '../package.json'

type Env = any

const RECAPTCHA_JS = 'https://www.google.com/recaptcha/enterprise.js'
// Firewall Policies API is currently only available in the public preview.
const DEFAULT_RECAPTCHA_ENDPOINT =
  'https://public-preview-recaptchaenterprise.googleapis.com'

// Some headers aren't safe to forward from the origin response through an
// EdgeWorker on to the client For more information see the tech doc on
// create-response: https://techdocs.akamai.com/edgeworkers/docs/create-response
const UNSAFE_RESPONSE_HEADERS = new Set([
  'content-length',
  'transfer-encoding',
  'connection',
  'vary',
  'accept-encoding',
  'content-encoding',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'upgrade'
])

export {
  callCreateAssessment,
  callListFirewallPolicies,
  NetworkError,
  ParseError,
  processRequest,
  RecaptchaConfig,
  RecaptchaError
} from '@google-cloud/recaptcha'

export class AkamaiContext extends RecaptchaContext {
  static injectRecaptchaJs (inputResponse: object) {
    throw new Error('Method not implemented.')
  }

  readonly sessionPageCookie = 'recaptcha-akam-t'
  readonly challengePageCookie = 'recaptcha-akam-e'
  readonly environment: [string, string] = [pkg.name, pkg.version]
  readonly httpGetCachingEnabled = true
  start_time: number
  performance_counters: Array<[string, number]> = []

  constructor (
    private readonly env: Env,
    cfg: RecaptchaConfig
  ) {
    super(cfg)
    this.start_time = performance.now()
  }

  /**
   * Log performance debug information.
   *
   * This method should conditionally log performance only if the
   * config.debug flag is set to true.
   */
  log_performance_debug (event: string) {
    if (this.config.debug) {
      this.performance_counters.push([
        event,
        performance.now() - this.start_time
      ])
    }
  }

  buildEvent (req: Request): object {
    return {
      // extracting common signals
      userIpAddress: req.headers.get('True-Client-IP'),
      headers: Array.from(req.headers.entries()).map(([k, v]) => `${k}:${v}`),
      ja3:
        (req as any)?.akamai?.bot_management?.ja3_hash ?? undefined,
      requestedUri: req.url,
      userAgent: req.headers.get('user-agent')
    }
  }

  getSafeResponseHeaders (headers: any) {
    for (const [headerKey] of Object.entries(headers)) {
      if (UNSAFE_RESPONSE_HEADERS.has(headerKey)) {
        headers.delete(headerKey)
      }
    }

    return headers
  }

  async injectRecaptchaJs (resp: Response): Promise<Response> {
    const sessionKey = this.config.sessionSiteKey
    const RECAPTCHA_JS_SCRIPT = `<script src="${RECAPTCHA_JS}?render=${sessionKey}&waf=session" async defer></script>`

    const rewriter = new HtmlRewritingStream()

    rewriter.onElement('head', (el) => {
      el.append(`${RECAPTCHA_JS_SCRIPT}`)
    })

    // Create a new ReadableStream from the response body
    let readableBody: ReadableStream<Uint8Array>
    if (resp.body) {
      const reader = resp.body.getReader()
      readableBody = new ReadableStream({
        async pull(controller) {
          const { done, value } = await reader.read()
          if (done) {
            controller.close()
          } else {
            controller.enqueue(value)
          }
        }
      })
    } else {
      // Create an empty ReadableStream if resp.body is null
      readableBody = new ReadableStream()
    }

    return new Response(readableBody.pipeThrough(rewriter), {
      status: resp.status,
      headers: this.getSafeResponseHeaders(resp.headers)
    })
  }

  // Fetch the firewall lists, then cache the firewall policies:
  // https://techdocs.akamai.com/api-definitions/docs/caching
  // https://techdocs.akamai.com/property-mgr/docs/caching-2#how-it-works
  async fetch_list_firewall_policies (
    req: Request,
    options?: RequestInit
  ): Promise<Response> {
    return await this.fetch(req, {
      ...options
    })
  }
}

export function recaptchaConfigFromEnv (env: Env): RecaptchaConfig {
  return {
    projectNumber: env.PMUSER_GCPPROJECTNUMBER,
    apiKey: env.PMUSER_GCPAPIKEY,
    actionSiteKey: env.PMUSER_RECAPTCHAACTIONSITEKEY,
    expressSiteKey: env.PMUSER_RECAPTCHAEXPRESSSITEKEY,
    sessionSiteKey: env.PMUSER_RECAPTCHASESSIONSITEKEY,
    challengePageSiteKey: env.PMUSER_RECAPTCHACHALLENGESITEKEY,
    recaptchaEndpoint: env.RECAPTCHA_ENDPOINT ?? DEFAULT_RECAPTCHA_ENDPOINT,
    sessionJsInjectPath: env.PMUSER_RECAPTCHAJSINSTALL,
    debug: env.DEBUG ?? false
  }
}
