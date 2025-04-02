import { RecaptchaConfig } from "@google-cloud/recaptcha-edge";
import * as server from "./index";

// TODO. Definitely need some validation here.
function getConfig(): RecaptchaConfig {
    return {
        projectNumber: parseInt(process.env.PROJECT_NUMBER || ""),
        apiKey: process.env.API_KEY || "",
        actionSiteKey: process.env.ACTION_SITE_KEY || "",
        expressSiteKey: process.env.EXPRESS_SITE_KEY || undefined,
        sessionSiteKey: process.env.SESSION_SITE_KEY || undefined,
        challengePageSiteKey: process.env.CHALLENGE_PAGE_SITE_KEY || "",
        enterpriseSiteKey: process.env.ENTERPRISE_SITE_KEY || undefined,
        recaptchaEndpoint: process.env.RECAPTCHA_ENDPOINT || "",
        sessionJsInjectPath: process.env.SESSION_JS_INJECT_PATH || undefined,
        debug: true,
        unsafe_debug_dump_logs: true,
        strict_cookie: false
      };
}

server.start(getConfig(), 8080);