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
        recaptchaEndpoint: process.env.RECAPTCHA_ENDPOINT || "",
        sessionJsInjectPath: process.env.SESSION_JS_INSTALL_PATH || undefined,
        debug: (process.env.DEBUG ?? "false") == "true",
        unsafe_debug_dump_logs: false,
        strict_cookie: false
      };
}

server.start(getConfig(), 8080);