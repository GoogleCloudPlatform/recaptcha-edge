import { test, expect, type Cookie, Browser, Page } from "@playwright/test";

async function measurePageLoadAndElementVisibility(page: Page, url: string, selector: string, timeout: number): Promise<number> {
    const startTime = Date.now();

    await page.goto(url);
    await expect(page).toHaveURL(url); // Good practice to keep this

    try {
        await page.waitForSelector(selector, { timeout });
    } catch (error) {
        const elapsedTime = Date.now() - startTime;
         throw new Error(`Element ${selector} not visible within ${timeout}ms (Total time: ${elapsedTime}ms).`);
    }

    const endTime = Date.now();
    return endTime - startTime;
}

test.beforeEach(async ({ context }) => {
  await context.clearCookies();
});

// By default, playwright tests in a single file are run in order.
test("should get session token and load condition within 600ms", async ({ browser, page }) => {
    const endpointUrl = process.env.ENDPOINT as string;

    // 1. Get the session token (we still need to do this).
    let cookies: Cookie[] = [];
    try {
        await page.goto(`${endpointUrl}/token/session`);
        await page.waitForTimeout(1000); // Wait for token, but keep it short.
        cookies = await page.context().cookies();
    } catch (err) {
        await browser.close();
        throw new Error(err.message);
    }
    const cookieRegex = /recaptcha-.+-t/;
    const sessionToken = cookies.find((cookie) => cookieRegex.test(cookie.name))?.value;
    expect(sessionToken).toBeTruthy();


    // 2. Measure the performance of loading /condition/1 and element visibility.
    const loadTime = await measurePageLoadAndElementVisibility(
        page,
        `${endpointUrl}/condition/1`,
        "text=x-recaptcha-test", // More concise selector
        300
    );

    console.log(`Page load and element visibility time: ${loadTime}ms`);
    expect(loadTime).toBeLessThanOrEqual(600);
});

test("should generate action token and load condition within 600ms", async ({ page }) => {
    const endpointUrl = process.env.ENDPOINT as string;

    // 1. Get the action token.
    await page.goto(`${endpointUrl}/token/action`);
      // Intercept the request triggered by the button click.
    const responsePromise = page.waitForResponse(
      (response) =>
        response.url().includes("/token/action") &&
        response.request().method() === "GET" &&
        !!response.request().headers()["x-recaptcha-token"], // Check if the header exists.
    );
    await page.click("#execute-button");

      // Wait for the response and extract the token from the header.
    const response = await responsePromise;
    const actionToken = response.request().headers()["x-recaptcha-token"];

    // Assert that the token is not empty.
    expect(actionToken).toBeTruthy();

    // 2. Measure the performance of loading /condition/1 and element visibility.
    const loadTime = await measurePageLoadAndElementVisibility(
        page,
        `${endpointUrl}/condition/1`,
        "text=x-recaptcha-test", // More concise selector
        600
    );

    console.log(`Page load and element visibility time: ${loadTime}ms`);
    expect(loadTime).toBeLessThanOrEqual(600);
});
