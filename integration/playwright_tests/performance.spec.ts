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
 * @fileoverview Integration tes for tokens with Playwright browser session.
 */

import { test, expect, type Cookie, Page } from "@playwright/test";

async function measurePageLoadAndElementVisibility(
  page: Page,
  url: string,
  selector: string,
  timeout: number,
): Promise<number> {
  await page.goto(url);
  await expect(page).toHaveURL(url);
  const startTime = Date.now();

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

// By default, playwright tests in a single file run in order.
test("should get session token and load condition within 600ms", async ({ browser, page }) => {
  const endpointUrl = process.env.ENDPOINT as string;

  // Get the session token.
  let cookies: Cookie[] = [];
  try {
    await page.goto(`${endpointUrl}/token/session`);
    await page.waitForTimeout(1200); // Wait for token.
    cookies = await page.context().cookies();
  } catch (err) {
    await browser.close();
    throw new Error(err.message);
  }
  const cookieRegex = /recaptcha-.+-t/;
  const sessionToken = cookies.find((cookie) => cookieRegex.test(cookie.name))?.value;
  expect(sessionToken).toBeTruthy();

  // Measure the performance of loading a condition page and element visibility,
  // which implies the duration of a CreateAssessment call.
  const loadTime = await measurePageLoadAndElementVisibility(
    page,
    `${endpointUrl}/condition/1`,
    "text=x-recaptcha-test",
    300,
  );

  console.log(`Page load and element visibility time: ${loadTime}ms`);
  expect(loadTime).toBeLessThanOrEqual(600);
});

test("should generate action token and load condition within 600ms", async ({ page }) => {
  const endpointUrl = process.env.ENDPOINT as string;

  // Get the action token.
  await page.goto(`${endpointUrl}/token/action`);
  // Intercept the request triggered by the button click.
  const responsePromise = page.waitForResponse(
    (response) =>
      response.url().includes("/token/action") &&
      response.request().method() === "GET" &&
      !!response.request().headers()["x-recaptcha-token"],
  );
  await page.click("#execute-button");

  // Wait for the response and extract the token from the header.
  const response = await responsePromise;
  const actionToken = response.request().headers()["x-recaptcha-token"];
  expect(actionToken).toBeTruthy();

  // Measure the performance of loading a condition page and element visibility,
  // which implies the duration of a CreateAssessment call.
  const loadTime = await measurePageLoadAndElementVisibility(
    page,
    `${endpointUrl}/condition/1`,
    "text=x-recaptcha-test",
    600,
  );

  console.log(`Page load and element visibility time: ${loadTime}ms`);
  expect(loadTime).toBeLessThanOrEqual(600);
});
