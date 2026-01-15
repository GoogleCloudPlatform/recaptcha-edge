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

import { test, expect, type Cookie } from "@playwright/test";

test.beforeEach(async ({ context }) => {
  await context.newPage();
});

test("should fetch the WAF endpoint correctly", async ({ page }) => {
  const endpointUrl = process.env.ENDPOINT as string;
  const response = await page.goto(`${endpointUrl}/action/allow`);
  expect(response?.status()).toBe(200);
  await expect(page).toHaveURL(`${endpointUrl}/action/allow`);
});

test("should get session token as a cookie", async ({ browser, page }) => {
  let cookies: Cookie[] = [];

  const endpointUrl = process.env.ENDPOINT as string;

  try {
    // Perform JS injection automatically.
    await page.goto(`${endpointUrl}/token/session`);
    await page.waitForTimeout(1000);
    // Get cookies from the current context.
    cookies = await page.context().cookies();
  } catch (err) {
    await browser.close();
    throw new Error(err.message);
  }

  // Extract the token from the cookie.
  const cookieRegex = /recaptcha-.+-t/;
  const sessionToken = cookies.find((cookie) => cookieRegex.test(cookie.name))?.value;
  // Assert that the token is not empty.
  expect(sessionToken).toBeTruthy();

  // Call CreateAsessment by visit condition matching pages.
  await page.goto(`${endpointUrl}/condition/1`);
  await expect(page).toHaveURL(`${endpointUrl}/condition/1`);
  // Match the expected value from the firewall rule.
  await expect(page.getByText("x-recaptcha-test")).toBeVisible({ timeout: 1000 });
});

test("should generate an action token after execute() by clicking the button", async ({ page }) => {
  const endpointUrl = process.env.ENDPOINT as string;
  // Go to the page with the reCAPTCHA.
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

  // Call CreateAsessment by visit condition matching pages.
  await page.goto(`${endpointUrl}/condition/1`);
  await expect(page).toHaveURL(`${endpointUrl}/condition/1`);
  // Match the expected value from the firewall rule.
  await expect(page.getByText("x-recaptcha-test")).toBeVisible({ timeout: 1000 });
});

test("should generate an enterprise token after execute() by clicking the button", async ({ page }) => {
  const endpointUrl = process.env.ENDPOINT as string;
  // Go to the page with the reCAPTCHA.
  await page.goto(`${endpointUrl}/token/v3web`);

  // Intercept the request triggered by the button click.
  const responsePromise = page.waitForResponse(
    (response) => response.url().includes("/server") && response.request().method() === "POST",
  );
  await page.click("#execute-button");

  // Wait for the response and extract the token from the header.
  const response = await responsePromise;
  const enterpriseToken = response.request().postDataJSON()["g-recaptcha-response"];

  // Assert that the token is not empty.
  expect(enterpriseToken).toBeTruthy();

  // Call CreateAsessment by visit condition matching pages.
  await page.goto(`${endpointUrl}/condition/1`);
  await expect(page).toHaveURL(`${endpointUrl}/condition/1`);
  // Match the expected value from the firewall rule.
  await expect(page.getByText("x-recaptcha-test")).toBeVisible({ timeout: 1000 });
});

test("should get session token after visiting the intended injectJS path", async ({ page }) => {
  const endpointUrl = process.env.ENDPOINT as string;

  await page.goto(`${endpointUrl}/hello.html`);

  // Wait for the reCAPTCHA script to be injected (adjust timeout if needed).
  await page.waitForTimeout(2000);

  // Check if the reCAPTCHA script is present in the page.
  const scriptExists = await page.evaluate(() => {
    return Array.from(document.querySelectorAll("script")).some((script) =>
      script.src.includes("www.google.com/recaptcha/enterprise.js"),
    );
  });
  expect(scriptExists).toBe(true);
});

test("should get challenge token as a cookie", async ({ browser, page }) => {
  let cookies: Cookie[] = [];
  const endpointUrl = process.env.ENDPOINT as string;

  try {
    await page.goto(`${endpointUrl}/action/redirect`);
    await page.waitForTimeout(5000);
    // Get cookies from the selecteds domain.
    cookies = await page.context().cookies([endpointUrl]);
  } catch (err) {
    await browser.close();
    throw new Error(err.message);
  }

  // Extract the token from the cookie.
  const cookieRegex = /recaptcha-.+-e/;
  const challengeToken = cookies.find((cookie) => cookieRegex.test(cookie.name))?.value;
  expect(challengeToken).toBeTruthy();

  // Call CreateAsessment by visit condition matching pages.
  await page.goto(`${endpointUrl}/condition/1`);
  await expect(page).toHaveURL(`${endpointUrl}/condition/1`);
  // Match the expected value from the firewall rule.
  await expect(page.getByText("x-recaptcha-test")).toBeVisible({ timeout: 1000 });
});

test("should get session token and then challenge token", async ({ page }) => {
  const endpointUrl = process.env.ENDPOINT as string;

  await page.goto(`${endpointUrl}/hello.html`);

  await page.waitForTimeout(2000);

  const scriptExists = await page.evaluate(() => {
    return Array.from(document.querySelectorAll("script")).some((script) =>
      script.src.includes("www.google.com/recaptcha/enterprise.js"),
    );
  });
  expect(scriptExists).toBe(true);
  // Get cookies (session token).
  const cookies = await page.context().cookies([endpointUrl]);
  const sessionCookieRegex = /recaptcha-.+-t/;
  const sessionToken = cookies.find((cookie) => sessionCookieRegex.test(cookie.name))?.value;

  // Navigate to the page that issues the challenge token.
  await page.goto(`${endpointUrl}/action/redirect`);
  // Nocaptcha setting allows us to always pass the challenge.
  await page.waitForTimeout(5000);

  // Get cookies again.
  const allCookies = await page.context().cookies([endpointUrl]);

  // 5. Extract the challenge token from the cookies.
  const challengeCookieRegex = /recaptcha-.+-e/;
  const challengeTokenCookie = allCookies.find((cookie) => challengeCookieRegex.test(cookie.name));
  const challengeToken = challengeTokenCookie?.value;

  expect(sessionToken).toBeTruthy();
  expect(challengeToken).toBeTruthy();

  await page.goto(`${endpointUrl}/condition/1`);
  await expect(page).toHaveURL(`${endpointUrl}/condition/1`);
  // Match the expected value from the firewall rule.
  await expect(page.getByText("x-recaptcha-test")).toBeVisible({ timeout: 1000 });
});

test("should get user info with an enterprise token by accessing the default login page (json)", async ({ page }) => {
  const endpointUrl = process.env.ENDPOINT as string;
  // Go to the page with the reCAPTCHA.
  await page.goto(`${endpointUrl}/token/credentials`);

  await page.fill("#firstName1", "Test");
  await page.fill("#lastName1", "User");
  await page.fill("#email1", "testing@example.com");
  await page.fill("#username1", "test_user");
  await page.fill("#password1", "test_password");

  // Intercept the request triggered by the button click.
  const responsePromise = page.waitForResponse(
    (response) => response.url().includes("/login") && response.request().method() === "POST",
  );
  await page.click("#submit-json");

  // Wait for the response and extract data.
  const response = await responsePromise;

  // Extract the token and username from the parsed body.
  const enterpriseToken = response.request().postDataJSON()["g-recaptcha-response"];
  const username = response.request().postDataJSON()["username"];

  // Assert that the token and username are not empty.
  expect(enterpriseToken).toBeTruthy();
  expect(username).toBeTruthy();
  expect(username).toEqual("test_user");

  // Call CreateAsessment by visit condition matching pages.
  await page.goto(`${endpointUrl}/condition/1`);
  await expect(page).toHaveURL(`${endpointUrl}/condition/1`);
  // Match the expected value from the firewall rule.
  await expect(page.getByText("x-recaptcha-test")).toBeVisible({ timeout: 1000 });
});

test("should get user info with an enterprise token by accessing the default login page (form-urlencoded)", async ({
  page,
}) => {
  const endpointUrl = process.env.ENDPOINT as string;
  // Go to the page with the reCAPTCHA.
  await page.goto(`${endpointUrl}/token/credentials`);

  await page.fill("#firstName2", "Test");
  await page.fill("#lastName2", "User");
  await page.fill("#email2", "testing@example.com");
  await page.fill("#username2", "test_user");
  await page.fill("#password2", "test_password");

  // Intercept the request triggered by the button click.
  const responsePromise = page.waitForResponse(
    (response) => response.url().includes("/login") && response.request().method() === "POST",
  );
  await page.click("#submit-form");

  // Wait for the response and extract data.
  const response = await responsePromise;

  // Extract the token and username from the parsed body.
  const enterpriseToken = response.request().postDataJSON()["g-recaptcha-response"];
  const username = response.request().postDataJSON()["username"];

  // Assert that the token and username are not empty.
  expect(enterpriseToken).toBeTruthy();
  expect(username).toBeTruthy();
  expect(username).toEqual("test_user");

  // Call CreateAsessment by visit condition matching pages.
  await page.goto(`${endpointUrl}/condition/1`);
  await expect(page).toHaveURL(`${endpointUrl}/condition/1`);
  // Match the expected value from the firewall rule.
  await expect(page.getByText("x-recaptcha-test")).toBeVisible({ timeout: 1000 });
});
