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
 * @fileoverview pre-written end-to-end integration test without tokens.
 */

import { expect, test } from "@playwright/test";

test.beforeEach(async ({ context }) => {
  await context.newPage();
});

test.describe("Check Different Actions", () => {
  // const endpointUrl = process.env.ENDPOINT as string;
  const endpointUrl = "https://recaptchatest3.global.ssl.fastly.net";
  if (!endpointUrl) {
    throw new Error("ENDPOINT environment variable not found.");
  }

  test("should fetch the endpoint correctly", async ({ page }) => {
    const response = await page.goto(endpointUrl);
    expect(response?.status()).toBe(200);
  });

  test("Access the allow page", async ({ page }) => {
    const testPageUrl = "/action/allow";
    const response = await page.goto(`${endpointUrl}${testPageUrl}`);
    expect(response?.status()).toBe(200);
  });

  test("Access the block page", async ({ page }) => {
    const testPageUrl = "/action/block";
    const response = await page.goto(`${endpointUrl}${testPageUrl}`);
    expect(response?.status()).toBe(403);
  });

  test("Access the substitute page", async ({ page }) => {
    const testPageUrl = "/action/substitute";
    const response = await page.goto(`${endpointUrl}${testPageUrl}`);
    expect(response?.status()).toBe(200);

    const responseJson = await response?.json();
    expect(responseJson.url).toEqual("/substitute/target");
  });

  test("Access the set header page", async ({ page }) => {
    const testPageUrl = "/action/setheader";
    const response = await page.goto(`${endpointUrl}${testPageUrl}`);
    expect(response?.status()).toBe(200);

    const responseJson = await response?.json();
    expect(responseJson.headers["x-recaptcha-test"]).toEqual("test-value");
  });
});

test.describe("Check Different Path Matching", () => {
  // const endpointUrl = process.env.ENDPOINT as string;
  const endpointUrl = "https://recaptchatest3.global.ssl.fastly.net";
  if (!endpointUrl) {
    throw new Error("ENDPOINT environment variable not found.");
  }

  test("Set header if the page url follows /page/wild*", async ({ page }) => {
    const testPageUrl = "/path/wild";
    const response = await page.goto(`${endpointUrl}${testPageUrl}`);
    expect(response?.status()).toBe(200);

    const responseJson = await response?.json();
    expect(responseJson.headers["x-recaptcha-test"]).toEqual("wild-path");

    const testPageUrl2 = "/path/wild/testA";
    const response2 = await page.goto(`${endpointUrl}${testPageUrl2}`);
    expect(response2?.status()).toBe(200);
    const responseJson2 = await response2?.json();
    expect(responseJson2.headers).not.toHaveProperty("x-recaptcha-test");

    const testPageUrl3 = "/path/wildtestB";
    const response3 = await page.goto(`${endpointUrl}${testPageUrl3}`);
    expect(response3?.status()).toBe(200);
    const responseJson3 = await response3?.json();
    expect(responseJson3.headers["x-recaptcha-test"]).toEqual("wild-path");
  });

  test("Set header if the page url follows /path/qu?stion", async ({ page }) => {
    const testPageUrl = "/path/question";
    const response = await page.goto(`${endpointUrl}${testPageUrl}`);
    expect(response?.status()).toBe(200);
    const responseJson = await response?.json();
    expect(responseJson.headers["x-recaptcha-test"]).toEqual("question-path");

    const testPageUrl2 = "/path/quabcstion";
    const response2 = await page.goto(`${endpointUrl}${testPageUrl2}`);
    expect(response2?.status()).toBe(200);
    const responseJson2 = await response2?.json();
    expect(responseJson2.headers).not.toHaveProperty("x-recaptcha-test");

    const testPageUrl3 = "/path/qustion";
    const response3 = await page.goto(`${endpointUrl}${testPageUrl3}`);
    expect(response3?.status()).toBe(200);
    const responseJson3 = await response3?.json();
    expect(responseJson3.headers).not.toHaveProperty("x-recaptcha-test");
  });
});

test.describe("Check Different Conditions", () => {
  // const endpointUrl = process.env.ENDPOINT as string;
  const endpointUrl = "https://recaptchatest3.global.ssl.fastly.net";
  if (!endpointUrl) {
    throw new Error("ENDPOINT environment variable not found.");
  }

  test("Access the conditionally-allowed page", async ({ page }) => {
    const testPageUrl = "/express/allow";
    const response = await page.goto(`${endpointUrl}${testPageUrl}`);
    expect(response?.status()).toEqual(200);
  });

  test("Access the conditionally-blocked page", async ({ page }) => {
    const testPageUrl = "/express/block";
    const response = await page.goto(`${endpointUrl}${testPageUrl}`);
    expect(response?.status()).toEqual(403);
  });

  test("Access the first condition page", async ({ page }) => {
    const testPageUrl = "/condition/1";
    const response = await page.goto(`${endpointUrl}${testPageUrl}`);
    expect(response?.status()).toEqual(200);
    const responseJson = await response?.json();
    expect(responseJson.headers["x-recaptcha-test"]).toEqual("condition-match");
  });

  test("Access the second condition page", async ({ page }) => {
    const testPageUrl = "/condition/2";
    const response = await page.goto(`${endpointUrl}${testPageUrl}`);
    expect(response?.status()).toEqual(200);
    const responseJson = await response?.json();
    expect(responseJson.headers["x-recaptcha-test"]).toEqual("condition-match");
  });

  test("Access the third condition page", async ({ page }) => {
    const testPageUrl = "/condition/3";
    const response = await page.goto(`${endpointUrl}${testPageUrl}`);
    expect(response?.status()).toEqual(200);
    const responseJson = await response?.json();
    expect(responseJson.headers["x-recaptcha-test"]).toEqual("condition-match");
  });
});
