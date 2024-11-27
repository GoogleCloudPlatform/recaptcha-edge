import { test, expect, Cookie } from '@playwright/test';
import { chromium, firefox, webkit } from 'playwright';

test('has title', async ({ page }) => {
  await page.goto('https://playwright.dev/');

  // Expect a title "to contain" a substring.
  await expect(page).toHaveTitle(/Playwright/);
});

test('get started link', async ({ page }) => {
  await page.goto('https://playwright.dev/');

  // Click the get started link.
  await page.getByRole('link', { name: 'Get started' }).click();

  // Expects page to have a heading with the name of Installation.
  await expect(page.getByRole('heading', { name: 'Installation' })).toBeVisible();
});

// The end of default test examples.

test('should fetch the CF endpoint correctly', async ({ page }) => {
  const response = await page.goto("https://www.branowl.xyz/action/allow");
  expect(response?.status()).toBe(200); 
  await expect(page).toHaveURL("https://www.branowl.xyz/action/allow"); 
});

test('should get session token as a cookie', async ({ page }) => {
  let cookies : Cookie[] = [];
  const browser = await chromium.launch({ headless: true});
  const context = await browser.newContext();
  
  const endpointUrl = "https://www.branowl.xyz"; 

  try {
    const page = await context.newPage();
    // Perform JS injection automatically.
    await page.goto(`${endpointUrl}/token/session`);
    await page.waitForTimeout(5000); // important
    // Get cookies from the current context
    cookies = await context.cookies();

  } catch (err) {
    await browser.close();
    throw new Error(err.message);
  }

  // // Extract the token from the cookie
  const sessionToken = cookies.find(cookie => cookie.name === 'recaptcha-fastly-t')?.value; // TODO: the cookie name should be more generic
  // // Assert that the token is not empty
  expect(sessionToken).toBeTruthy();
  
  page.on('console', (msg) => {
    console.log(msg);
  });
});

test('should generate an action token after execute() by clicking the button', async ({ page }) => {
  const endpointUrl = "https://www.branowl.xyz"; 

  // Go to the page with the reCAPTCHA
  await page.goto(`${endpointUrl}/token/action`);

  // Intercept the request triggered by the button click
  const responsePromise = page.waitForResponse(response => 
    response.url().includes('/token/action') && 
    response.request().method() === 'GET' &&
    !!response.request().headers()['x-recaptcha-token'] // Check if the header exists and is truthy
  );

  // Click the "Execute Button"
  await page.click('#execute-button');

  // Wait for the response and extract the token from the header
  const response = await responsePromise;
  const actionToken = response.request().headers()['x-recaptcha-token'];

  // Assert that the token is not empty
  expect(actionToken).toBeTruthy();
  console.log('Action Token:', actionToken);

  // TODO: CreateAsessment by visit condition matching pages
});