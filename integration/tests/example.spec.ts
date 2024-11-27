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

test('should get session cookie after JS injection', async ({ page }) => {
  let cookies : Cookie[] = [];
  const browser = await chromium.launch({ headless: true});
  const context = await browser.newContext();
  
  // const sessionKey = '6LcG0V0qAAAAABKRl9x2_Rf2MMKdwg55Kcps11el';
  const endpointUrl = "https://www.branowl.xyz"; 

  try {
    const page = await context.newPage();
    // Perform JS injection automatically.
    await page.goto(`${endpointUrl}/token/session`);

    await page.waitForTimeout(5000); // important
    // Get cookies from the current context
    cookies = await context.cookies();
    console.log('Cookies after landing on session page:', cookies);

  } catch (err) {
    await browser.close();
    throw new Error(err.message);
  }

  // // Extract the token from the cookie
  const token = cookies.find(cookie => cookie.name === 'recaptcha-fastly-t')?.value;
  console.log('Token:', token); 

  // // Assert that the token is not empty
  expect(token).toBeTruthy();
  
  page.on('console', (msg) => {
    console.log(msg);
  });

  // createAssessment API call with condition match
});