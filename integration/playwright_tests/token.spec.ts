import { test, expect, Cookie } from '@playwright/test';
import { chromium, firefox, webkit } from 'playwright';

test.beforeEach(async ({ context }) => {
  // Create a new page with an empty context for each test
  const page = await context.newPage(); 
});

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

  // call CreateAsessment by visit condition matching pages
  const condition1Response = await page.goto(`${endpointUrl}/condition/1`);

  // Assert that the x-recaptcha-test header is set correctly
  const headers = condition1Response?.headers();
  // Match the expected value from the firewall rule
  // expect(headers?.['x-recaptcha-test']).toBe('condition-match'); 
});

test('should generate an action token after execute() by clicking the button', async ({ page }) => {
  const endpointUrl = "https://www.branowl.xyz"; 

  // Go to the page with the reCAPTCHA
  await page.goto(`${endpointUrl}/token/action`);

  // Intercept the request triggered by the button click
  const responsePromise = page.waitForResponse(response => 
    response.url().includes('/token/action') && 
    response.request().method() === 'GET' &&
    !!response.request().headers()['x-recaptcha-token'] // Check if the header exists
  );

  // Click the "Execute Button"
  await page.click('#execute-button');

  // Wait for the response and extract the token from the header
  const response = await responsePromise;
  const actionToken = response.request().headers()['x-recaptcha-token'];

  // Assert that the token is not empty
  expect(actionToken).toBeTruthy();
  // console.log('Action Token:', actionToken);

  // call CreateAsessment by visit condition matching pages
  const condition1Response = await page.goto(`${endpointUrl}/condition/1`);

  // Assert that the x-recaptcha-test header is set correctly
  const headers = condition1Response?.headers();
  // Match the expected value from the firewall rule
  // expect(headers?.['x-recaptcha-test']).toBe('condition-match'); 

});

test('should get session token after visiting the intended injectJS path', async ({ page }) => {
  const endpointUrl = "https://www.branowl.xyz/hello.html"; 

  await page.goto(`${endpointUrl}`);

  // Wait for the reCAPTCHA script to be injected (adjust timeout if needed)
  await page.waitForTimeout(5000); 

  // Check if the reCAPTCHA script is present in the page
  const scriptExists = await page.evaluate(() => {
    return Array.from(document.querySelectorAll('script')).some(script => 
      script.src.includes('www.google.com/recaptcha/enterprise.js')
    );
  });
  expect(scriptExists).toBe(true);
});

// To be verified: Express Key with Condition
test('should access express allow page with condition set', async ({ page }) => {
  const response = await page.goto("https://www.branowl.xyz/express/allow");
  expect(response?.status()).toBe(200); 
});

test('should deny express block page with condition set', async ({ page }) => {
  const response = await page.goto("https://www.branowl.xyz/express/block");
  expect(response?.status()).toBe(500); 
});

// TODO: Merge the CF_end_to_end tests with Express only?

test('should get challenge token as a cookie', async ({ page }) => {
  let cookies : Cookie[] = [];
  const browser = await chromium.launch({ headless: true});
  const context = await browser.newContext();
  
  const endpointUrl = "https://www.branowl.xyz"; 

  try {
    const page = await context.newPage();
    // Perform JS injection automatically.
    await page.goto(`${endpointUrl}/action/redirect`);
    await page.waitForTimeout(5000); // important
    // Get cookies from the current context
    cookies = await context.cookies();

  } catch (err) {
    await browser.close();
    throw new Error(err.message);
  }

  // // Extract the token from the cookie
  const challengeToken = cookies.find(cookie => cookie.name === 'recaptcha-fastly-e')?.value;
  // // Assert that the token is not empty
  expect(challengeToken).toBeTruthy();

  // call CreateAsessment by visit condition matching pages
  const condition1Response = await page.goto(`${endpointUrl}/condition/1`);

  // Assert that the x-recaptcha-test header is set correctly
  const headers = condition1Response?.headers();
  // Match the expected value from the firewall rule
  // expect(headers?.['x-recaptcha-test']).toBe('condition-match'); 
});