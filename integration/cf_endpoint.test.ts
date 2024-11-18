import {
  createExecutionContext,
  env,
  fetchMock,
  SELF,
  waitOnExecutionContext,
} from "cloudflare:test";
import { expect, test, describe } from 'vitest';
import puppeteer from "@cloudflare/puppeteer";
import "../bindings/cloudflare/src";

describe('Cloudflare Worker Integration Test', () => {
  // const endpointUrl = process.env.CLOUDFLARE_ENDPOINT as string;
  const endpointUrl = "https://www.branowl.xyz/";
  if (!endpointUrl) {
    throw new Error('CLOUDFLARE_ENDPOINT environment variable not found.');
  }
  test('should return the expected response from the CF endpoint', async () => {

    const response = await SELF.fetch(endpointUrl); 
    expect(response.status).toEqual(200); 

    const data = await response.json(); 
    expect(data.headers).toHaveProperty('cf-connecting-ip'); 
  });

  // test('should inject JavaScript code into HTML', async () => {
  //   const testPageUrl = 'https://my-test-page.example.com'; // Your test page URL

  //   // Fetch the test page through the Cloudflare Worker
  //   const response = await fetch(`${endpointUrl}${testPageUrl}`); 
  //   expect(response.status).toEqual(200);

  //   const html = await response.text();

  //   // Assert that the injected JavaScript code is present in the HTML
  //   expect(html).toContain(`<script>console.log("Injected code!");</script>`); 

  //   // If the placement of the injected code is important, add more specific assertions
  //   // For example, to check if it's injected before the closing </body> tag:
  //   expect(html).toMatch(/<script>console\.log\("Injected code!"\);<\/script>\s*<\/body>/); 
  // });

  // test('should not inject JavaScript code when conditions are not met', async () => {
  //   const testPageUrl = 'https://my-excluded-page.example.com'; // A page where injection shouldn't happen

  //   const response = await fetch(`${endpointUrl}${testPageUrl}`);
  //   expect(response.status).toEqual(200);

  //   const html = await response.text();

  //   // Assert that the injected code is NOT present
  //   expect(html).not.toContain('<script>console.log("Injected code!");</script>'); 
  // });

  // Add more test cases for different scenarios:
  // - Different content types (e.g., application/xhtml+xml)
  // - Error handling (e.g., invalid URLs)
  // - Large HTML files
  // - Unusual HTML structures
});
