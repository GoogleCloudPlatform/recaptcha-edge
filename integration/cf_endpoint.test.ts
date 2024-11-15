import fetch from 'node-fetch';
import { expect, test, describe } from 'vitest'; 

describe('Cloudflare Worker Integration Test', () => {
  // const endpointUrl = process.env.CLOUDFLARE_ENDPOINT as string;
  const endpointUrl = "https://www.branowl.xyz/";
  if (!endpointUrl) {
    throw new Error('CLOUDFLARE_ENDPOINT environment variable not found.');
  }
  test('should return the expected response from the CF endpoint', async () => {

    const response = await fetch(endpointUrl); 

    expect(response.status).toEqual(200); 

    const data = await response.json(); 
    expect(data.headers).toHaveProperty('cf-connecting-ip'); 
  });

  test('should handle a POST request', async () => {
    const response = await fetch(endpointUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ someData: 'test' })
    });

    expect(response.status).toEqual(200);
  });
});