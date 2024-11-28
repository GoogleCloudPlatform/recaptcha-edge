import { expect, test, describe } from 'vitest';

describe('Check Different Actions', () => {
  // const endpointUrl = process.env.CLOUDFLARE_ENDPOINT as string;
  const endpointUrl = "https://recaptchawaf.global.ssl.fastly.net/";
  if (!endpointUrl) {
    throw new Error('CLOUDFLARE_ENDPOINT environment variable not found.');
  }

  test('should fetch the Fastly endpoint correctly', async () => {
    const response = await fetch(endpointUrl); 
    expect(response.status).toEqual(200); 
  });

  test('Access the allow page', async () => {
    const testPageUrl = 'action/allow';
    const response = await fetch(`${endpointUrl}${testPageUrl}`); 
    expect(response.status).toEqual(200);
  });

  test('Access the block page', async () => {
    const testPageUrl = 'action/block';
    const response = await fetch(`${endpointUrl}${testPageUrl}`); 
    expect(response.status).toEqual(403);
  });

  test('Access the redirect page', async () => {
    const testPageUrl = 'action/redirect';
    const response = await fetch(`${endpointUrl}${testPageUrl}`); 
    expect(response.status).toEqual(200);
  
    const html = await response.text();
    expect(html).toContain(`<base href="https://www.google.com/recaptcha/challengepage/">`); 
  });

  test('Access the substitute page', async () => {
    const testPageUrl = 'action/substitute';
    const response = await fetch(`${endpointUrl}${testPageUrl}`); 
    expect(response.status).toEqual(200);
    const html = await response.text();
    const html_json = JSON.parse(html)
    expect(html_json.url).toEqual('/substitute/target'); 
  });

  test('Access the set header page', async () => {
    const testPageUrl = 'action/setheader';
    const response = await fetch(`${endpointUrl}${testPageUrl}`); 
    expect(response.status).toEqual(200);
    const html = await response.text();
    const html_json = JSON.parse(html)
    expect(html_json.headers['x-recaptcha-test']).toEqual('test-value'); 
  });

  // TODO: JS injection

});

describe('Check Different Path Matching', () => {
  // const endpointUrl = process.env.CLOUDFLARE_ENDPOINT as string;
  const endpointUrl = "https://recaptchawaf.global.ssl.fastly.net/";
  if (!endpointUrl) {
    throw new Error('Fastly environment variable not found.');
  }

  test('Set header if the page url follows /page/wild*', async () => {
    const testPageUrl = 'path/wild';
    const response = await fetch(`${endpointUrl}${testPageUrl}`); 
    expect(response.status).toEqual(200);
    const html = await response.text();
    const html_json = JSON.parse(html)
    expect(html_json.headers['x-recaptcha-test']).toEqual('wild-path'); 

    // '*' and '**' glob patterns act differently
    const testPageUrl2 = 'path/wild/testA';
    const response2 = await fetch(`${endpointUrl}${testPageUrl2}`); 
    expect(response2.status).toEqual(200);
    const html2 = await response2.text();
    const html_json2 = JSON.parse(html2)
    expect(html_json2.headers).to.not.have.property('x-recaptcha-test');

    const testPageUrl3 = 'path/wildtestB';
    const response3 = await fetch(`${endpointUrl}${testPageUrl3}`); 
    expect(response3.status).toEqual(200);
    const html3 = await response3.text();
    const html_json3 = JSON.parse(html3)
    expect(html_json3.headers['x-recaptcha-test']).toEqual('wild-path'); 
  });


  test('Set header if the page url follows /path/qu?stion', async () => {
    const testPageUrl = 'path/question';
    const response = await fetch(`${endpointUrl}${testPageUrl}`); 
    expect(response.status).toEqual(200);
    const html = await response.text();
    const html_json = JSON.parse(html)
    expect(html_json.headers['x-recaptcha-test']).toEqual('question-path'); 

    // '?' and '??' glob patterns act differently
    const testPageUrl2 = 'path/quabcstion';
    const response2 = await fetch(`${endpointUrl}${testPageUrl2}`); 
    expect(response2.status).toEqual(200);
    const html2 = await response2.text();
    const html_json2 = JSON.parse(html2)
    expect(html_json2.headers).to.not.have.property('x-recaptcha-test');

    const testPageUrl3 = 'path/qustion';
    const response3 = await fetch(`${endpointUrl}${testPageUrl3}`); 
    expect(response3.status).toEqual(200);
    const html3 = await response3.text();
    const html_json3 = JSON.parse(html3)
    expect(html_json3.headers).to.not.have.property('x-recaptcha-test');
  });

});

// describe('Check Different Conditions', () => {
//   const endpointUrl = "https://www.branowl.xyz/";
//   if (!endpointUrl) {
//     throw new Error('CLOUDFLARE_ENDPOINT environment variable not found.');
//   }

//   test('Set header if http.path == "/condition/1"', async () => {
//     const testPageUrl = 'condition/1';
//     const response = await fetch(`${endpointUrl}${testPageUrl}`); 
//     expect(response.status).toEqual(200);
//     const html = await response.text();
//     const html_json = JSON.parse(html)
//     expect(html_json.headers['x-recaptcha-test']).toEqual('test-value'); 
//   });

//   test('Set header if http.domain == "branowl.xyz"', async () => {
//     const testPageUrl = 'condition/2';
//     const response = await fetch(`${endpointUrl}${testPageUrl}`); 
//     expect(response.status).toEqual(200);
//     const html = await response.text();
//     const html_json = JSON.parse(html)
//     expect(html_json.headers['x-recaptcha-test']).toEqual('test-value'); 
//   });

//   test('Set header if recaptcha.score > 0.7', async () => {
//     const testPageUrl = 'condition/3';
//     const response = await fetch(`${endpointUrl}${testPageUrl}`); 
//     expect(response.status).toEqual(200);
//     const html = await response.text();
//     const html_json = JSON.parse(html)
//     expect(html_json.headers['x-recaptcha-test']).toEqual('test-value'); 
//   });
// });
