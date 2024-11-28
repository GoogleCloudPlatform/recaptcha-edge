# Mock Backend

This project will serve a simple website that returns basic HTTP parameters
as a JSON object. This is intended to be used for testing WAF behaviour.

For example, testing that a silent redirect occurred, a header was added,
or traffic was blocked.

## How to run

Install dependencies with `npm i`.

Add site keys to config.js.

Run with `npm run start`

## How to use

This project is intended to fill in as a backend in a WAF workflow. This Backend
should be turned up on a server, the WAF under test should point to this server.

Visiting the public WAF address should show pages hosted on this backend.

The `/token/action` page hosts entry form that will asynchronously submit a
request with an 'action' token attached.

The `/token/session` page hosts a page with session token Javascript already
installed.

`/hello.html` is a static HTML page, intended to test JavaScript injection.

All other pages return a synthetic JSON response. This response is intended to
be parsed by integration tests to confirm Firewall Policy behaviour.