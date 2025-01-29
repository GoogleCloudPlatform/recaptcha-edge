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

import { describe, test, afterAll, beforeAll } from "vitest";
import assert from "node:assert";
import path from "node:path";
import url from "node:url";
import express from "express";
import { JSDOM } from "jsdom";

import { ComputeApplication } from "@fastly/compute-testing";

describe("Run local Viceroy", function () {
  // Represents the app running in the local development environment
  const testPolicies = [
    {
      name: "test-policy",
      description: "test-description",
      path: "/action/allow",
      condition: "recaptcha.score > 0.5",
      // 'type' isn't a part of the interface, but is added for testing.
      actions: [{ allow: {}, type: "allow" }],
    },
    {
      name: "test-policy2",
      description: "test-description2",
      path: "/action/block",
      actions: [{ block: {}, type: "block" }],
    },
    {
      name: "test-policy3",
      description: "test-description3",
      path: "/action/redirect",
      condition: "recaptcha.score > 0.5",
      actions: [{ redirect: {}, type: "redirect" }],
    },
  ];

  const app = new ComputeApplication();

  const origin_app = express();
  origin_app.get("/helloworld", (req, res) => {
    res.send("<html><head><title>hello</title></head>helloworld</html>");
  });
  origin_app.get("/inject", (req, res) => {
    res.send("<html><head><title>inject</title></head>inject</html>");
  });
  origin_app.listen(18080, () => {
    console.log("origin mock running on port 18080");
  });
  const goog_app = express();
  goog_app.post("/recaptcha/challengepage", (req, res) => {
    res.send("<html>challengepage!</html>");
  });
  goog_app.listen(18081, () => {
    console.log("challengepage mock running on port 18081");
  });

  const rc_app = express();
  let assessment_count = 0;
  rc_app.get("/v1/projects/:projectNumber/firewallpolicies", (req, res) => {
    res.json({ firewallPolicies: testPolicies });
  });
  rc_app.post("/v1/projects/:projectNumber/assessments", (req, res) => {
    assessment_count++;
    res.json({
      firewallPolicyAssessment: {
        firewallPolicy: {
          name: "test-policy3",
          description: "test-description3",
          path: "/action/redirect",
          condition: "recaptcha.score > 0.5",
          actions: [{ redirect: {}, type: "redirect" }],
        },
      },
    });
  });
  rc_app.listen(18082, () => {
    console.log("recaptcha mock running on port 18082");
  });

  beforeAll(async function () {
    // Start the app
    const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
    await app.start({
      // Set 'appRoot' to the directory in which to start the app.  This is usually
      // the directory that contains the 'fastly.toml' file.
      appRoot: path.join(__dirname, "../"),
      // Optionally set 'addr', which defaults to 'http://127.0.0.1:7676/', it can be
      // used to start the development environment on a different local address or port.
      // addr: 'http://127.0.0.1:7676/'
    });
  });

  test("Response status code is 200", async function () {
    // Make a fetch request to the app. Returns a Promise that resolves to a Response.
    const response = await app.fetch("/helloworld");
    assert.equal(await response.text(), "<html><head><title>hello</title></head>helloworld</html>");
    assert.equal(response.status, 200);
  });

  test("Response headers include Content-Type: text/html", async function () {
    const response = await app.fetch("/helloworld");
    const contentTypeHeaders = (response.headers.get("content-type") ?? "")
      .split(",")
      .map((value) => value.trim().split(";")[0]);
    assert.equal(response.headers, "");
    assert.ok(contentTypeHeaders.includes("text/html"));
  });

  test("local block", async function () {
    const response = await app.fetch("/action/block");
    assert.equal(response.status, 403);
  });

  test("remote redirect", async function () {
    const response = await app.fetch("/action/redirect");
    assert.equal(await response.text(), "<html>challengepage!</html>");
  });

  test("js injection", async function () {
    const response = await app.fetch("/inject");

    const html = await response.text();
    const dom = new JSDOM(html);
    const document = dom.window.document;

    // Check if the script tag with the specific src exists
    const scriptTag = document.querySelector("script");

    assert.ok(scriptTag, "Script tag not found");
    assert.equal(scriptTag.src, "https://www.google.com/recaptcha/enterprise.js?render=sessionkey&waf=session");
  });

  afterAll(async function () {
    // Shut down the app
    await app.shutdown();
  });
});
