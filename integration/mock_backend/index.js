const express = require("express");
const handlebars = require("express-handlebars");
const path = require("path");
const config = require("./config");
const https = require("https");
const fs = require("fs");
const app = express();
var https_options = null;
try {
  var key = fs.readFileSync(__dirname + "/certs/selfsigned.key");
  var cert = fs.readFileSync(__dirname + "/certs/selfsigned.crt");
  https_options = {
    key: key,
    cert: cert,
  };
} catch {}

app.engine("handlebars", handlebars.engine({ defaultLayout: false })); // No default layout here
app.set("view engine", "handlebars");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public")); // Serve static files from public folder

// Function to set Cache-Control header
function setCacheControl(res, value) {
  res.setHeader("Cache-Control", value);
}

app.get("/token/action", (req, res) => {
  setCacheControl(res, "public, max-age=3600"); // no-store: Don't cache this route
  res.render("action", { siteKey: config.actionSiteKey });
});

app.get("/token/session", (req, res) => {
  setCacheControl(res, "public, max-age=3600"); // Example: Cache for 1 hour
  res.render("session", { siteKey: config.sessionSiteKey });
});

app.get("/token/v3web", (req, res) => {
  setCacheControl(res, "no-cache"); // Example: Revalidate with the server
  res.render("v3web", { siteKey: config.enterpriseSiteKey });
});

app.get("/token/credentials", (req, res) => {
  setCacheControl(res, "private, max-age=60"); // Example: Cache for 60 seconds, only for the browser
  res.render("credentials", { siteKey: config.enterpriseSiteKey });
});

app.get("*", (req, res) => {
  setCacheControl(res, "public, max-age=3600"); // Example: Don't cache this route
  res.send({
    url: req.url,
    method: req.method,
    body: req.body,
    headers: req.headers,
    query: req.query,
    params: req.params,
  });
});

app.listen(config.http_port, () => {
  console.log(`mock backend listening on port ${config.http_port}`);
});

if (config.https_port > 0 && https_options) {
  var server = https.createServer(https_options, app);
  server.listen(config.https_port, () => {
    console.log(`mock backend https starting on port " ${config.https_port}`);
  });
}
