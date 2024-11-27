const express = require('express');
const handlebars = require('express-handlebars');
const path = require('path');
const config = require('./config');
const app = express();

app.engine('handlebars', handlebars.engine({defaultLayout: false})); // No default layout here
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public')); // Serve static files from public folder

app.get('/token/action', (req, res) => {
  res.render('action',
    { siteKey: config.actionSiteKey });
});

app.get('/token/session', (req, res) => {
  res.render('session',
    { siteKey: config.sessionSiteKey });
});

app.get('*', (req, res) => {
  res.send({
    url: req.url,
    method: req.method,
    body: req.body,
    headers: req.headers,
    query: req.query,
    params: req.params
  });
});

app.listen(config.port, () => {
  console.log(`mock backend listening on port ${config.port}`);
});