const express = require('express');
const fetch = require('node-fetch');
const querystring = require('querystring');
const config = require('./config');

const entityMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;'
};

function escape (string) {
    return String(string).replace(/[&<>"'`=\/]/g, function fromEntityMap (s) {
        return entityMap[s];
    });
}

async function runApp() {
    console.log('uri', config.discoveryUri);
    const response = await fetch(config.discoveryUri);
    const discovery = await response.json();
    const { authorization_endpoint, token_endpoint } = discovery;

    const app = express();

    app.get('/', (req, res) => res.redirect(authorization_endpoint + '?' + querystring.stringify({
        response_type: 'code',
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        scope: 'openid profile',
        state: '123',
        nonce: '456'
    })));

    app.get('/gosys/callback', async (req, res) => {
        const code = req.query.code;
        const tokenRes = await fetch(token_endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
            },
            body: querystring.stringify({
                code,
                grant_type: 'authorization_code',
                client_secret: config.clientSecret,
                redirect_uri: config.redirectUri,
                client_id: config.clientId
            })
        });
        const data = await tokenRes.json();
        res.send(`
<h1>Result</h1>
${Object.keys(data).map(key => `<b>${escape(key)}:</b> ${escape(data[key])}<br />`).join('')}
`);
    });

    app.listen(8085, () => console.log('App listening on port 8085'));
}

runApp().catch(console.error);
