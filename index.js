const express = require('express');
const url = require('url');
const fetch = require('node-fetch');
const HttpsProxyAgent = require('https-proxy-agent');
const querystring = require('querystring');
const config = require('./config');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

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

const agent = new HttpsProxyAgent({
    ...url.parse('http://webproxy-utvikler.nav.no:8088'),
    rejectUnauthorized: false
});

function escape (string) {
    return String(string).replace(/[&<>"'`=\/]/g, function fromEntityMap (s) {
        return entityMap[s];
    });
}

async function runApp() {
    console.log('uri', config.discoveryUri);
    const response = await fetch(config.discoveryUri, {
        agent
    });
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
        if (req.query.error) {
            res.send(`<h1>Authentication Error</h1><p>${req.query.error_description}</p>`)
            return;
        }
        const code = req.query.code;
        const tokenRes = await fetch(token_endpoint, {
            agent,
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

        if (tokenRes.status != 200) {
            res.send('<h1>Authentication Error</h1>' + data.error_description);
            return;
        }

        const idToken = data.id_token;
        const encodedToken = Buffer.from(idToken, 'utf-8').toString('base64');

        let text = '';
        try {
            const body = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><wsse:Security soap:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="UsernameToken-2aa9eb5e-df63-49f8-acba-62e32f7465e6"><wsse:Username>${config.systemUser}</wsse:Username><wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${config.systemPassword}</wsse:Password></wsse:UsernameToken></wsse:Security></soap:Header><soap:Body><wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><wst:SecondaryParameters xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
<wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>
</wst:SecondaryParameters><wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType><wst:OnBehalfOf><wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="urn:ietf:params:oauth:token-type:jwt">${encodedToken}</wsse:BinarySecurityToken></wst:OnBehalfOf><wst:Renewing Allow="false"/></wst:RequestSecurityToken></soap:Body></soap:Envelope>`;

            console.log('==========');
            console.log(body);
            console.log('==========');

            const stsResponse = await fetch(config.stsUrl, {
                method: 'post',
                headers: {
                    'content-type': 'text/xml; charset=UTF-8',
                    accept: '*/*',
                    soapaction: '"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"',
                    'user-agent': 'Apache-CXF/3.2.1',
                    'cache-control': 'no-cache',
                    pragma: 'no-cache'
                },
                body
            });

            console.log('Response status: ' + stsResponse.status);

            text = await stsResponse.text();

            console.log(text);
        } catch (err) {
            text = 'Could not get SAML token: ' + err;
        }

        res.send(`
<h1>Result</h1>
${Object.keys(data).map(key => `<b>${escape(key)}:</b> ${escape(data[key])}<br />`).join('')}

<h2>SAML</h2>
<pre>${escape(text)}</pre>
`);
    });

    app.listen(8085, () => console.log('App listening on port 8085'));
}

runApp().catch(console.error);
