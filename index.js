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
        if (req.query.error) {
            res.send(`<h1>Authentication Error</h1><p>${req.query.error_description}</p>`)
            return;
        }
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
        const idToken = data.id_token;

        let text = '';
        try {
            const stsResponse = await fetch(config.stsUrl, {
                method: 'post',
                headers: {
                    'Content-Type': 'text/xml',
                    'SoapAction': 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue'
                },
                body: `
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
<wsse:Security soap:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="UsernameToken-76db6c8f-9de8-4cdf-a23d-3335676df8e7">
<wsse:Username>${config.systemUser}</wsse:Username>
<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${config.systemPassword}</wsse:Password>
</wsse:UsernameToken>
</wsse:Security>
</soap:Header>
<soap:Body>
<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
<wst:SecondaryParameters xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
        <wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>
</wst:SecondaryParameters>
<wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType>
<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
<wst:OnBehalfOf>
<wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="urn:ietf:params:oauth:token-type:jwt">${idToken}</wsse:BinarySecurityToken>
</wst:OnBehalfOf>
<wst:Renewing Allow="false"/>
</wst:RequestSecurityToken>
</soap:Body>
</soap:Envelope>`
            });

            const text = await stsResponse.text();
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
