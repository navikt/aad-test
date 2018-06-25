# Nav AAD login test app

This app is meant to test/debug Azure AD configuration.

#### Running

- Copy config.example.js and call it config.js
- Add client id and client secret
- npm install
- Run `node index.js` to start the app

#### Usage

Open `http://localhost:8085` in the browser. You will be
redirected to Microsoft Azure login. Login with a test user, and you
will be redirected back to the test app. The test app will then output
the returned data from Microsoft.

#### Contact/support

No external support is provided for this repository, as it is
only meant for internal testing. If you need to contact the owners,
create a Github issue in the issue tracker for the repository.
