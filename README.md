# file-dashboard-be

## Dependencies:
To run the server, several dependencies are needed (dropbox, flask...). These are listed in requirements.txt and can be simply installed with:
```bash
pip install -r requirements.txt
```

## Dropbox:
A [dropbox app](https://www.dropbox.com/developers) needs to be created and set up. There are several things to consider here:
1. Choose Scoped Access API + Full Dropbox access during application creation.
2. Enable additional users under Settings - Development users.
3. Redirect URIs must be manually added in the Settings - OAuth2 section, even for localhost redirects. These must start with https:// (though http is allowed for localhost).
4. Permissions must be set properly: files.content.read, files.content.write, files.metadata.read and files.metadata.write must be enabled.

For more information, refer to the [dropbox documentation](https://developers.dropbox.com/oauth-guide).

## Environment Variables:
Create a .env file in the root directory and specify the following variables:
```
DROPBOX_APP_KEY=
DROPBOX_APP_SECRET=
ARMMS_SECRET=
DROPBOX_REDIRECT_URI=
CALLBACK_REDIRECT_URI=
KEYCLOAK_JWKS_URL=
```
- DROPBOX_APP_KEY and DROPBOX_APP_SECRET are used to link the Dropbox app you just created to the server. They can be found in the settings section under App key and App secret, respectively.
- ARMMS_SECRET is an organisation secret used for signing JWT tokens.
- DROPBOX_REDIRECT_URI is used by dropbox after logging in, this should be the /dropbox_callback endpoint and should be registered under the dropbox application settings (see step 3 of the previous section)
- CALLBACK_REDIRECT_URI is used to redirect the user after successful log in.
- KEYCLOAK_JWKS_URL is used to provide keycloak certificate for validated JWT.

## Keycloak configuration
To run the server, a keycloak configuration is needed. It is stored in a keycloak_config.json file in the root directory.
The JSON file contains the following attributes:
```json
{
  "web": {
    "issuer": "ISSUER_URI",
    "auth_uri": "AUTH_URI",
    "client_id": "CLIENT_ID",
    "client_secret": "CLIENT_SECRET",
    "token_uri": "TOKEN_URI",
    "redirect_uris" : ["REDIRECT_URI"],
    "userinfo_uri": "USER_INFO_URI",
    "token_uri": "TOKEN_URI",
    "logout_uri": "LOGOUT_URI"
  }
}
```
Please inform more about [keycloak](https://www.keycloak.org) and [flask-oidc](https://flask-oidc.readthedocs.io/en/latest).

## Running the server
Once all other steps are completed, you can run the server using [Docker](https://www.docker.com/) and the provided Dockerfile.