# OIDC compatible Fake IdP service for testing

This is a HTTP(S) based service with a valid key and discovery endpoint that allows
to generate JWT tokens based on the claims you like to receive.

WARNING: This is a **test** service, don't use the keys and the service as such in a
production setup as it allows you to create any kind of JWT token signed by the given keys.

## Version 0.3 and on

COMMAND LINED ARGUMENTS CHANGED AS OF VERSION 0.3.0

The -s for static is no -f for folder (serving the html for login)

The -h for the exposed host is now -e (that makes the help work as it should)

## Running the service

Running the binary works follows:

```bash
fakeidp
Allows to generate any valid JWT for OIDC

❯ ./target/debug/fakeidp --help
Usage: fakeidp [OPTIONS] [KEYFILE]

Arguments:
  [KEYFILE]  Location of the RSA DER keypair as a file

Options:
  -p, --bind-port <BIND_PORT>
          Sets the port to listen to [default: 8080]
  -b, --bind-host <BIND_HOST>
          Sets the host or IP number to bind to [default: 0.0.0.0]
  -e, --exposed-host <EXPOSED_HOST>
          Full base URL of the host the service is found, like https://accounts.google.com [default: http://localhost:8080]
  -f, --folder <FOLDER>
          Folder for the static files to serve [default: ./static]
  -u, --users <USERS>
          JSON file, or folder of *.json files, holding an array of users (claim sets or encoded JWTs) to pick from on the login screen instead of typing one in [env: USERS=]
  -h, --help
          Print help information
  -V, --version
          Print version information
```

### Generate keys

The mock service makes use of DER encoded key files. The easiest way to generate these are the openssl tool

```
openssl genpkey -algorithm RSA \
                -pkeyopt rsa_keygen_bits:2048 \
                -outform der \
                -out private_key.der
```

Note that a keypair is provided by default.

### The other option is to run it as a DOCKER container:

```bash
docker run -p9090:9090 -e BIND=0.0.0.0 -e PORT=9090 -e EXPOSED_HOST=http://localhost:9090 spectare/fakeidp:latest
```

Add `-e USERS=/users -v $PWD/users:/users:ro` to offer a fixed set of users on the login screen, see
[A fixed set of users to log in as](#a-fixed-set-of-users-to-log-in-as).

where BIND and PORT are environment variables that allow you to change the endpoint binding and address within the container.
Note that you need to expose the port you choose and match that with the exposed host name/port.
EXPOSED_HOST is the base URL used by the outside world to find the ./well-known/openid-configuration and the keys.

## Use it for manual OIDC Login

Point your client at the `.well-known/openid-configuration` endpoint and it will find the authorization
endpoint (`/auth`). Both the **authorization code flow with PKCE** (RFC 7636) and the older **implicit
flow** are supported; which one you get is decided by the `response_type` you send.

Either way you land on a login screen where you set the `sub(ject)` - most of the times your account ID -
and the name. Use **Add claim** to put any other claim in the tokens, for example `email`,
`email_verified` or `groups`.

Claim values are read as JSON when they parse as JSON, so `true` becomes a boolean, `1735689600` a number
and `["admin","user"]` an array. Anything else stays a string. Claims you enter override the defaults the
service would otherwise pick, so setting `iss`, `aud` or an `exp` in the past is a way to produce a token
your client should reject.

### A fixed set of users to log in as

Typing a subject and claims on every login gets old. Pass `-u`/`--users` (or set `USERS`) to a JSON file
holding an array of users and the login screen lists them instead: subject and name up front, the other
claims folded away under a click, and a **Login** button next to each that runs the flow as that user. The manual
form is still there, folded away under **Log in as someone else** below the list. Without the option you get the
manual form directly.

```json
[
  { "sub": "F82E617D", "name": "Arie Ministrone", "email": "admin@example.com", "groups": ["admin"] },
  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwQjZGM0MxRSIsIm5hbWUiOiJFbGxhIn0.c2ln"
]
```

An entry is either a claim set, used verbatim (so an `exp` in it is the `exp` you get), or an encoded JWT, of
which only the payload is read. The signature is not checked, and `iat`, `exp`, `nbf` and `auth_time` are
dropped from it, because a token copied from somewhere was minted in the past. Every entry needs a string `sub`;
the service refuses to start otherwise.

`-u` also takes a folder, in which case every `*.json` file in it is read in file name order. That is the way to
use it with docker compose: mount the folder, not the file, because editors replace a file on save and a
single-file bind mount keeps pointing at the old one. Users are read at startup, so restart after editing.

```yaml
services:
  fakeidp:
    image: spectare/fakeidp:latest
    ports:
      - "9090:9090"
    environment:
      PORT: "9090"
      EXPOSED_HOST: "http://localhost:9090"
      USERS: /usr/local/etc/fakeidp/users
    volumes:
      - ./users:/usr/local/etc/fakeidp/users:ro
```

A runnable version, with two example users, is in [examples/](examples/docker-compose.yml).

### Authorization code flow with PKCE

Send `response_type=code` together with a `code_challenge`:

```
GET /auth?response_type=code
         &client_id=my-test-app
         &redirect_uri=http://localhost:3000/callback
         &scope=openid%20profile
         &state=xyz
         &nonce=n-0S6_WzA2Mj
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
         &code_challenge_method=S256
```

After the login screen the browser is redirected to `redirect_uri?code=...&state=...`. Exchange that code
at the token endpoint:

```bash
curl -X POST http://localhost:8080/token \
  -d grant_type=authorization_code \
  -d code=<the code from the redirect> \
  -d redirect_uri=http://localhost:3000/callback \
  -d client_id=my-test-app \
  -d code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

which returns the usual token response:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 12200,
  "scope": "openid profile"
}
```

Both `S256` and `plain` challenge methods work. PKCE is optional: leave the `code_challenge` out of the
authorization request and the code can be exchanged without a `code_verifier`.

A few deliberate conveniences for a test service:

- Authorization codes live for 10 minutes and are single use, but only a *successful* exchange spends
  them. A rejected `code_verifier` leaves the code alone so you can fix your client and retry the same
  code.
- There is no client registration and no client secret. `client_id` is whatever you send, and it is
  echoed back as the `aud` claim. `redirect_uri` and `client_id` only have to match between the
  authorization request and the token request.
- Codes are held in memory, so restarting the service invalidates the outstanding ones.

### Implicit flow

Send `response_type=token%20id_token&scope=openid` and the tokens come straight back in the fragment of
the redirect: `redirect_uri#access_token=...&id_token=...&state=...&token_type=bearer`.

## Example for JWT token creation

Next to its role as the OAuth token endpoint, `/token` doubles as a "sign this for me" shortcut: post a
bare JSON object and get the encoded JWT back as `text/plain`. The two are told apart by the content
type, so a form encoded body is treated as a code exchange and anything else as a claim set to sign.

The service runs by default on port 8080 and in order to generate a token, you post the required claimset
to the /token endpoint

```bash
curl -d "@claim.json" -X POST http://`hostname -f`:9090/token
```

where claim.json contains the claimset:

```json
{
  "iss": "http://localhost:8080/mock",
  "sub": "CgVhZG1pbhIFbG9jYWw",
  "aud": "cafienne-ui",
  "exp": 1576568495,
  "iat": 1576482095,
  "at_hash": "zqKhL-sV6TNJUFQSF7PwLQ",
  "email": "admin@example.com",
  "email_verified": true,
  "name": "admin"
}
```

## Example for userinfo

When you need to mock your userinfo call, you can create a token with the above example and thereafter
do a GET on the /userinfo enpoint with an 'Authorization' header including 'Bearer <jwt>' where <jwt> is the
generated token of the example.

Note that your claims need to contain the fields you want to return for userinfo.
Currently supported are:

```json
{
  "iss": "http://localhost:8080",
  "sub": "F82E617D-DEAF-4EE6-8F96-CF3409060CA2",
  "email": "admin@example.com",
  "email_verified": true,
  "name": "Arie Ministrone"
}
```

Name, email and email_verified. The other 2 are required for generation of the token and are used in the validation.
