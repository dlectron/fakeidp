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
  -c, --clients <CLIENTS>
          JSON file, or folder of *.json files, holding an array of clients for the client credentials and token exchange grants: their claims, allowed flows and allowed resources. Clients not in it are allowed everything [env: CLIENTS=]
  -s, --styling <STYLING>
          Folder restyling the login screen: custom.css, logo.<ext> and background.<ext> are picked up when present, and the folder is served under /styling [env: STYLING=]
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
[A fixed set of users to log in as](#a-fixed-set-of-users-to-log-in-as), and
`-e CLIENTS=/clients -v $PWD/clients:/clients:ro` to describe the clients of the machine-to-machine grants,
see [A clients file](#a-clients-file).

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

### Restyling the login screen

Pass `-s`/`--styling` (or set `STYLING`) to a folder to change the look of the login screen without
rebuilding. It is served under `/styling`, and these files in it are picked up when present:

| File | Effect |
|---|---|
| `custom.css` | Linked after the built-in `/static/main.css`, so its rules override the defaults |
| `logo.<ext>` | Replaces the logo in the navbar |
| `background.<ext>` | Covers the page behind the login panel (`cover`, centred, fixed) |

`<ext>` is one of `svg`, `png`, `webp`, `jpg`, `jpeg` or `gif`, looked for in that order. Every file is
optional; leave one out and you get the default for it. Other files in the folder, such as fonts or images
your `custom.css` refers to, are served too, at `/styling/<file>`. The folder is checked on every page
load, so unlike the users file there is no need to restart after a change. The service refuses to start if
the folder does not exist.

The background's size and position come from the `.theme-body--image` class in `main.css`; override it in
`custom.css` to tile or anchor the image instead. With docker compose, mount the folder:

```yaml
    environment:
      STYLING: /usr/local/etc/fakeidp/styling
    volumes:
      - ./styling:/usr/local/etc/fakeidp/styling:ro
```

[examples/styling](examples/styling) has one of each file and is used by the
[example compose file](examples/docker-compose.yml).

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

## Machine-to-machine grants

Two more grants at the token endpoint serve calls made without a person present. Their behaviour follows
[Rauthy](https://github.com/sebadob/rauthy) 0.36.1, so that a stack tested against this service behaves
the same against that one; the places where this service is more lenient are listed at the end.

The discovery document advertises them as OIDC Discovery 1.0 and RFC 8414 prescribe: both grants in
`grant_types_supported` (`client_credentials` and `urn:ietf:params:oauth:grant-type:token-exchange`), the
three ways to identify the client in `token_endpoint_auth_methods_supported` (`client_secret_basic`,
`client_secret_post`, `none`), and the claims they add — `azp` and `act` — in `claims_supported`. Neither RFC
8693 nor RFC 8707 defines further metadata, so there is no flag for `resource` or the issued token type.

### Client credentials

A client gets a token as itself (RFC 6749 4.4):

```bash
curl -X POST http://localhost:8080/token \
  -d grant_type=client_credentials \
  -d client_id=integration \
  -d client_secret=anything \
  -d resource=http://localhost:8083
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 12200
}
```

The access token has `sub` and `azp` set to the client id, `iss` to the exposed host, and `aud` to the client
id plus the `resource` when one was given (`["integration", "http://localhost:8083"]`; a string when it is
the client id alone). There is no `id_token` and no `refresh_token`. The client id can also come from an
`Authorization: Basic` header; the secret is read and ignored either way. A `scope` parameter is ignored, as
Rauthy ignores it: give the client a `scope` claim in the clients file instead.

### Token exchange

A client swaps a user's access token for one meant for a single service (RFC 8693). Without an
`actor_token` the new token looks like the user's; with one it carries an `act` claim naming the acting
party:

```bash
curl -X POST http://localhost:8080/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=integration \
  -d subject_token=<the user's access token> \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d actor_token=<the integration client's own token> \
  -d actor_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d resource=http://localhost:8083 \
  -d scope=openid
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 12200,
  "scope": "openid"
}
```

- The subject token's claims (`sub`, `name`, `email`, `groups`, anything else) are copied into the new
  token; `iss`, `aud`, `azp`, `iat`, `exp`, `scope` and `act` are set afresh. `aud` is the client id plus
  the target, as above.
- **The subject and actor tokens are verified**: they must be signed by this service's key and, when they
  have an `exp`, not be expired. Otherwise the answer is `invalid_grant`. This is the one place the service
  checks a token, so that a backend's "the IdP refused the user's token" branch can be tested. An expired
  token is still one `/token` call away on the legacy path, see below.
- `resource` or `audience` names the target; both at once is `invalid_target`.
- `scope` can only narrow the subject token's `scope`; asking for more is `invalid_scope`. Without a
  `scope` the subject token's is kept. Tokens from the login screen carry their granted scope for this.
- Only `urn:ietf:params:oauth:token-type:access_token` is accepted as `subject_token_type`,
  `actor_token_type` (required with an `actor_token`) and `requested_token_type`.
- With an `actor_token`, `act` is `{"sub": <actor's sub>}`, and when the actor token has an `act` of its
  own, that one is nested inside.

### A clients file

Pass `-c`/`--clients` (or set `CLIENTS`) to a JSON file, or a folder of `*.json` files, holding an array of
clients:

```json
[
  {
    "client_id": "integration",
    "claims": { "name": "Integration service", "scope": "openid" },
    "flows": ["client_credentials", "token_exchange"],
    "allowed_resources": ["http://localhost:8083", "http://localhost:8084"]
  },
  { "client_id": "no-exchange", "flows": ["client_credentials"] }
]
```

- `claims` are added to every client-credentials token of that client, over the defaults (`sub` included,
  if you insist).
- `flows` and `allowed_resources` restrict the client: a grant not in `flows` is `unauthorized_client`, a
  `resource`/`audience` not in `allowed_resources` is `invalid_target`. Leave them out to allow everything.
- A client that is not in the file is allowed everything, with the default claims. Without a file every
  client is.

The file is read once at startup, like the users file, and a bad one stops the service. A runnable
example is in [examples/](examples/docker-compose.yml).

### Where this differs from Rauthy

Deliberately more lenient, in the spirit of this service:

- the client secret is not checked; public, unknown and Basic-only clients are accepted;
- `flows` and `allowed_resources` allow everything when left out (Rauthy denies by default);
- the clients file may override reserved claims such as `sub` (Rauthy refuses them);
- the exchange copies the subject token's claims instead of rebuilding them from a user record;
- subject and actor tokens are checked for their signature and `exp` only, and a token without `exp` is
  accepted;
- refusals carry the RFC error codes (`unauthorized_client`, `invalid_scope`, `invalid_request`) and an
  `error_description`, where Rauthy answers `"BadRequest"` with a `message`. `invalid_grant` and
  `invalid_target` are the same on both;
- responses add `scope`, and the exchange's adds `issued_token_type`; tokens have no `nbf`, `jti` or `typ`.

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
