# Client credentials and token exchange

Status: accepted 2026-11-04, to be implemented · owner: Olger · target release: 1.2.0 · consumer: Ampsflow
(`ev-operations/plans/hpc-platform-backlog.md`, issues 2 and 7).

## Why

Ampsflow's production IdP is Rauthy. From v0.36.1 Rauthy offers what Ampsflow's backend needs for calls made without
a person present:
- `client_credentials`: a confidential client gets a token as itself (the integration identity);
- RFC 8693 token exchange (`urn:ietf:params:oauth:grant-type:token-exchange`): that client swaps a user's access
  token for one meant for a single service, naming the user (`sub`) and, with an actor token, the acting party
  (`act`).

Ampsflow's local stacks run this fake IdP, not Rauthy. Today `POST /token` (form-encoded) knows only
`authorization_code` (`token.rs`, `exchange_code`: anything else is `unsupported_grant_type`), and discovery advertises
`authorization_code` and `implicit`. So the local stack cannot exercise either grant. This plan adds both, in the
fake IdP's own spirit: any client, any secret, tokens with whatever claims the test needs.

**Fidelity rule.** The shape of the issued tokens and the refusals follow Rauthy v0.36.1, checked against its source
(`src/service/src/oidc/grant_types/{client_credentials,token_exchange}.rs`, `src/service/src/token_set.rs`; v0.37.2
behaves the same). That is the behaviour Ampsflow's backend meets in production. Where the fake IdP is deliberately
more lenient, the plan says so, and the list is collected in "Deliberate differences from Rauthy" below. Error
bodies use the RFC codes, not Rauthy's.

## What stays as it is

- The legacy path: a non-form body to `/token` is signed verbatim, as text.
- The authorization code flow and its behaviour (a failed exchange leaves the code usable), with one addition
  below: the access token gains a `scope` claim.
- No real client authentication. A client secret is read and ignored. This is not a hardening change. CLAUDE.md's
  rule holds: nothing here makes it harder to mint an arbitrary token, because the legacy path still signs anything.
- RS256 and the hardcoded key id `2020-01-29`.

## What changes in the existing flows

**The access token of the code and implicit flows carries the granted `scope`.** Today `scope` is one of the nine
`PROTOCOL_FIELDS` in `auth.rs`: it is kept in `AuthCode.scope` and echoed in the token response, but never put in
the token. Rauthy's access tokens carry `scope` (`JwtCommonClaims.scope`), and §4's scope narrowing reads it, so
without this a login-screen token would allow no requested scope on an exchange. The change:
- `issue_tokens` takes the scope (`Option<&str>`) and inserts it into the access token after the `base` clone, so
  the id token stays as it is;
- a `scope` typed as a claim at the login screen still wins, like every other claim;
- `test_pkce_code_exchange` asserts the access token's `scope` is `openid profile`.
`test_route_create_token` is unaffected: the legacy path does not use `issue_tokens`.

## 1. A clients file (`-c/--clients`, env `CLIENTS`)

The same shape and loading rules as the users file (`users.rs`): a JSON file, or a folder of `*.json` files read in
file-name order, read once at startup. A bad file stops the service. No option means no clients file: every client
is accepted with defaults.

```json
[
  {
    "client_id": "ampsflow-integration",
    "claims": { "name": "Ampsflow integration", "scope": "openid" },
    "flows": ["client_credentials", "token_exchange"],
    "allowed_resources": ["http://localhost:8083", "http://localhost:8084"]
  },
  { "client_id": "no-exchange", "flows": ["client_credentials"] }
]
```

- `client_id` is required.
- `claims` are put in every client-credentials token of that client, verbatim; they override the defaults below.
  This is Rauthy's per-client custom claims with `claims_at_root` on.
  - Rauthy refuses custom claims that collide with reserved ones (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`,
    …), so a Rauthy client-credentials token's `sub` is always the client id.
  - The fake IdP still lets the file override them, because minting a token the client should reject is a test case.
    Leave them out to stay close to Rauthy.
- `flows` and `allowed_resources` are optional. When they are left out, everything is allowed. They exist so a test
  can provoke the refusals Rauthy gives: an exchange by a client without `token_exchange`, or for a resource not on
  its list. The file is the only source of refusals *about the client*. Refusals about the request's shape and
  about the subject token (§2, §4) follow Rauthy and apply with or without a file.
- An unknown `client_id` (not in the file) is allowed everything, with default claims.

New module `clients.rs` (loader plus a `find(client_id)` lookup), `AppState.clients`, the clap option in `main.rs`,
and the env var in the Dockerfile's documented set (`ENV CLIENTS=""`).

- An empty `CLIENTS` counts as not given, as `USERS` and `STYLING` do in `main.rs`. Without that, the Dockerfile's
  empty default would try to load the path `""`.
- The file-or-folder walk (`users::json_files`, private today) moves to a small shared helper used by both loaders,
  rather than being copied.

## 2. The token endpoint, shared by both grants

**The client.**
- `client_id` comes from HTTP Basic (`client_secret_basic`) or from the form (`client_secret_post`, or a public
  client's plain `client_id`). The secret is not checked.
- Basic credentials are URL-encoded before base64 (RFC 6749 §2.3.1), so `client_id` is percent-decoded after the
  base64 decode.
- When both are given and differ, the answer is `invalid_request`. As with `redirect_uri` in `exchange_code`, a
  mismatch means the client is misconfigured; it is not an edge case being tested.
- `create_token` hands the request headers to the form handler. Today it passes only the body.
- Discovery already lists `client_secret_basic`, `client_secret_post` and `none` as auth methods. It stays so.

**The target.** As in Rauthy, a request names at most one target:
- client credentials reads `resource` only, and ignores `audience`;
- the exchange takes `resource` or `audience`; both at once is `invalid_target`;
- a parameter given more than once is `invalid_request`. The form keeps being parsed as `Vec<(String, String)>` so
  the duplicate can be seen;
- when the client is in the file with `allowed_resources`, the target must be on that list, otherwise
  `invalid_target`.

**`aud`.** As in Rauthy (RFC 8707): the `client_id`, plus the target when there is one and it differs.
- One value gives a string, two give an array.
- So `resource=http://localhost:8083` gives `["ampsflow-integration", "http://localhost:8083"]`, and no target gives
  `"ampsflow-integration"`.

**Errors.** RFC 6749 §5.2 / RFC 8693 / RFC 8707 bodies: `{"error": ..., "error_description": ...}` with status 400,
via the existing `oauth_error`. Where Rauthy answers with its generic `"BadRequest"`, the fake IdP uses the RFC code
that fits:

| Situation | Rauthy 0.36.1 `error` | fake IdP `error` |
|---|---|---|
| client's `flows` lacks the grant | `BadRequest` | `unauthorized_client` |
| target not allowed, or both `resource` and `audience` | `invalid_target` | `invalid_target` |
| subject or actor token invalid or expired | `invalid_grant` | `invalid_grant` |
| requested `scope` wider than the subject token's | `BadRequest` | `invalid_scope` |
| wrong or missing `*_token_type`, missing `subject_token`, unsupported `requested_token_type` | `BadRequest` | `invalid_request` |

**Response.** `Cache-Control: no-store` as for the code exchange, never an `id_token` or a `refresh_token`.

## 3. `grant_type=client_credentials`

Request: `client_id` (Basic or form), optional `resource` (RFC 8707). A `scope` parameter is ignored, as in Rauthy,
where the token gets the client's default scopes. Put a `scope` in the client's `claims` for a token that needs one.

Token claims, defaults first, then the client's `claims` from the file win:

| Claim | Value |
|---|---|
| `iss` | `exposed_host` |
| `sub` | the `client_id`, as Rauthy with `client_credentials_map_sub = true` |
| `aud` | see §2 |
| `azp` | the `client_id`, as in Rauthy's `JwtCommonClaims`. No `client_id` claim: Rauthy has none |
| `iat`, `exp` | now, now + `TOKEN_TTL_SECS`. Rauthy also sets `nbf`, `jti` and `typ: "Bearer"`; the fake IdP does not, as none of its tokens do |

Response: `access_token`, `token_type: Bearer`, `expires_in`, and `scope` when the token has one.
- Rauthy sends no `scope`; the extra field is harmless, but Ampsflow must not depend on it.
- No `id_token` (there is no user) and no `refresh_token` (RFC 6749 §4.4.3).

Refused (`unauthorized_client`) only when the client is in the file and its `flows` lacks `client_credentials`; and
(`invalid_target`) when the `resource` is not in its `allowed_resources`.

## 4. `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`

Request (RFC 8693 §2.1), with Rauthy's restrictions:
- `subject_token` and `subject_token_type` are both required. The only accepted type is
  `urn:ietf:params:oauth:token-type:access_token`; `…:jwt`, `…:id_token` and anything else are `invalid_request`.
- `actor_token` is optional. When it is given, `actor_token_type` is required, with the same single accepted type.
- `requested_token_type`: only `…:access_token`, or omitted.
- `resource` or `audience` (§2), and `scope`.

**Checking the subject and actor tokens.** Each must be a JWT signed with this IdP's own key and not expired;
otherwise the answer is `invalid_grant`.
- This is the one place the fake IdP checks a token. Ampsflow's token registry falls back to the integration
  identity exactly when Rauthy refuses an expired user token, so the local stack must refuse it too, or that branch
  is never tested.
- It does not make minting harder: an expired or foreign-looking token can still be had from the legacy path or the
  login screen.
- An `exp` that is present but not a number is `invalid_grant`.
- Rauthy checks more: `nbf`, an `iat` not in the future, `typ == "Bearer"`, `iss` equal to its own issuer, and
  revocation; a token without `exp` fails to parse. The fake IdP checks none of these, on purpose.
  - Its own tokens carry no `typ`, so requiring one would refuse them.
  - A token without `exp` counts as not expired: the legacy path mints many such tokens, and refusing them would make
    that path useless as a source of subject tokens.

**Scope.** As in Rauthy, the exchange can only narrow:
- every space-separated value of the requested `scope` must be in the subject token's `scope`, otherwise
  `invalid_scope`. A subject token without `scope` therefore allows no requested scope;
- without a requested `scope`, the subject token's `scope` is kept.

**The issued token.**

| Claim | Value |
|---|---|
| everything of the subject token | copied, except `iat`, `exp`, `nbf`, `aud`, `at_hash`, `nonce`, `jti`, `azp`, `act`, `scope` |
| `iss` | `exposed_host` |
| `aud` | see §2, with the exchanging `client_id` |
| `azp` | the exchanging `client_id` |
| `iat` / `exp` | now / now + `TOKEN_TTL_SECS`. Not capped at the subject token's `exp`: Rauthy gives the exchanging client's normal access-token lifetime |
| `act` | with an actor token: `{ "sub": <actor's sub> }`, and when the *actor* token has an `act`, that one nested inside: `{ "sub": <actor>, "act": <actor's act> }`. Without an actor token (impersonation): no `act`. An actor token without `sub` is `invalid_grant` |
| `scope` | as above, left out when empty |

Copying the subject token's claims differs from Rauthy on purpose. Rauthy rebuilds the token from its user record
(found by `sub`): `roles` always, `email`/`email_verified` and `groups` only when the scope holds `email` or
`groups`, and custom attributes per scope. The fake IdP has no user record, and the subject token is the closest
stand-in for one. The test decides what the user looks like by what it puts in the subject token.

Response (RFC 8693 §2.2.1): `access_token`, `issued_token_type: urn:ietf:params:oauth:token-type:access_token`,
`token_type: Bearer`, `expires_in`, and `scope` when the token has one. Never a `refresh_token`, as in Rauthy.
- Rauthy 0.36.1 sends only `access_token`, `token_type` and `expires_in`.
- `issued_token_type` is required by the RFC, so the fake IdP sends it; Ampsflow must not depend on it, nor on
  `scope`.

Refused (`unauthorized_client`) only when the client is in the file without `token_exchange` in its `flows`;
(`invalid_target`) as in §2. Rauthy accepts only confidential clients. The fake IdP has no notion of confidential,
so a public `client_id` is accepted. Use the file to refuse it.

`may_act` is not supported, as in Rauthy 0.36.1.

## 5. Discovery

`grant_types_supported` becomes `authorization_code`, `implicit`, `client_credentials` and
`urn:ietf:params:oauth:grant-type:token-exchange`. The error for an unknown grant names all three token-endpoint
grants.

## 6. Code layout

- `token.rs` keeps the dispatch on content type, `issue_tokens`, `create_jwt` and `oauth_error`. The
  `grant_type` match moves to a small dispatcher.
- `grants/authorization_code.rs` (today's `exchange_code`, unchanged), `grants/client_credentials.rs` and
  `grants/token_exchange.rs`. `oauth_error`, `issue_tokens` and `create_jwt` in `token.rs` become `pub(crate)` for
  them.
- `clients.rs` for the file.
- Token verification for the exchange: check the RS256 signature over `header.payload` with `rsa_key_pair`
  (biscuit's `SignatureAlgorithm::RS256.verify` accepts the key pair directly). Then base64url-decode the payload
  into a `Map` yourself, as the `decode_claims` test helper does, and compare `exp` with `now_secs()` by hand.
- Do **not** decode into biscuit's `ClaimsSet<Value>`. `create_jwt` puts every claim in `private` when encoding, but
  on decoding serde's flatten fills `registered` first. `iss`/`sub`/`aud`/`exp`/`nbf`/`iat`/`jti` would then be
  missing from the `Value`, so an expired token would pass. A non-integer `exp`, which the legacy path will sign,
  would also fail to decode at all. Reading the raw payload also keeps every claim exactly as it was for the copy.

## 7. Tests

Unit tests next to each grant, in the style of the existing `token.rs` tests (`token_request`, decode and assert
claims):
- *client credentials:*
  - `sub` defaults to the `client_id`; file claims override; no `id_token`;
  - `aud` is the `client_id` alone without `resource`, and `[client_id, resource]` with one;
  - a requested `scope` is ignored; `audience` is ignored;
  - Basic and post both work; a Basic `client_id` that differs from the form's is `invalid_request`;
  - a repeated `resource` is `invalid_request`;
  - a file client without the flow is `unauthorized_client`; a `resource` outside `allowed_resources` is
    `invalid_target`.
- *exchange:*
  - `sub` and the user claims are kept; `aud` is `[client_id, resource]`;
  - `act` is set with an actor token, nested when the actor token had one, absent without an actor token;
  - `exp` is now + `TOKEN_TTL_SECS` even when the subject token expires sooner; a subject token without `exp` is
    accepted;
  - the subject token's `scope` is kept when none is requested; a narrower request narrows it; a wider one is
    `invalid_scope`; a subject token without `scope` allows no requested scope;
  - a token minted by the code flow can be exchanged with `scope=openid`, which is what the `scope` claim above is
    for;
  - an expired subject token, a malformed one, one with a non-numeric `exp`, one with a tampered signature, and an
    actor token without `sub` are `invalid_grant`. One changed byte of the signature stands in for "signed with
    another key", because ring cannot generate RSA keys and a second key fixture is not worth committing;
  - `subject_token_type=…:jwt`, an `actor_token` without `actor_token_type`, and an unsupported
    `requested_token_type` are `invalid_request`;
  - `resource` and `audience` together are `invalid_target`;
  - the response carries `issued_token_type` and no `refresh_token`;
  - file refusals give `unauthorized_client` and `invalid_target`.
- *discovery:* the new grants are listed.
- `test_route_create_token` (the literal JWT) is untouched: the legacy path does not change.
- `test_unsupported_grant_type` uses `grant_type=client_credentials` as its unsupported example today. It moves to
  `grant_type=password`.
- `test_pkce_code_exchange` gains the `scope` claim assertion (see "What changes in the existing flows").
- Smoke tests `test/client_credentials.sh` and `test/token_exchange.sh` (curl against a container on 9090). The
  `docker-build` job's smoke test stays as it is.

CI as today: `cargo fmt --check`, `clippy -D warnings`, `cargo test --jobs 1 --all`.

## 8. Docs and release

- README: a section per grant with a curl example, and the clients file next to the users file. It lists the
  deliberate differences from Rauthy below.
- `examples/clients/clients.json` and the example compose mounting it.
- CLAUDE.md:
  - add `/token`'s new grants to the route table;
  - add `clients.rs` to the module list, and `CLIENTS` next to `USERS`/`STYLING` in the Dockerfile paragraph;
  - add one bullet to "Things that will bite you": the exchange is the only place a token is verified, on purpose;
  - note that `scope` is both a protocol field and, from 1.2.0, a claim of the access token.
- Version 1.2.0 in `Cargo.toml`, tag `1.2.0` on the built commit. CircleCI publishes `spectare/fakeidp:1.2.0`.

## 9. On the Ampsflow side (not this repository)

- `runtime/fakeidp/clients/clients.json` and `ev-models/fakeidp/clients/clients.json` with the integration client
  (both flows, the two registries as resources). This replaces the "fake-IdP *user* `integration`" of backlog
  issue 2: a client identity comes from the clients file, not the login screen.
- **The integration identity's `sub` is the client id.** On Rauthy it cannot be anything else (custom claims may not
  set `sub`). Either name the client `integration`, or have Ampsflow expect `ampsflow-integration`. Do not set `sub`
  in the clients file, or the local stack hides the mismatch.
- The composes set `CLIENTS=/usr/local/etc/fakeidp/clients`, mount the folder, and pin `FAKEIDP_VERSION=1.2.0`.
- Rauthy configuration this plan assumes:
  - `CLIENT_CREDENTIALS_MAP_SUB=true`. Its default in code is `false`, and without it a client-credentials token has
    no `sub`;
  - `claims_at_root` on the integration client, or its custom claims land under `custom` instead of at the root;
  - `client_credentials` and the token-exchange URN in the client's enabled flows, and the registries in its
    `allowed_resources` (Rauthy denies both by default);
  - a confidential client.
- **Send the client secret in the form body (`client_secret_post`).** Rauthy 0.36.1's client-credentials handler
  checks for a body `client_secret` before it reads the Basic header, so a Basic-only request fails with
  `'client_secret' is missing`. The token exchange accepts both. The fake IdP accepts Basic for both, so it will not
  catch this.
- Branch on the `error` values `invalid_grant` and `invalid_target` only. Those are the same on both IdPs. Every
  other Rauthy refusal is `"BadRequest"` with a `message`, where the fake IdP gives an RFC code and
  `error_description`.
- The registries' audience check stays out for now (backlog issue 7). When it comes, it must accept an array `aud`
  that also holds the integration client's id.

## Deliberate differences from Rauthy

The fake IdP is more lenient than Rauthy 0.36.1 in these places, and only these:
- the client secret is not checked; public, unknown and Basic-only clients are accepted;
- `flows` and `allowed_resources` allow everything when left out (Rauthy denies by default);
- client claims may override reserved claims such as `sub` (Rauthy refuses them);
- the exchange copies the subject token's claims instead of rebuilding them from a user record;
- subject and actor tokens are checked for signature and `exp` only, and a token without `exp` is accepted;
- refusals carry RFC error codes and `error_description`, not Rauthy's `"BadRequest"` and `message`;
- responses add `scope`, and the exchange's adds `issued_token_type`;
- tokens have no `nbf`, `jti` or `typ` claim.
