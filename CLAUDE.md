# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`fakeidp` is an OIDC-compatible **fake Identity Provider, for testing only**. It exists so that test suites and local development can obtain a JWT with whatever claims they need, signed by a key their code will accept.

### It is explicitly NOT SECURE, and does not need to be

This is not an oversight or a backlog item — it is the product:

- `POST /token` signs **any** JSON claim set it is handed, verbatim. No validation of `iss`, `aud`, `exp`, `sub`, or anything else. Callers can mint expired tokens, tokens for issuers that don't exist, tokens impersonating any subject.
- There is **no client authentication** — no client secret, no registered redirect URI check, no consent. `/auth` renders a login form that accepts any subject and name you type. The `client_credentials` and token-exchange grants take any `client_id` and ignore the secret.
- The signing key `keys/private_key.der` is **committed to this repository** and baked into the published Docker image. Every token it issues is forgeable by anyone.
- CORS is open to any origin, method, and header.

Consequences for how you work here:

- **Do not "harden" this service.** Adding claim validation, client-secret checks, redirect-URI allowlists, or key rotation would break the tool's purpose. If a change would make it harder to mint an arbitrary token, it is the wrong change.
- **Do not treat these as vulnerabilities.** Security scanners, `/security-review`, and dependency advisories will flag the permissive endpoints and the committed private key. Those findings are expected and by design; report them as such rather than fixing them. Genuine bugs — a panic, a broken signature, a dependency CVE affecting availability — are still worth fixing.
- Never deploy this anywhere reachable by production traffic, and never point a real system's OIDC config at it.

## Commands

```bash
cargo build                      # debug build -> ./target/debug/fakeidp
cargo build --release
cargo test --jobs 1 --all        # exactly what CI runs
cargo test test_route_create_token -- --nocapture   # single test

# CI gates on these two, so a warning fails the build:
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings

./.scripts/coverage.sh           # lcov.info + summary, via cargo-llvm-cov

./target/debug/fakeidp                                  # defaults: keys/private_key.der, 0.0.0.0:8080
./target/debug/fakeidp -p 9090 -e http://localhost:9090 # -e must match how clients reach the service
```

**Tests must run from the repo root.** Every test loads `./keys/private_key.der` by relative path.

`test/*.sh` are manual curl smoke tests that assume a container on port 9090 (see README). `.scripts/benchmark.sh` needs the `hey` load tool.

## Architecture

Single actix-web 4 binary. `main.rs` builds `AppState { rsa_key_pair, exposed_host }` plus an `Oidc` instance (from `actix-4-jwt-auth`) and wires one handler module per route:

| Route | Module | Notes |
|---|---|---|
| `GET /.well-known/openid-configuration`, `GET /keys` | `discovery.rs` | All URLs derived from `exposed_host` |
| `POST /token` | `token.rs`, `grants/` | Legacy signing shortcut plus the OAuth grants `authorization_code`, `client_credentials` and RFC 8693 token exchange — see below |
| `GET /auth`, `POST /auth/login` | `auth.rs` | Login form, code flow + implicit flow |
| `GET /userinfo` | `userinfo.rs` | Bearer-token protected |
| `GET /health` | `checks.rs` | Memory stats via `sysinfo` |
| `/static/*` | actix-files | Served from the `-f` folder |
| `/styling/*` | actix-files | Served from the `-s` folder, only when one is given |

`codes.rs` holds the in-memory authorization code store; `styling.rs` resolves the optional `-s`/`STYLING` folder (served at `/styling`) into the stylesheet link, logo URL and background attributes of the login page; `users.rs` loads the optional `-u`/`USERS` users file (or folder of `*.json`) into `AppState.users` at startup; `clients.rs` does the same for the optional `-c`/`CLIENTS` clients file into `AppState.clients` (claims, allowed flows and allowed resources per client of the machine-to-machine grants); `grants/` holds the form-encoded token endpoint, one module per grant plus the shared parsing, client checks and `aud` rule in `grants/mod.rs`; `errors.rs` is empty but still declared as a module.

### The two authorization flows

`GET /auth` renders the same login form for both; `response_type` decides what `POST /auth/login` does with it.

- **`response_type` containing `code`** — authorization code flow (RFC 6749 4.1) with optional PKCE (RFC 7636). The submitted claims are parked in the `AuthCodeStore` under a `nanoid` code, and the browser is redirected to `redirect_uri?code=...&state=...`. Tokens are minted later, at the exchange, so `iat`/`exp` are fresh. Hybrid response types are treated as plain code flow — there is no `c_hash`.
- **anything else** — implicit flow: tokens are minted immediately and returned in the redirect fragment.

Both paths converge on `token::issue_tokens`, which builds the access token and the matching id token (`at_hash`, `nonce`) from one claim set.

### `POST /token` serves two callers

Dispatch is on `Content-Type`, because the discovery document has only ever advertised one `token_endpoint`:

- `application/x-www-form-urlencoded` → OAuth token endpoint (`grants::handle`), dispatching on `grant_type`: `authorization_code`, `client_credentials`, or `urn:ietf:params:oauth:grant-type:token-exchange`. Returns a JSON token response, or a `{"error": ..., "error_description": ...}` body with 400. Grants return `Result<HttpResponse, Refusal>`; the `Refusal` becomes the error body at the top, which is what keeps clippy's `result_large_err` quiet.
- anything else → the original shortcut: sign this JSON claim set verbatim, return the JWT as `text/plain`.

Keep both working. The legacy path is what most of this repo's users actually call.

The two machine-to-machine grants follow Rauthy 0.36.1 (what Ampsflow runs in production) rather than the bare RFCs: `aud` is the client id plus the one `resource`/`audience` (string for one value, array for two), the exchange can only narrow `scope`, only `…:access_token` token types are accepted, `act` nests the *actor's* `act`. The deliberate leniencies are listed in the README under "Where this differs from Rauthy" and in [plans/client-credentials-and-token-exchange.md](plans/client-credentials-and-token-exchange.md); keep those lists in step with the code.

### Things that will bite you

- **The key id `"2020-01-29"` is hardcoded in two places** — the JWT header in [token.rs](src/token.rs) and the JWK in [discovery.rs](src/discovery.rs). They must stay identical or signature verification (and `/userinfo`) breaks.
- **`token::create_jwt` fills `RegisteredClaims` with all `None`** and stuffs the entire caller-supplied JSON into `private`. This is intentional: it lets callers emit any `iss`/`aud`/`exp` they like, including invalid ones. It also means biscuit does no claim validation on the way out.
- **`test_route_create_token` asserts a full literal JWT string.** Changing `keys/private_key.der`, the `kid`, the algorithm, or the JOSE header field order will fail it. Regenerate the expected token deliberately, don't loosen the assertion casually.
- **[template/login.html](template/login.html) is embedded with `include_str!` and rendered through `format!`** with named args (`{state}`, `{redirect_uri}`, `{nonce}`, `{client_id}`). Any literal `{` or `}` you add to that HTML must be doubled (`{{`/`}}`) or the build fails. Editing it requires a rebuild — it is not read from disk at runtime, unlike `static/`.
- **The styling folder is looked at on every `/auth` render** (a few `is_file` stats), unlike the users file, so files dropped into a mounted folder take effect without a restart. `styling::Branding` fills `{stylesheet}`, `{logo}`, `{body_class}` and `{body_style}` in login.html; without a folder they fall back to no extra CSS, `/static/logo.png` and a plain body. A configured folder that doesn't exist stops the service at startup.
- **[template/manual_login.html](template/manual_login.html) is inserted as a `format!` *value*** (the `{credentials}` slot), not used as a format string, so braces in it need no doubling. When `AppState.users` is non-empty, `auth::credentials` renders a user list in that slot instead, with the manual form folded into a `<details>` below it. Each user's Login button submits `user=<index>` and carries `formnovalidate`, because the manual `sub`/`name` inputs are `required` and would otherwise block it; `login` then replaces the claim set with that user's. `user` is one of the `PROTOCOL_FIELDS` so it never leaks into the token.
- **The users file is read once at startup and the service exits on a bad one** (not an array, an entry without a string `sub`). An empty folder or empty `USERS` falls back to the manual form. Encoded-JWT entries lose `iat`/`exp`/`nbf`/`auth_time`; claim-set entries are verbatim.
- **`exposed_host` is the discovery contract.** It is echoed as `issuer` and used to build every endpoint URL, and `auth::login` signs it as `iss`. If it doesn't match the URL clients actually use, token validation fails downstream.
- **`web::Data<AppState>` is built once in `main` and cloned into the workers.** The closure passed to `HttpServer::new` runs per worker thread, so constructing `AppState` inside it would give every worker its own authorization code store and a code issued by one worker would be unknown to the worker handling the exchange. Do not move it back inside.
- **The login form is parsed as `Vec<(String, String)>`, not a struct**, because the "add claim" rows have names that are not known at compile time. `auth::split_form` routes the nine `PROTOCOL_FIELDS` to protocol handling and treats everything else as a claim, so `sub` and `name` need no special case. The dynamic rows arrive as adjacent `claim_key`/`claim_value` pairs matched up **in submission order** — if you restructure [static/login.js](static/login.js), keep the two inputs adjacent and in that order.
- **Claims typed at the login screen override the defaults**, `iss`/`aud`/`exp` included. That is deliberate: minting a token the client should reject is a test case. `at_hash` and `nonce` are only filled in when the login form did not supply them.
- **Only a successful exchange consumes an authorization code** (`AuthCodeStore::get` vs `consume`). A rejected `code_verifier` deliberately leaves the code usable so a developer can fix their client and retry. Don't "fix" this into single-attempt semantics.
- **The token exchange is the only place a token is verified, on purpose.** `token::verify_jwt` checks the RS256 signature with the service's own key and `exp` (absent `exp` passes; a non-numeric one fails), nothing else — no `iss`, `aud`, `typ`, `nbf`. It exists because a backend's fallback when its IdP refuses an expired user token is a branch worth testing. It decodes the payload by hand: biscuit's `ClaimsSet` would move `exp` and the other registered claims out of the `Value`, so a hand-rolled `exp` check on the private part would silently pass expired tokens.
- **`scope` is both a protocol field and, since 1.2.0, an access-token claim.** `auth::split_form` keeps it out of the login claims, and `issue_tokens` then puts the granted scope into the access token only (not the id token), because the exchange reads it there to decide what scope an exchanged token may have. A `scope` typed as a claim at the login screen still wins.
- **The clients file never authenticates anyone.** A client not in it is allowed every grant and every resource; the file only adds claims and lets a test provoke `unauthorized_client`/`invalid_target`. Request-shape refusals (`invalid_request`, `invalid_scope`, both targets at once) apply with or without a file.
- `/auth` requires only `client_id`, `redirect_uri` and `response_type`; the rest are optional. A missing required one yields a deserialization error, not a friendly message.
- CORS is wide open (any origin/method/header) and JSON bodies are capped at 4096 bytes.

## Keys

DER-encoded RSA keypair, default `keys/private_key.der` (committed — it is a test key, treat it as public):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform der -out private_key.der
```

## Build & release

Multi-stage [Dockerfile](Dockerfile): `rust:1.98-slim-trixie` builds, `gcr.io/distroless/cc-debian13:nonroot` runs it as the image's own `nonroot` account (uid and gid 65532). The runtime image holds glibc, libgcc, ca-certificates, tzdata and nothing else: no shell, no package manager, no `whoami`. It scores zero at every severity in Docker Scout, where `debian:trixie-slim` carried findings Debian has no fix for and the full `rust:*-trixie` builder carried dozens. The container reads `FAKE_BIND`, `FAKE_PORT`, `EXPOSED_HOST`, `USERS`, `STYLING` and `CLIENTS` through clap's `env` support (the Dockerfile sets the first three to the defaults and the rest empty), and serves static files from `/usr/local/fakeidp/static`.

Constraints that are easy to break:

- **Keep the builder and runtime on the same Debian release.** The binary links glibc dynamically, so a builder on a different distro (or a CI convenience image like `cimg/rust`) yields something that builds fine and dies on startup. Distroless `*-debian13` is trixie; move both together.
- **The runtime image has no OpenSSL and no way to install one.** `reqwest` resolves to rustls and the unused `openssl` crate has been dropped from `Cargo.toml`, so `ldd` shows only libc/libm/libgcc and the distroless `cc` flavour suffices. If a change pulls in native-tls, the options are vendoring OpenSSL into the binary or going back to a Debian runtime with `libssl3` — and, for cross builds, the target arch's `libssl-dev` in the builder.
- **The builder cross-compiles; it never runs under emulation.** It is `FROM --platform=$BUILDPLATFORM` and, when `TARGETPLATFORM` differs, installs Debian's `gcc-<arch>-linux-gnu` + `libc6-dev-<arch>-cross` and builds `--target <triple>` (ring, aws-lc-sys and zstd-sys need the C cross compiler; the slim image has gcc and libc6-dev for the native case). Building arm64 under QEMU took ~58 min for the dependencies alone and ran `publish-docker-latest` into CircleCI's 1h job limit (pipeline 1202, job 1659); `no_output_timeout` does not extend that limit. The runtime stage only copies files, so nothing runs emulated any more. A new native C dependency must cross-compile, or it reintroduces the problem.
- **Do not `--chmod` the static directory.** `COPY --chmod` applies the mode to the directory too, and a static dir without its execute bit cannot be traversed, so `/static/*` 404s while everything else looks healthy. The same bites a *parent* directory `COPY` has to create: distroless has no `/usr/local/etc`, so copying the key there with `--chmod=440` produced a 0440 directory and `PermissionDenied` on the key. That is why the builder lays the key out with `install` under `/out/etc` and the runtime copies the directory.
- **The binary and key stay root-owned**, mode 0755 and 0440 (`root:nonroot`). The service can read them and cannot rewrite them. Chowning the binary *to* the runtime user, as an earlier revision did, lets the process overwrite its own executable. `--chown` names are resolved against the distroless image's `/etc/passwd` and `/etc/group`, so `nonroot` works and `runtme` would not.
- **There is no shell in the runtime image.** `CMD` is exec form, so the binary is PID 1 and gets SIGTERM directly (`docker stop` in ~0.4s). Nothing the service runs at startup may shell out: the `whoami` in the banner is best-effort for exactly this reason. To look inside the image use `docker create` + `docker export | tar -tvf -`, not `docker run ... sh`.
- [.dockerignore](.dockerignore) keeps the 1.5G host `target/` out of the context; without it `COPY . .` drops foreign-architecture artifacts on top of the container's build dir.

CircleCI ([.circleci/config.yml](.circleci/config.yml)), project `gh/dlectron/fakeidp` — pipelines at https://app.circleci.com/pipelines/gh/dlectron/fakeidp. Job details and step logs of this public project can be fetched without auth from `https://circleci.com/api/v1.1/project/gh/dlectron/fakeidp/<buildNumber>` (each step action's `output_url`). Jobs: every branch runs `build` (fmt, clippy, build, test, coverage) and `docker-build` (native-platform image + smoke test) in parallel. `main` pushes `spectare/fakeidp:latest`; a git tag pushes `spectare/fakeidp:$TAG` — both multi-arch (amd64 + arm64) via buildx. The publish jobs run `git describe --tags --exact-match`, so a release tag must point at the built commit.

`docker-build` exists because the publish jobs only run on `main` and tags, which used to make a release the first thing to exercise the Dockerfile. Its smoke test starts the container and talks to it from a `curlimages/curl` sidecar on the container's network namespace, because the image has no shell to inspect files with and the remote docker host's ports are not reachable from the job. Startup proves the builder and runtime agree on glibc and that the key is readable; `/static/login.js` proves the static dir is traversable; `docker top` proves the uid.

Rust version is pinned in two places that must move together: the CircleCI image (`cimg/rust:1.98.0`) and the Dockerfile builder (`rust:1.98-slim-trixie`). Testing on one release and shipping a binary built by another hides breakage from CI.
