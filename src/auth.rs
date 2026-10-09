use crate::codes::{now_secs, AuthCode, CODE_TTL_SECS};
use crate::AppState;
use actix_web::http::StatusCode;
use actix_web::{web, Error, HttpResponse};
use serde_derive::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;

/// Login form fields that carry protocol state rather than a claim.
const PROTOCOL_FIELDS: [&str; 9] = [
    "response_type",
    "client_id",
    "redirect_uri",
    "state",
    "nonce",
    "scope",
    "code_challenge",
    "code_challenge_method",
    // Index into the users file, sent by the login button next to a listed user.
    "user",
];

/// Authorization request (RFC 6749 section 4.1.1 plus RFC 7636 section 4.3).
///
/// Only `client_id`, `redirect_uri` and `response_type` are required; a test IdP
/// that refuses to render a login screen over a missing `nonce` is not useful.
#[derive(Deserialize)]
pub struct AuthParameters {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

pub async fn auth(
    app_state: web::Data<AppState>,
    info: web::Query<AuthParameters>,
) -> Result<HttpResponse, Error> {
    let flow = if wants_code(&info.response_type) {
        match &info.code_challenge {
            Some(_) => "Authorization code + PKCE",
            None => "Authorization code",
        }
    } else {
        "Implicit"
    };

    let branding = app_state.styling.branding();
    let body = format!(
        include_str!("../template/login.html"),
        stylesheet = branding.stylesheet,
        logo = branding.logo,
        body_class = branding.body_class,
        body_style = branding.body_style,
        flow = flow,
        client_id = escape_attribute(&info.client_id),
        redirect_uri = escape_attribute(&info.redirect_uri),
        response_type = escape_attribute(&info.response_type),
        scope = escape_attribute(info.scope.as_deref().unwrap_or_default()),
        state = escape_attribute(info.state.as_deref().unwrap_or_default()),
        nonce = escape_attribute(info.nonce.as_deref().unwrap_or_default()),
        code_challenge = escape_attribute(info.code_challenge.as_deref().unwrap_or_default()),
        code_challenge_method =
            escape_attribute(info.code_challenge_method.as_deref().unwrap_or_default()),
        credentials = credentials(&app_state.users),
    );
    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(body))
}

/// Handle the login form for both flows.
///
/// The form is parsed as an ordered list of pairs rather than a struct so that
/// the "add claim" rows, whose names are not known at compile time, come through.
pub async fn login(
    app_state: web::Data<AppState>,
    form: web::Form<Vec<(String, String)>>,
) -> Result<HttpResponse, Error> {
    let (fields, mut claims) = split_form(form.into_inner());

    // A listed user was picked: their claim set replaces anything typed.
    if let Some(index) = fields.get("user") {
        match index
            .parse::<usize>()
            .ok()
            .and_then(|i| app_state.users.get(i))
        {
            Some(user) => claims = user.clone(),
            None => return Ok(HttpResponse::BadRequest().body("Unknown user on the login form")),
        }
    }

    let client_id = fields.get("client_id").cloned().unwrap_or_default();
    let redirect_uri = match fields.get("redirect_uri") {
        Some(uri) if !uri.is_empty() => uri.clone(),
        _ => {
            return Ok(HttpResponse::BadRequest().body("Login form is missing a redirect_uri"));
        }
    };
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if subject.is_empty() {
        return Ok(HttpResponse::BadRequest().body("A sub(ject) is required to build a token"));
    }

    let state = fields.get("state").cloned().unwrap_or_default();
    let nonce = fields.get("nonce").filter(|n| !n.is_empty()).cloned();
    let scope = fields.get("scope").filter(|s| !s.is_empty()).cloned();
    let response_type = fields.get("response_type").cloned().unwrap_or_default();

    if wants_code(&response_type) {
        // Authorization code flow: park everything and hand back a code.
        let code = nanoid::nanoid!(32);
        app_state.auth_codes.insert(
            code.clone(),
            AuthCode {
                client_id,
                redirect_uri: redirect_uri.clone(),
                nonce,
                scope,
                code_challenge: fields
                    .get("code_challenge")
                    .filter(|c| !c.is_empty())
                    .cloned(),
                code_challenge_method: fields
                    .get("code_challenge_method")
                    .filter(|m| !m.is_empty())
                    .cloned()
                    .unwrap_or_else(|| "plain".to_string()),
                claims,
                expires_at: now_secs() + CODE_TTL_SECS,
            },
        );

        return Ok(redirect_to(&append_query(
            &redirect_uri,
            &[("code", code), ("state", state)],
        )));
    }

    // Implicit flow: the tokens themselves travel back in the fragment.
    let tokens = crate::token::issue_tokens(
        &app_state.rsa_key_pair,
        &app_state.exposed_host,
        &client_id,
        &claims,
        nonce.as_deref(),
    );

    Ok(redirect_to(&append_fragment(
        &redirect_uri,
        &[
            ("access_token", tokens.access_token),
            ("expires_in", tokens.expires_in.to_string()),
            ("id_token", tokens.id_token),
            ("state", state),
            ("token_type", "bearer".to_string()),
        ],
    )))
}

/// The part of the login form that says who logs in: the manual subject/name/claims
/// inputs, or, when a users file was given, one row per user with its own login
/// button and the manual inputs folded away below the list. The button submits the
/// user's index; the claims stay server side.
fn credentials(users: &[Map<String, Value>]) -> String {
    let manual = include_str!("../template/manual_login.html");
    if users.is_empty() {
        return manual.to_string();
    }

    let rows: String = users
        .iter()
        .enumerate()
        .map(|(index, user)| {
            let text = |claim: &str| match user.get(claim) {
                Some(Value::String(value)) => escape_attribute(value),
                Some(other) => escape_attribute(&other.to_string()),
                None => String::new(),
            };
            let others: Map<String, Value> = user
                .iter()
                .filter(|(claim, _)| *claim != "sub" && *claim != "name")
                .map(|(claim, value)| (claim.clone(), value.clone()))
                .collect();
            let details = if others.is_empty() {
                String::new()
            } else {
                format!(
                    r#"<details class="idp-user-claims"><summary>{count} more claims</summary><pre>{claims}</pre></details>"#,
                    count = others.len(),
                    claims = escape_attribute(
                        &serde_json::to_string_pretty(&others).unwrap_or_default()
                    ),
                )
            };
            format!(
                r#"            <li class="idp-user">
                <div class="idp-user-row">
                    <div class="idp-user-id">
                        <div class="idp-user-name">{name}</div>
                        <div class="idp-subtle-text">{sub}</div>
                    </div>
                    <button type="submit" name="user" value="{index}" formnovalidate class="idp-btn theme-btn--primary idp-user-login">Login</button>
                </div>
                {details}
            </li>
"#,
                name = text("name"),
                sub = text("sub"),
            )
        })
        .collect();
    // The manual inputs are `required`, which is why the user buttons carry
    // `formnovalidate`: they submit the same form while those are still empty.
    // `user` is only sent by the button that was clicked, so the manual Login
    // button below goes down the typed-claims path as usual.
    format!(
        "<ul class=\"idp-users\">\n{}</ul>\n<details class=\"idp-manual\">\n<summary>Log in as someone else</summary>\n{}</details>\n",
        rows,
        manual.replace(" autofocus", "")
    )
}

/// `code` anywhere in the response type means the client wants an authorization
/// code back. Hybrid response types are treated as plain code flow.
fn wants_code(response_type: &str) -> bool {
    response_type
        .split_whitespace()
        .any(|token| token == "code")
}

/// Split the submitted form into protocol fields and the claim set to sign.
///
/// Anything that is not a protocol field becomes a claim, so the fixed `sub` and
/// `name` inputs need no special casing. The "add claim" rows arrive as adjacent
/// `claim_key`/`claim_value` pairs and are matched up in submission order.
fn split_form(pairs: Vec<(String, String)>) -> (HashMap<String, String>, Map<String, Value>) {
    let mut fields = HashMap::new();
    let mut claims = Map::new();
    let mut pending_key: Option<String> = None;

    for (key, value) in pairs {
        match key.as_str() {
            "claim_key" => pending_key = Some(value),
            "claim_value" => {
                if let Some(name) = pending_key.take() {
                    let name = name.trim();
                    if !name.is_empty() {
                        claims.insert(name.to_string(), parse_claim_value(&value));
                    }
                }
            }
            name if PROTOCOL_FIELDS.contains(&name) => {
                fields.insert(key, value);
            }
            _ => {
                claims.insert(key, Value::String(value));
            }
        }
    }
    (fields, claims)
}

/// Claim values are typed as text but a claim set is JSON, so anything that
/// parses as JSON is used as-is. That is what makes `true`, `1735689600` and
/// `["admin","user"]` reachable from a text input; everything else stays a string.
fn parse_claim_value(value: &str) -> Value {
    serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()))
}

fn redirect_to(location: &str) -> HttpResponse {
    HttpResponse::build(StatusCode::SEE_OTHER)
        .insert_header(("Location", location))
        .finish()
}

fn append_query(redirect_uri: &str, params: &[(&str, String)]) -> String {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    format!("{}{}{}", redirect_uri, separator, encode_params(params))
}

fn append_fragment(redirect_uri: &str, params: &[(&str, String)]) -> String {
    let separator = if redirect_uri.contains('#') { '&' } else { '#' };
    format!("{}{}{}", redirect_uri, separator, encode_params(params))
}

/// Percent-encode the response parameters, skipping the empty ones so a client
/// that sent no `state` does not get an empty one back.
fn encode_params(params: &[(&str, String)]) -> String {
    let present: Vec<&(&str, String)> = params
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .collect();
    serde_urlencoded::to_string(present).unwrap_or_default()
}

/// Values from the query string end up inside HTML attributes on the login form.
/// Escaping them keeps a quote in a `state` or `redirect_uri` from tearing the
/// form apart (and taking the redirect with it).
fn escape_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http, test, App};
    use biscuit::jws::Secret;
    use serde_json::json;

    fn test_state() -> web::Data<AppState> {
        let rsa_keys = Secret::rsa_keypair_from_file("./keys/private_key.der")
            .expect("Cannot read RSA keypair");
        web::Data::new(AppState::new(rsa_keys, "http://localhost:8080".to_string()))
    }

    fn location(resp: &actix_web::dev::ServiceResponse) -> &str {
        resp.headers()
            .get("Location")
            .expect("no Location header")
            .to_str()
            .unwrap()
    }

    #[actix_rt::test]
    async fn test_auth_renders_login_form_with_pkce_parameters() -> Result<(), Error> {
        let app = test::init_service(
            App::new()
                .app_data(test_state())
                .service(web::resource("/auth").route(web::get().to(auth))),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(
                "/auth?client_id=test-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb\
                  &response_type=code&scope=openid&state=xyz&nonce=n-0S6\
                  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
                  &code_challenge_method=S256",
            )
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let body = test::read_body(resp).await;
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(html.contains(r#"name="code_challenge_method" value="S256""#));
        assert!(html.contains(r#"name="response_type" value="code""#));
        assert!(html.contains("Authorization code + PKCE"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_auth_without_optional_parameters() -> Result<(), Error> {
        let app = test::init_service(
            App::new()
                .app_data(test_state())
                .service(web::resource("/auth").route(web::get().to(auth))),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/auth?client_id=c&redirect_uri=http%3A%2F%2Flocalhost&response_type=code")
            .to_request();

        assert_eq!(
            test::call_service(&app, req).await.status(),
            http::StatusCode::OK
        );
        Ok(())
    }

    #[actix_rt::test]
    async fn test_auth_applies_the_styling_folder() -> Result<(), Error> {
        let rsa_keys = Secret::rsa_keypair_from_file("./keys/private_key.der")
            .expect("Cannot read RSA keypair");
        let folder =
            std::env::temp_dir().join(format!("fakeidp-auth-styling-{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("custom.css"), "").unwrap();
        std::fs::write(folder.join("logo.svg"), "").unwrap();
        std::fs::write(folder.join("background.png"), "").unwrap();
        let state = web::Data::new(
            AppState::new(rsa_keys, "http://localhost:8080".to_string())
                .with_styling(crate::styling::Styling::new(Some(folder.clone()))),
        );
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::resource("/auth").route(web::get().to(auth))),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/auth?client_id=c&redirect_uri=http%3A%2F%2Flocalhost&response_type=code")
            .to_request();
        let body = test::read_body(test::call_service(&app, req).await).await;
        let html = std::str::from_utf8(&body).unwrap();
        std::fs::remove_dir_all(folder).unwrap();

        assert!(html.contains(r#"<link href="/styling/custom.css" rel="stylesheet">"#));
        assert!(html.contains(r#"src="/styling/logo.svg""#));
        assert!(html.contains(
            r#"<body class="theme-body theme-body--image" style="background-image: url('/styling/background.png')">"#
        ));
        Ok(())
    }

    fn users_state() -> web::Data<AppState> {
        let rsa_keys = Secret::rsa_keypair_from_file("./keys/private_key.der")
            .expect("Cannot read RSA keypair");
        let users = vec![
            json!({"sub": "alice-1", "name": "Alice <Admin>", "groups": ["admin"]}),
            json!({"sub": "bob-2", "name": "Bob"}),
        ]
        .into_iter()
        .map(|user| user.as_object().unwrap().clone())
        .collect();
        web::Data::new(
            AppState::new(rsa_keys, "http://localhost:8080".to_string()).with_users(users),
        )
    }

    #[actix_rt::test]
    async fn test_auth_lists_users_instead_of_manual_form() -> Result<(), Error> {
        let app = test::init_service(
            App::new()
                .app_data(users_state())
                .service(web::resource("/auth").route(web::get().to(auth))),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/auth?client_id=c&redirect_uri=http%3A%2F%2Flocalhost&response_type=code")
            .to_request();
        let body = test::read_body(test::call_service(&app, req).await).await;
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("Alice &lt;Admin&gt;"));
        assert!(html.contains("alice-1"));
        assert!(html.contains(r#"name="user" value="1""#));
        // Only Alice has claims beyond sub and name to fold away; the other
        // details element holds the manual form.
        assert_eq!(
            html.matches(r#"<details class="idp-user-claims""#).count(),
            1
        );
        assert!(html.contains(r#"<details class="idp-manual">"#));
        assert!(html.contains(r#"id="sub""#));
        assert!(html.contains("formnovalidate"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_login_as_listed_user_uses_their_claims() -> Result<(), Error> {
        let state = users_state();
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/auth/login").route(web::post().to(login))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/auth/login")
            .set_form(vec![
                ("response_type", "code"),
                ("client_id", "test-client"),
                ("redirect_uri", "http://localhost:3000/cb"),
                ("user", "0"),
            ])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::SEE_OTHER);

        let code = location(&resp)
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string();
        let stored = state.auth_codes.get(&code).expect("code was not stored");
        assert_eq!(stored.claims["sub"], json!("alice-1"));
        assert_eq!(stored.claims["groups"], json!(["admin"]));
        assert!(!stored.claims.contains_key("user"));

        let req = test::TestRequest::post()
            .uri("/auth/login")
            .set_form(vec![
                ("response_type", "code"),
                ("redirect_uri", "http://localhost:3000/cb"),
                ("user", "7"),
            ])
            .to_request();
        assert_eq!(
            test::call_service(&app, req).await.status(),
            http::StatusCode::BAD_REQUEST
        );
        Ok(())
    }

    #[actix_rt::test]
    async fn test_login_code_flow_redirects_with_code() -> Result<(), Error> {
        let state = test_state();
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/auth/login").route(web::post().to(login))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/auth/login")
            .set_form(vec![
                ("response_type", "code"),
                ("client_id", "test-client"),
                ("redirect_uri", "http://localhost:3000/cb"),
                ("state", "xyz abc"),
                ("nonce", "n-0S6"),
                ("scope", "openid profile"),
                (
                    "code_challenge",
                    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                ),
                ("code_challenge_method", "S256"),
                ("sub", "F82E617D"),
                ("name", "Arie Ministrone"),
                ("claim_key", "email_verified"),
                ("claim_value", "true"),
                ("claim_key", "groups"),
                ("claim_value", r#"["admin","user"]"#),
            ])
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::SEE_OTHER);

        let location = location(&resp).to_string();
        assert!(location.starts_with("http://localhost:3000/cb?code="));
        // The state is handed back percent-encoded rather than raw.
        assert!(location.contains("state=xyz+abc"));

        // The code resolves to the claim set that was typed in, with the text
        // inputs coerced to their JSON types.
        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        let stored = state.auth_codes.get(code).expect("code was not stored");
        assert_eq!(stored.claims["sub"], json!("F82E617D"));
        assert_eq!(stored.claims["name"], json!("Arie Ministrone"));
        assert_eq!(stored.claims["email_verified"], json!(true));
        assert_eq!(stored.claims["groups"], json!(["admin", "user"]));
        assert_eq!(stored.code_challenge_method, "S256");
        assert_eq!(stored.nonce, Some("n-0S6".to_string()));
        assert_eq!(stored.scope, Some("openid profile".to_string()));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_login_implicit_flow_still_returns_tokens() -> Result<(), Error> {
        let app = test::init_service(
            App::new()
                .app_data(test_state())
                .service(web::resource("/auth/login").route(web::post().to(login))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/auth/login")
            .set_form(vec![
                ("response_type", "token id_token"),
                ("client_id", "test-client"),
                ("redirect_uri", "http://localhost:3000/cb"),
                ("state", "xyz"),
                ("nonce", "n-0S6"),
                ("sub", "F82E617D"),
                ("name", "Arie Ministrone"),
            ])
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::SEE_OTHER);

        let location = location(&resp);
        assert!(location.starts_with("http://localhost:3000/cb#"));
        assert!(location.contains("access_token="));
        assert!(location.contains("id_token="));
        assert!(location.contains("token_type=bearer"));
        assert!(!location.contains("code="));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_login_without_subject_is_rejected() -> Result<(), Error> {
        let app = test::init_service(
            App::new()
                .app_data(test_state())
                .service(web::resource("/auth/login").route(web::post().to(login))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/auth/login")
            .set_form(vec![
                ("response_type", "code"),
                ("client_id", "test-client"),
                ("redirect_uri", "http://localhost:3000/cb"),
                ("name", "No Subject"),
            ])
            .to_request();

        assert_eq!(
            test::call_service(&app, req).await.status(),
            http::StatusCode::BAD_REQUEST
        );
        Ok(())
    }
}

// Separate module: `use actix_web::test` above pulls in actix-web's `test`
// attribute macro, which shadows the built-in `#[test]` for sync functions.
#[cfg(test)]
mod form_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_claim_values_keep_their_json_type() {
        assert_eq!(parse_claim_value("true"), json!(true));
        assert_eq!(parse_claim_value("42"), json!(42));
        assert_eq!(parse_claim_value(r#"{"a":1}"#), json!({"a": 1}));
        assert_eq!(
            parse_claim_value("admin@example.com"),
            json!("admin@example.com")
        );
    }

    #[test]
    fn test_response_type_detection() {
        assert!(wants_code("code"));
        assert!(wants_code("code id_token"));
        assert!(!wants_code("token id_token"));
        assert!(!wants_code(""));
    }

    #[test]
    fn test_redirect_uri_with_existing_query_keeps_it() {
        let redirect = append_query(
            "http://localhost:3000/cb?tenant=acme",
            &[("code", "abc".to_string()), ("state", String::new())],
        );
        assert_eq!(redirect, "http://localhost:3000/cb?tenant=acme&code=abc");
    }

    #[test]
    fn test_protocol_fields_are_not_claims() {
        let (fields, claims) = split_form(vec![
            ("client_id".to_string(), "c".to_string()),
            ("sub".to_string(), "s".to_string()),
            ("claim_key".to_string(), "dept".to_string()),
            ("claim_value".to_string(), "sales".to_string()),
            // A key with no following value is dropped rather than guessed at.
            ("claim_key".to_string(), "dangling".to_string()),
        ]);
        assert_eq!(fields.get("client_id"), Some(&"c".to_string()));
        assert!(!claims.contains_key("client_id"));
        assert_eq!(claims["sub"], json!("s"));
        assert_eq!(claims["dept"], json!("sales"));
        assert!(!claims.contains_key("dangling"));
    }
}
