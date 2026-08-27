use crate::codes::now_secs;
use crate::AppState;
use actix_web::http::StatusCode;
use actix_web::{error, web, Error, HttpRequest, HttpResponse};
use biscuit::jwa::*;
use biscuit::jws::*;
use biscuit::*;
use bytes::Bytes;
use data_encoding::BASE64URL_NOPAD;
use ring::digest;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::str;

/// Lifetime of the tokens minted by the login screen, unless the login form
/// supplied its own `exp`.
pub const TOKEN_TTL_SECS: u64 = 12200;

/// The `/token` endpoint serves two unrelated purposes.
///
/// * `application/x-www-form-urlencoded` -> the OAuth 2.0 token endpoint, used
///   to exchange an authorization code (with PKCE) for tokens.
/// * anything else -> the original "sign this claim set for me" shortcut, which
///   takes a bare JSON object and returns the encoded JWT as `text/plain`.
///
/// Dispatching on the content type keeps both callers working on one path, which
/// is what the discovery document has always advertised as `token_endpoint`.
pub async fn create_token(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: Bytes,
) -> Result<HttpResponse, Error> {
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    if content_type.starts_with("application/x-www-form-urlencoded") {
        Ok(exchange_code(&state, &body))
    } else {
        sign_claim_set(&state, &body)
    }
}

/// The original endpoint: sign whatever JSON object is posted, no questions asked.
fn sign_claim_set(state: &AppState, claims_req: &Bytes) -> Result<HttpResponse, Error> {
    let signing_secret = &state.rsa_key_pair;

    let res: Result<Value, Error> = str::from_utf8(claims_req)
        .map(|s| serde_json::from_str(s))
        .unwrap()
        .map_err(error::ErrorInternalServerError);

    //Please note that the way the token is created with RegisteredClaims (all None)
    //and private claims with a JSON Value with all passed claims is a bit of a hack.
    res.and_then(|claims| match claims {
        Value::Object(ref _v) => {
            let encoded_token = create_jwt(signing_secret, claims);
            Ok(HttpResponse::Ok()
                .content_type("text/plain")
                .body(encoded_token))
        }
        other => Err(error::ErrorBadRequest(format!(
            "Claims are not given as JSON object but as: {:?}",
            other
        ))),
    })
}

/// RFC 6749 section 4.1.3 / RFC 7636 section 4.5: swap an authorization code for
/// the tokens that the login screen described.
fn exchange_code(state: &AppState, body: &Bytes) -> HttpResponse {
    let form: HashMap<String, String> =
        match serde_urlencoded::from_bytes::<Vec<(String, String)>>(body) {
            Ok(pairs) => pairs.into_iter().collect(),
            Err(err) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    &format!("Request body is not valid form encoding: {}", err),
                )
            }
        };

    let field = |name: &str| form.get(name).filter(|value| !value.is_empty());

    match field("grant_type").map(String::as_str) {
        Some("authorization_code") => {}
        Some(other) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                &format!("Only authorization_code is supported, got {}", other),
            )
        }
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing grant_type",
            )
        }
    }

    let code = match field("code") {
        Some(code) => code,
        None => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "Missing code"),
    };

    // Looked up but not yet retired: a request that fails validation below leaves
    // the code exchangeable so it can be retried with a corrected verifier.
    let entry = match state.auth_codes.get(code) {
        Some(entry) => entry,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Authorization code is unknown, already used or expired",
            )
        }
    };

    // These two are the only things we are strict about, because a client that
    // gets them wrong is misconfigured rather than exercising an edge case.
    if let Some(redirect_uri) = field("redirect_uri") {
        if *redirect_uri != entry.redirect_uri {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "redirect_uri does not match the one used at the authorization endpoint",
            );
        }
    }
    if let Some(client_id) = field("client_id") {
        if *client_id != entry.client_id {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "client_id does not match the one used at the authorization endpoint",
            );
        }
    }

    if !entry.verify_pkce(field("code_verifier").map(String::as_str)) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "code_verifier does not match the code_challenge",
        );
    }

    // Validation passed, so the code is spent.
    state.auth_codes.consume(code);

    let tokens = issue_tokens(
        &state.rsa_key_pair,
        &state.exposed_host,
        &entry.client_id,
        &entry.claims,
        entry.nonce.as_deref(),
    );

    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Pragma", "no-cache"))
        .json(json!({
            "access_token": tokens.access_token,
            "id_token": tokens.id_token,
            "token_type": "Bearer",
            "expires_in": tokens.expires_in,
            "scope": entry.scope.unwrap_or_else(|| "openid".to_string()),
        }))
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    HttpResponse::build(status)
        .insert_header(("Cache-Control", "no-store"))
        .json(json!({ "error": error, "error_description": description }))
}

pub struct IssuedTokens {
    pub access_token: String,
    pub id_token: String,
    pub expires_in: u64,
}

/// Build the access token and matching id token for a set of login claims.
///
/// Shared by the implicit flow (tokens in the redirect fragment) and the code
/// flow (tokens at the token endpoint), so both produce identical claim sets.
pub fn issue_tokens(
    signing_secret: &Secret,
    exposed_host: &str,
    client_id: &str,
    claims: &Map<String, Value>,
    nonce: Option<&str>,
) -> IssuedTokens {
    let iat = now_secs();

    let mut base = Map::new();
    base.insert("iss".to_string(), json!(exposed_host));
    base.insert("aud".to_string(), json!(client_id));
    base.insert("iat".to_string(), json!(iat));
    base.insert("exp".to_string(), json!(iat + TOKEN_TTL_SECS));
    // Claims typed at the login screen win over our defaults. Handing out a token
    // with a bogus issuer or an expiry in the past is a supported test case.
    for (key, value) in claims {
        base.insert(key.clone(), value.clone());
    }

    let access_token = create_jwt(signing_secret, Value::Object(base.clone()));

    let mut id_claims = base.clone();
    id_claims
        .entry("at_hash")
        .or_insert_with(|| json!(at_hash(&access_token)));
    if let Some(nonce) = nonce {
        id_claims.entry("nonce").or_insert_with(|| json!(nonce));
    }
    let id_token = create_jwt(signing_secret, Value::Object(id_claims));

    let expires_in = base
        .get("exp")
        .and_then(Value::as_u64)
        .map(|exp| exp.saturating_sub(iat))
        .unwrap_or(TOKEN_TTL_SECS);

    IssuedTokens {
        access_token,
        id_token,
        expires_in,
    }
}

/// at_hash. Access Token hash value.
/// Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the access_token value,
/// where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header.
/// For instance, if the alg is RS256, hash the access_token value with SHA-256, then take the left-most 128 bits and base64url encode them. (without padding)
/// The at_hash value is a case sensitive string.
pub fn at_hash(access_token: &str) -> String {
    let sha_digest = digest::digest(&digest::SHA256, access_token.as_bytes());
    BASE64URL_NOPAD.encode(&sha_digest.as_ref()[0..16])
}

pub fn create_jwt(signing_secret: &Secret, claims: Value) -> String {
    let decoded_token = JWT::new_decoded(
        From::from(RegisteredHeader {
            algorithm: SignatureAlgorithm::RS256,
            key_id: Some("2020-01-29".to_string()),
            ..Default::default()
        }),
        ClaimsSet::<Value> {
            registered: RegisteredClaims {
                issuer: None,
                subject: None,
                audience: None,
                not_before: None,
                expiry: None,
                id: None,
                issued_at: None,
            },
            private: claims,
        },
    );
    decoded_token
        .encode(&signing_secret)
        .unwrap()
        .unwrap_encoded()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codes::{AuthCode, CODE_TTL_SECS};
    use crate::discovery::create_jwk_set;
    use actix_4_jwt_auth::{Oidc, OidcConfig};
    use actix_web::{http, test, web, App};
    use std::str;

    async fn create_oidc(secret: &Secret) -> Oidc {
        let jwk_set = create_jwk_set(secret.clone());
        Oidc::new(OidcConfig::Jwks(jwk_set)).await.unwrap()
    }

    fn test_keys() -> Secret {
        Secret::rsa_keypair_from_file("./keys/private_key.der").expect("Cannot read RSA keypair")
    }

    // RFC 7636 appendix B.
    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn stored_code(challenge: Option<&str>) -> AuthCode {
        let mut claims = Map::new();
        claims.insert("sub".to_string(), json!("F82E617D"));
        claims.insert("name".to_string(), json!("Arie Ministrone"));
        claims.insert("groups".to_string(), json!(["admin", "user"]));
        AuthCode {
            client_id: "test-client".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            nonce: Some("n-0S6_WzA2Mj".to_string()),
            scope: Some("openid profile".to_string()),
            code_challenge: challenge.map(str::to_string),
            code_challenge_method: "S256".to_string(),
            claims,
            expires_at: now_secs() + CODE_TTL_SECS,
        }
    }

    /// Build the app with one authorization code already issued.
    async fn app_with_code(
        challenge: Option<&str>,
    ) -> (
        impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = Error,
        >,
        web::Data<AppState>,
    ) {
        let rsa_keys = test_keys();
        let oidc = create_oidc(&rsa_keys).await;
        let state = web::Data::new(AppState::new(rsa_keys, "http://localhost:8080".to_string()));
        state
            .auth_codes
            .insert("the-code".to_string(), stored_code(challenge));

        let app = test::init_service(
            App::new()
                .app_data(oidc)
                .app_data(state.clone())
                .service(web::resource("/token").route(web::post().to(create_token))),
        )
        .await;
        (app, state)
    }

    fn token_request(body: &str) -> actix_http::Request {
        test::TestRequest::post()
            .uri("/token")
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload(body.to_string())
            .to_request()
    }

    #[actix_rt::test]
    async fn test_route_create_token() -> Result<(), Error> {
        let claims = r##"
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
        "##;

        let rsa_keys = test_keys();
        let oidc = create_oidc(&rsa_keys).await;

        let exposed_host = "http://localhost:8080".to_string();
        let app = test::init_service(
            App::new()
                .app_data(oidc.clone())
                .app_data(web::Data::new(AppState::new(rsa_keys, exposed_host)))
                .service(web::resource("/").route(web::post().to(create_token))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/")
            .set_payload(claims)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response_body = test::read_body(resp).await;
        let body_str = match str::from_utf8(&response_body) {
            Ok(v) => v,
            Err(_e) => "Error with parsing result from bytes to string",
        };

        assert_eq!(body_str, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIwMjAtMDEtMjkifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvbW9jayIsInN1YiI6IkNnVmhaRzFwYmhJRmJHOWpZV3ciLCJhdWQiOiJjYWZpZW5uZS11aSIsImV4cCI6MTU3NjU2ODQ5NSwiaWF0IjoxNTc2NDgyMDk1LCJhdF9oYXNoIjoienFLaEwtc1Y2VE5KVUZRU0Y3UHdMUSIsImVtYWlsIjoiYWRtaW5AZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImFkbWluIn0.KxJNef8u8N8t7CfHSiha4yFpiivRGcR_zmNNAN9CJGBGuX5i0h9cYw1AGupNvBe5VEQTpp_hk3_S5lJE8qTw60ey9zUfbbiMX3uWUUsqNVcCv51kF5hzPA0eQffZMpMRBSzJa1WgY39yQATy2eBoDEt_JPXixGOy6Xl9Op9VoDozFyVYtG31oUSM4rFhSqTAYFrRfXIdrYIaBkcqd5FFRRidSb6mSgZwl9YT5gCr2LF7fLAePqAEJqiQP3weOJNytv52OMRMjosmO6bnQQvNx6Hq7M3o6n-nfWa8SE7GlvV4MJ8b-HR8n6xQ4EZYZ09hBM2HYlS1CqpAjHs0OM3z9g");

        Ok(())
    }

    #[actix_rt::test]
    async fn test_pkce_code_exchange() -> Result<(), Error> {
        let (app, _state) = app_with_code(Some(RFC_CHALLENGE)).await;

        let resp = test::call_service(
            &app,
            token_request(&format!(
                "grant_type=authorization_code&code=the-code\
                 &redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback\
                 &client_id=test-client&code_verifier={}",
                RFC_VERIFIER
            )),
        )
        .await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["token_type"], json!("Bearer"));
        assert_eq!(body["scope"], json!("openid profile"));
        assert_eq!(body["expires_in"], json!(TOKEN_TTL_SECS));

        // The claims typed at the login screen, including the non-string ones,
        // come back in both tokens.
        let id_token = body["id_token"].as_str().unwrap();
        let id_claims = decode_claims(id_token);
        assert_eq!(id_claims["sub"], json!("F82E617D"));
        assert_eq!(id_claims["groups"], json!(["admin", "user"]));
        assert_eq!(id_claims["aud"], json!("test-client"));
        assert_eq!(id_claims["iss"], json!("http://localhost:8080"));
        assert_eq!(id_claims["nonce"], json!("n-0S6_WzA2Mj"));

        // at_hash has to bind the id token to the access token it came with.
        let access_token = body["access_token"].as_str().unwrap();
        assert_eq!(id_claims["at_hash"], json!(at_hash(access_token)));

        Ok(())
    }

    #[actix_rt::test]
    async fn test_pkce_rejects_wrong_verifier() -> Result<(), Error> {
        let (app, _state) = app_with_code(Some(RFC_CHALLENGE)).await;

        let resp = test::call_service(
            &app,
            token_request(
                "grant_type=authorization_code&code=the-code&code_verifier=wrong-verifier",
            ),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], json!("invalid_grant"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_pkce_requires_verifier_when_challenge_was_sent() -> Result<(), Error> {
        let (app, _state) = app_with_code(Some(RFC_CHALLENGE)).await;

        let resp = test::call_service(
            &app,
            token_request("grant_type=authorization_code&code=the-code"),
        )
        .await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[actix_rt::test]
    async fn test_code_without_challenge_needs_no_verifier() -> Result<(), Error> {
        let (app, _state) = app_with_code(None).await;

        let resp = test::call_service(
            &app,
            token_request("grant_type=authorization_code&code=the-code"),
        )
        .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        Ok(())
    }

    /// A rejected verifier must not burn the code: fixing the verifier and
    /// retrying the same code is the common case when debugging a client.
    #[actix_rt::test]
    async fn test_failed_exchange_leaves_the_code_usable() -> Result<(), Error> {
        let (app, _state) = app_with_code(Some(RFC_CHALLENGE)).await;

        let rejected = test::call_service(
            &app,
            token_request("grant_type=authorization_code&code=the-code&code_verifier=wrong"),
        )
        .await;
        assert_eq!(rejected.status(), http::StatusCode::BAD_REQUEST);

        let retried = test::call_service(
            &app,
            token_request(&format!(
                "grant_type=authorization_code&code=the-code&code_verifier={}",
                RFC_VERIFIER
            )),
        )
        .await;
        assert_eq!(retried.status(), http::StatusCode::OK);
        Ok(())
    }

    #[actix_rt::test]
    async fn test_code_is_single_use() -> Result<(), Error> {
        let (app, _state) = app_with_code(None).await;
        let body = "grant_type=authorization_code&code=the-code";

        assert_eq!(
            test::call_service(&app, token_request(body)).await.status(),
            http::StatusCode::OK
        );
        let resp = test::call_service(&app, token_request(body)).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let error: Value = test::read_body_json(resp).await;
        assert_eq!(error["error"], json!("invalid_grant"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_mismatched_redirect_uri_is_rejected() -> Result<(), Error> {
        let (app, _state) = app_with_code(None).await;

        let resp = test::call_service(
            &app,
            token_request(
                "grant_type=authorization_code&code=the-code&redirect_uri=http%3A%2F%2Fevil.example%2Fcb",
            ),
        )
        .await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[actix_rt::test]
    async fn test_unsupported_grant_type() -> Result<(), Error> {
        let (app, _state) = app_with_code(None).await;

        let resp = test::call_service(&app, token_request("grant_type=client_credentials")).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], json!("unsupported_grant_type"));
        Ok(())
    }

    /// Decode the payload of a JWT without verifying it; the signature is covered
    /// by the userinfo tests.
    fn decode_claims(jwt: &str) -> Value {
        let payload = jwt.split('.').nth(1).expect("jwt has no payload");
        let decoded = BASE64URL_NOPAD.decode(payload.as_bytes()).unwrap();
        serde_json::from_slice(&decoded).unwrap()
    }
}
