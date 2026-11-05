//! RFC 8693 token exchange: a client swaps a user's access token for one meant
//! for a single service. Without an `actor_token` the new token simply looks like
//! the user's (impersonation); with one it carries an `act` claim naming the
//! acting party (delegation).
//!
//! The behaviour follows Rauthy 0.36.1, which Ampsflow runs in production: only
//! access tokens are exchanged, the scope can only narrow, one target at a time.
//! Where this IdP has no user record to rebuild the token from, the subject
//! token's own claims stand in for one and are copied.
//!
//! This is the one place the service verifies a token. The fallback a backend
//! takes when its IdP refuses an expired user token is a branch worth testing,
//! and an expired or foreign token is still one legacy `/token` call away.

use super::{
    audience, check_flow, check_target, expires_in, token_response, Refusal, TokenRequest,
};
use crate::clients::Flow;
use crate::codes::now_secs;
use crate::token::{create_jwt, verify_jwt, TOKEN_TTL_SECS};
use crate::AppState;
use actix_web::HttpResponse;
use serde_json::{json, Map, Value};

pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Claims of the subject token that describe that token rather than the user:
/// its lifetime, its audience, its binding to an id token, its delegation chain
/// and its scope. Everything else is copied into the new token.
const NOT_COPIED: [&str; 10] = [
    "iat", "exp", "nbf", "aud", "at_hash", "nonce", "jti", "azp", "act", "scope",
];

pub fn grant(state: &AppState, form: &TokenRequest) -> Result<HttpResponse, Refusal> {
    let client_id = form
        .client_id()
        .ok_or_else(|| Refusal::invalid_request("Missing client_id"))?;
    let client = check_flow(state, client_id, Flow::TokenExchange)?;

    if let Some(requested) = form.get("requested_token_type") {
        if requested != ACCESS_TOKEN_TYPE {
            return Err(Refusal::invalid_request(format!(
                "The only supported requested_token_type is {}",
                ACCESS_TOKEN_TYPE
            )));
        }
    }

    let subject_token = presented_token(form, "subject_token")?
        .ok_or_else(|| Refusal::invalid_request("Missing subject_token"))?;
    let subject_claims = verify_jwt(&state.rsa_key_pair, subject_token)
        .map_err(|why| invalid_grant("subject_token", &why))?;

    let act = match presented_token(form, "actor_token")? {
        None => None,
        Some(actor_token) => {
            let actor_claims = verify_jwt(&state.rsa_key_pair, actor_token)
                .map_err(|why| invalid_grant("actor_token", &why))?;
            let sub = actor_claims
                .get("sub")
                .ok_or_else(|| invalid_grant("actor_token", "it has no sub claim"))?;
            let mut act = Map::new();
            act.insert("sub".to_string(), sub.clone());
            // An actor that was itself acting for someone keeps that history
            // nested inside the new act.
            if let Some(previous) = actor_claims.get("act") {
                act.insert("act".to_string(), previous.clone());
            }
            Some(Value::Object(act))
        }
    };

    // RFC 8693 names the target `audience`; `resource` (RFC 8707) does the same
    // job. Rauthy takes one or the other, never both.
    let target = match (form.single("resource")?, form.single("audience")?) {
        (Some(_), Some(_)) => {
            return Err(Refusal::new(
                "invalid_target",
                "resource and audience must not be given at the same time",
            ))
        }
        (resource, audience) => resource.or(audience),
    };
    check_target(client, target)?;

    // The exchange can narrow the subject's scope, never widen it.
    let subject_scope = subject_claims
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let scope = match form.get("scope") {
        Some(requested) => {
            let granted: Vec<&str> = subject_scope.split_whitespace().collect();
            let requested: Vec<&str> = requested.split_whitespace().collect();
            if let Some(extra) = requested.iter().find(|s| !granted.contains(s)) {
                return Err(Refusal::new(
                    "invalid_scope",
                    format!("The subject_token does not grant the scope {}", extra),
                ));
            }
            requested.join(" ")
        }
        None => subject_scope.to_string(),
    };

    let iat = now_secs();
    let mut claims = Map::new();
    for (key, value) in &subject_claims {
        if !NOT_COPIED.contains(&key.as_str()) {
            claims.insert(key.clone(), value.clone());
        }
    }
    claims.insert("iss".to_string(), json!(state.exposed_host));
    claims.insert("aud".to_string(), audience(client_id, target));
    claims.insert("azp".to_string(), json!(client_id));
    claims.insert("iat".to_string(), json!(iat));
    claims.insert("exp".to_string(), json!(iat + TOKEN_TTL_SECS));
    if let Some(act) = act {
        claims.insert("act".to_string(), act);
    }
    if !scope.is_empty() {
        claims.insert("scope".to_string(), json!(scope));
    }

    let expires_in = expires_in(&claims, iat);
    let access_token = create_jwt(&state.rsa_key_pair, Value::Object(claims));

    let mut body = json!({
        "access_token": access_token,
        "issued_token_type": ACCESS_TOKEN_TYPE,
        "token_type": "Bearer",
        "expires_in": expires_in,
    });
    if !scope.is_empty() {
        body["scope"] = json!(scope);
    }
    Ok(token_response(body))
}

/// The `subject_token` or `actor_token`, when given. Its `*_type` parameter is
/// then required and must name an access token, as in Rauthy.
fn presented_token<'a>(form: &'a TokenRequest, name: &str) -> Result<Option<&'a str>, Refusal> {
    let token = match form.get(name) {
        Some(token) => token,
        None => return Ok(None),
    };
    match form.get(&format!("{}_type", name)) {
        Some(ACCESS_TOKEN_TYPE) => Ok(Some(token)),
        Some(other) => Err(Refusal::invalid_request(format!(
            "The only supported {}_type is {}, got {}",
            name, ACCESS_TOKEN_TYPE, other
        ))),
        None => Err(Refusal::invalid_request(format!("Missing {}_type", name))),
    }
}

fn invalid_grant(name: &str, why: &str) -> Refusal {
    Refusal::invalid_grant(format!("The {} is not a valid access token: {}", name, why))
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::ACCESS_TOKEN_TYPE;
    use crate::codes::now_secs;
    use crate::token::{create_jwt, issue_tokens, TOKEN_TTL_SECS};
    use actix_web::{http, test, Error};
    use serde_json::{json, Map, Value};

    const CLIENTS: &str = r#"[
        {
            "client_id": "integration",
            "flows": ["client_credentials", "token_exchange"],
            "allowed_resources": ["http://localhost:8083"]
        },
        { "client_id": "no-exchange", "flows": ["client_credentials"] }
    ]"#;

    /// A user's access token as the login screen would have minted it.
    fn user_token(extra: Value) -> String {
        let now = now_secs();
        let mut claims = json!({
            "iss": EXPOSED_HOST,
            "sub": "F82E617D",
            "aud": "web-app",
            "azp": "web-app",
            "iat": now,
            "exp": now + 600,
            "name": "Arie Ministrone",
            "email": "arie@example.com",
            "groups": ["admin", "user"],
            "scope": "openid profile email",
            "nonce": "n-0S6_WzA2Mj"
        });
        for (key, value) in extra.as_object().unwrap() {
            claims[key] = value.clone();
        }
        create_jwt(&test_keys(), claims)
    }

    fn exchange_body(subject_token: &str, rest: &str) -> String {
        format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
             &client_id=integration&subject_token={}&subject_token_type={}{}",
            subject_token, ACCESS_TOKEN_TYPE, rest
        )
    }

    async fn exchange(clients: &str, body: &str) -> (http::StatusCode, Value) {
        let app = app(super::super::testing::clients(clients)).await;
        let resp = test::call_service(&app, token_request(body)).await;
        let status = resp.status();
        (status, test::read_body_json(resp).await)
    }

    async fn exchanged_claims(body: &str) -> (Value, Value) {
        let (status, body) = exchange("[]", body).await;
        assert_eq!(status, http::StatusCode::OK, "{}", body);
        let claims = decode_claims(body["access_token"].as_str().unwrap());
        (body, claims)
    }

    #[actix_rt::test]
    async fn test_impersonation_keeps_the_user_and_targets_the_resource() -> Result<(), Error> {
        let (body, claims) = exchanged_claims(&exchange_body(
            &user_token(json!({})),
            "&resource=http%3A%2F%2Flocalhost%3A8083",
        ))
        .await;

        assert_eq!(body["issued_token_type"], json!(ACCESS_TOKEN_TYPE));
        assert_eq!(body["token_type"], json!("Bearer"));
        assert_eq!(body["scope"], json!("openid profile email"));
        assert!(body.get("refresh_token").is_none());
        assert!(body.get("id_token").is_none());

        assert_eq!(claims["sub"], json!("F82E617D"));
        assert_eq!(claims["name"], json!("Arie Ministrone"));
        assert_eq!(claims["email"], json!("arie@example.com"));
        assert_eq!(claims["groups"], json!(["admin", "user"]));
        assert_eq!(claims["scope"], json!("openid profile email"));
        assert_eq!(claims["iss"], json!(EXPOSED_HOST));
        assert_eq!(
            claims["aud"],
            json!(["integration", "http://localhost:8083"])
        );
        assert_eq!(claims["azp"], json!("integration"));
        assert!(claims.get("act").is_none());
        assert!(claims.get("nonce").is_none());
        assert!(claims.get("at_hash").is_none());
        Ok(())
    }

    #[actix_rt::test]
    async fn test_without_a_target_the_audience_is_the_client() -> Result<(), Error> {
        let (_, claims) = exchanged_claims(&exchange_body(&user_token(json!({})), "")).await;
        assert_eq!(claims["aud"], json!("integration"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_delegation_names_the_actor_and_keeps_its_chain() -> Result<(), Error> {
        let actor = user_token(json!({ "sub": "service-a" }));
        let actor_param = format!(
            "&actor_token={}&actor_token_type={}",
            actor, ACCESS_TOKEN_TYPE
        );
        let (_, claims) =
            exchanged_claims(&exchange_body(&user_token(json!({})), &actor_param)).await;
        assert_eq!(claims["act"], json!({ "sub": "service-a" }));

        // The actor itself was acting for someone: that act nests inside.
        let actor = user_token(json!({ "sub": "service-b", "act": { "sub": "service-a" } }));
        let actor_param = format!(
            "&actor_token={}&actor_token_type={}",
            actor, ACCESS_TOKEN_TYPE
        );
        let (_, claims) =
            exchanged_claims(&exchange_body(&user_token(json!({})), &actor_param)).await;
        assert_eq!(
            claims["act"],
            json!({ "sub": "service-b", "act": { "sub": "service-a" } })
        );
        Ok(())
    }

    #[actix_rt::test]
    async fn test_lifetime_is_the_usual_one_whatever_the_subject_token_says() -> Result<(), Error> {
        let (body, claims) = exchanged_claims(&exchange_body(&user_token(json!({})), "")).await;
        assert_eq!(body["expires_in"], json!(TOKEN_TTL_SECS));
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            TOKEN_TTL_SECS
        );

        // A legacy-path token without exp is a fine subject token too.
        let no_exp = create_jwt(
            &test_keys(),
            json!({ "sub": "F82E617D", "scope": "openid" }),
        );
        let (body, _) = exchanged_claims(&exchange_body(&no_exp, "")).await;
        assert_eq!(body["expires_in"], json!(TOKEN_TTL_SECS));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_scope_can_only_narrow() -> Result<(), Error> {
        let (body, claims) = exchanged_claims(&exchange_body(
            &user_token(json!({})),
            "&scope=openid%20email",
        ))
        .await;
        assert_eq!(claims["scope"], json!("openid email"));
        assert_eq!(body["scope"], json!("openid email"));

        let (status, body) = exchange(
            "[]",
            &exchange_body(&user_token(json!({})), "&scope=openid%20admin"),
        )
        .await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("invalid_scope"));

        // No scope on the subject token: nothing can be requested, and nothing
        // is issued.
        let no_scope = create_jwt(&test_keys(), json!({ "sub": "F82E617D" }));
        let (status, body) = exchange("[]", &exchange_body(&no_scope, "&scope=openid")).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("invalid_scope"));
        let (body, claims) = exchanged_claims(&exchange_body(&no_scope, "")).await;
        assert!(body.get("scope").is_none());
        assert!(claims.get("scope").is_none());
        Ok(())
    }

    /// The access token of the code flow carries its scope so that it can be
    /// exchanged with one.
    #[actix_rt::test]
    async fn test_a_code_flow_token_can_be_exchanged_with_a_scope() -> Result<(), Error> {
        let mut login = Map::new();
        login.insert("sub".to_string(), json!("F82E617D"));
        let tokens = issue_tokens(
            &test_keys(),
            EXPOSED_HOST,
            "web-app",
            &login,
            None,
            Some("openid profile"),
        );
        let (_, claims) =
            exchanged_claims(&exchange_body(&tokens.access_token, "&scope=openid")).await;
        assert_eq!(claims["scope"], json!("openid"));
        assert_eq!(claims["sub"], json!("F82E617D"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_bad_subject_tokens_are_invalid_grant() -> Result<(), Error> {
        let now = now_secs();
        let cases = [
            user_token(json!({ "exp": now - 1 })),
            user_token(json!({ "exp": "tomorrow" })),
            tamper(&user_token(json!({}))),
            "not.a.jwt".to_string(),
            "eyJhbGciOiJub25lIn0.e30.".to_string(),
        ];
        for subject in cases {
            let (status, body) = exchange("[]", &exchange_body(&subject, "")).await;
            assert_eq!(status, http::StatusCode::BAD_REQUEST, "{}", subject);
            assert_eq!(body["error"], json!("invalid_grant"), "{}", subject);
        }

        // An actor without a sub cannot be named in act.
        let actor = create_jwt(&test_keys(), json!({ "name": "nobody" }));
        let (status, body) = exchange(
            "[]",
            &exchange_body(
                &user_token(json!({})),
                &format!(
                    "&actor_token={}&actor_token_type={}",
                    actor, ACCESS_TOKEN_TYPE
                ),
            ),
        )
        .await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("invalid_grant"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_token_types_other_than_access_token_are_invalid_request() -> Result<(), Error> {
        let subject = user_token(json!({}));
        let cases = [
            // subject_token_type jwt
            format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
                 &client_id=integration&subject_token={}\
                 &subject_token_type=urn:ietf:params:oauth:token-type:jwt",
                subject
            ),
            // no subject_token_type at all
            format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
                 &client_id=integration&subject_token={}",
                subject
            ),
            // no subject_token at all
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
             &client_id=integration"
                .to_string(),
            // actor_token without its type
            exchange_body(&subject, &format!("&actor_token={}", subject)),
            // something other than an access token requested
            exchange_body(
                &subject,
                "&requested_token_type=urn:ietf:params:oauth:token-type:id_token",
            ),
        ];
        for body in cases {
            let (status, response) = exchange("[]", &body).await;
            assert_eq!(status, http::StatusCode::BAD_REQUEST, "{}", body);
            assert_eq!(response["error"], json!("invalid_request"), "{}", body);
        }
        Ok(())
    }

    #[actix_rt::test]
    async fn test_resource_and_audience_together_are_invalid_target() -> Result<(), Error> {
        let (status, body) = exchange(
            "[]",
            &exchange_body(
                &user_token(json!({})),
                "&resource=http%3A%2F%2Fa&audience=http%3A%2F%2Fb",
            ),
        )
        .await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("invalid_target"));

        // Either one alone names the target.
        let (_, claims) = exchanged_claims(&exchange_body(
            &user_token(json!({})),
            "&audience=http%3A%2F%2Fb",
        ))
        .await;
        assert_eq!(claims["aud"], json!(["integration", "http://b"]));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_file_refusals() -> Result<(), Error> {
        let subject = user_token(json!({}));

        let (status, body) = exchange(
            CLIENTS,
            &exchange_body(&subject, "").replace("client_id=integration", "client_id=no-exchange"),
        )
        .await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("unauthorized_client"));

        let (status, body) = exchange(
            CLIENTS,
            &exchange_body(&subject, "&audience=http%3A%2F%2Felsewhere"),
        )
        .await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("invalid_target"));

        let (status, _) = exchange(
            CLIENTS,
            &exchange_body(&subject, "&resource=http%3A%2F%2Flocalhost%3A8083"),
        )
        .await;
        assert_eq!(status, http::StatusCode::OK);
        Ok(())
    }
}
