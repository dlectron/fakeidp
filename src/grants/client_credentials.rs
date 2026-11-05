//! RFC 6749 section 4.4: a client gets a token as itself. No user, so no id token
//! and no refresh token.
//!
//! The claims follow Rauthy 0.36.1 with `client_credentials_map_sub = true`: the
//! subject is the client id, the audience is the client plus the `resource`. A
//! `scope` parameter is ignored, as Rauthy ignores it, and `audience` is only a
//! token-exchange parameter. The clients file can add claims and provoke the two
//! refusals.

use super::{
    audience, check_flow, check_target, expires_in, token_response, Refusal, TokenRequest,
};
use crate::clients::Flow;
use crate::codes::now_secs;
use crate::token::{create_jwt, TOKEN_TTL_SECS};
use crate::AppState;
use actix_web::HttpResponse;
use serde_json::{json, Map, Value};

pub fn grant(state: &AppState, form: &TokenRequest) -> Result<HttpResponse, Refusal> {
    let client_id = form
        .client_id()
        .ok_or_else(|| Refusal::invalid_request("Missing client_id"))?;
    let resource = form.single("resource")?;
    let client = check_flow(state, client_id, Flow::ClientCredentials)?;
    check_target(client, resource)?;

    let iat = now_secs();
    let mut claims = Map::new();
    claims.insert("iss".to_string(), json!(state.exposed_host));
    claims.insert("sub".to_string(), json!(client_id));
    claims.insert("aud".to_string(), audience(client_id, resource));
    claims.insert("azp".to_string(), json!(client_id));
    claims.insert("iat".to_string(), json!(iat));
    claims.insert("exp".to_string(), json!(iat + TOKEN_TTL_SECS));
    // The file's claims win over the defaults, `sub` and `exp` included.
    if let Some(client) = client {
        for (key, value) in &client.claims {
            claims.insert(key.clone(), value.clone());
        }
    }

    let scope = claims
        .get("scope")
        .and_then(Value::as_str)
        .map(str::to_string);
    let expires_in = expires_in(&claims, iat);
    let access_token = create_jwt(&state.rsa_key_pair, Value::Object(claims));

    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    });
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    Ok(token_response(body))
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use actix_web::{http, test, Error};
    use data_encoding::BASE64;
    use serde_json::{json, Value};

    const CLIENTS: &str = r#"[
        {
            "client_id": "integration",
            "claims": { "name": "Integration", "scope": "openid", "sub": "overridden" },
            "allowed_resources": ["http://localhost:8083"]
        },
        { "client_id": "no-credentials", "flows": ["token_exchange"] }
    ]"#;

    async fn credentials(clients: &str, body: &str) -> (http::StatusCode, Value) {
        let app = app(super::super::testing::clients(clients)).await;
        let resp = test::call_service(&app, token_request(body)).await;
        let status = resp.status();
        (status, test::read_body_json(resp).await)
    }

    #[actix_rt::test]
    async fn test_unknown_client_gets_a_token_as_itself() -> Result<(), Error> {
        let (status, body) =
            credentials("[]", "grant_type=client_credentials&client_id=my-service").await;
        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(body["token_type"], json!("Bearer"));
        assert_eq!(body["expires_in"], json!(crate::token::TOKEN_TTL_SECS));
        assert!(body.get("id_token").is_none());
        assert!(body.get("refresh_token").is_none());
        assert!(body.get("scope").is_none());

        let claims = decode_claims(body["access_token"].as_str().unwrap());
        assert_eq!(claims["iss"], json!(EXPOSED_HOST));
        assert_eq!(claims["sub"], json!("my-service"));
        assert_eq!(claims["aud"], json!("my-service"));
        assert_eq!(claims["azp"], json!("my-service"));
        assert!(claims.get("client_id").is_none());
        assert!(claims["exp"].as_u64().unwrap() > claims["iat"].as_u64().unwrap());
        Ok(())
    }

    #[actix_rt::test]
    async fn test_resource_joins_the_audience() -> Result<(), Error> {
        let (status, body) = credentials(
            "[]",
            "grant_type=client_credentials&client_id=my-service\
             &resource=http%3A%2F%2Flocalhost%3A8083",
        )
        .await;
        assert_eq!(status, http::StatusCode::OK);
        let claims = decode_claims(body["access_token"].as_str().unwrap());
        assert_eq!(
            claims["aud"],
            json!(["my-service", "http://localhost:8083"])
        );
        Ok(())
    }

    #[actix_rt::test]
    async fn test_file_claims_override_the_defaults() -> Result<(), Error> {
        let (status, body) = credentials(
            CLIENTS,
            "grant_type=client_credentials&client_id=integration",
        )
        .await;
        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(body["scope"], json!("openid"));
        let claims = decode_claims(body["access_token"].as_str().unwrap());
        assert_eq!(claims["name"], json!("Integration"));
        assert_eq!(claims["scope"], json!("openid"));
        assert_eq!(claims["sub"], json!("overridden"));
        assert_eq!(claims["azp"], json!("integration"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_scope_and_audience_parameters_are_ignored() -> Result<(), Error> {
        let (status, body) = credentials(
            "[]",
            "grant_type=client_credentials&client_id=my-service\
             &scope=openid%20profile&audience=http%3A%2F%2Felsewhere",
        )
        .await;
        assert_eq!(status, http::StatusCode::OK);
        assert!(body.get("scope").is_none());
        let claims = decode_claims(body["access_token"].as_str().unwrap());
        assert!(claims.get("scope").is_none());
        assert_eq!(claims["aud"], json!("my-service"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_basic_authentication_names_the_client() -> Result<(), Error> {
        let app = app(vec![]).await;
        // RFC 6749 2.3.1: form-urlencoded before base64, so the %3A is a colon.
        let basic = format!("Basic {}", BASE64.encode(b"my%3Aservice:any-secret-at-all"));
        let resp = test::call_service(
            &app,
            token_request_with(
                "grant_type=client_credentials",
                &[("Authorization", &basic)],
            ),
        )
        .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;
        let claims = decode_claims(body["access_token"].as_str().unwrap());
        assert_eq!(claims["sub"], json!("my:service"));

        // The same id in both places is fine, a different one is not.
        let resp = test::call_service(
            &app,
            token_request_with(
                "grant_type=client_credentials&client_id=someone-else",
                &[("Authorization", &basic)],
            ),
        )
        .await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], json!("invalid_request"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_missing_client_id_is_invalid_request() -> Result<(), Error> {
        let (status, body) = credentials("[]", "grant_type=client_credentials").await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("invalid_request"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_a_repeated_resource_is_invalid_request() -> Result<(), Error> {
        let (status, body) = credentials(
            "[]",
            "grant_type=client_credentials&client_id=my-service&resource=a&resource=b",
        )
        .await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("invalid_request"));
        Ok(())
    }

    #[actix_rt::test]
    async fn test_file_refusals() -> Result<(), Error> {
        let (status, body) = credentials(
            CLIENTS,
            "grant_type=client_credentials&client_id=no-credentials",
        )
        .await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("unauthorized_client"));

        let (status, body) = credentials(
            CLIENTS,
            "grant_type=client_credentials&client_id=integration&resource=http%3A%2F%2Felsewhere",
        )
        .await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("invalid_target"));

        let (status, _) = credentials(
            CLIENTS,
            "grant_type=client_credentials&client_id=integration&resource=http%3A%2F%2Flocalhost%3A8083",
        )
        .await;
        assert_eq!(status, http::StatusCode::OK);
        Ok(())
    }
}
