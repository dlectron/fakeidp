use actix_4_jwt_auth::AuthenticatedUser;
use actix_web::{Error, HttpResponse};
use serde::{Deserialize, Serialize};
use std::str;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct FoundClaims {
    pub sub: String,
    pub name: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

pub async fn user_info(user: AuthenticatedUser<FoundClaims>) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(user.claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::create_jwk_set;
    use crate::token;
    use actix_4_jwt_auth::{Oidc, OidcBiscuitValidator, OidcConfig};
    use actix_web::web;
    use actix_web::{http, test, App};
    use biscuit::jws::Secret;
    use biscuit::{Validation, ValidationOptions};
    use serde_json::json;
    use serde_json::Value;
    use std::str;

    async fn create_oidc(secret: &Secret) -> Oidc {
        let jwk_set = create_jwk_set(secret.clone());
        Oidc::new(OidcConfig::Jwks(jwk_set)).await.unwrap()
    }

    fn create_validator(issuer: String) -> OidcBiscuitValidator {
        OidcBiscuitValidator {
            options: ValidationOptions {
                issuer: Validation::Validate(issuer),
                ..ValidationOptions::default()
            },
        }
    }

    fn create_claims() -> &'static str {
        r##"
            {
                "iss": "http://localhost:8080",
                "sub": "F82E617D-DEAF-4EE6-8F96-CF3409060CA2",
                "aud": "fakeidp",
                "email": "admin@example.com",
                "email_verified": true,
                "name": "Arie Ministrone"
            }
        "##
    }

    #[actix_rt::test]
    async fn test_route_userinfo() -> Result<(), Error> {
        let claims = create_claims();
        let rsa_keys = Secret::rsa_keypair_from_file("./keys/private_key.der")
            .expect("Cannot read RSA keypair");
        let issuer = "http://localhost:8080".to_string();
        let oidc = create_oidc(&rsa_keys).await;
        let biscuit_validator = create_validator(issuer);

        let claims_json = serde_json::from_str(claims).unwrap();
        let jwt = token::create_jwt(&rsa_keys, claims_json);

        let app = test::init_service(
            App::new()
                .app_data(oidc.clone())
                .wrap(biscuit_validator.clone())
                .service(web::resource("/").route(web::post().to(user_info))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/")
            .insert_header(("Authorization", format!("Bearer {}", jwt)))
            .set_payload(claims)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response_body = test::read_body(resp).await;
        let body_str = str::from_utf8(&response_body)
            .unwrap_or("Error with parsing result from bytes to string");
        let p: Value = serde_json::from_str(body_str).unwrap();

        assert_eq!(p["name"], json!("Arie Ministrone"));

        Ok(())
    }

    #[actix_rt::test]
    async fn test_route_userinfo_no_token() -> Result<(), Error> {
        let rsa_keys = Secret::rsa_keypair_from_file("./keys/private_key.der")
            .expect("Cannot read RSA keypair");
        let issuer = "http://localhost:8080".to_string();
        let oidc = create_oidc(&rsa_keys).await;
        let biscuit_validator = create_validator(issuer);

        let app = test::init_service(
            App::new()
                .app_data(oidc.clone())
                .wrap(biscuit_validator.clone())
                .service(web::resource("/").route(web::post().to(user_info))),
        )
        .await;

        let claims = create_claims();
        let req = test::TestRequest::post()
            .uri("/")
            .set_payload(claims)
            .to_request();

        let resp = test::try_call_service(&app, req).await;
        let error = resp.unwrap_err();
        assert_eq!(
            error.to_string(),
            "No token found or token is not authorized"
        );
        Ok(())
    }
}
