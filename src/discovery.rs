use crate::AppState;
use actix_web::{web, Error, HttpResponse};
use biscuit::jwa;
use biscuit::jwa::Algorithm;
use biscuit::jwk::*;
use biscuit::jws::Secret;
use biscuit::Empty;
use num::BigUint;
use ring::{rsa::PublicKeyComponents, signature::KeyPair};
use serde_json::json;
use std::format;

pub async fn keys(state: web::Data<AppState>) -> Result<HttpResponse, Error> {
    let rsa_key = state.rsa_key_pair.clone();
    let jwk_set = create_jwk_set(rsa_key);
    Ok(HttpResponse::Ok().json(jwk_set))
}

pub fn create_jwk_set(secret: Secret) -> JWKSet<Empty> {
    let public_key = match secret {
        Secret::RsaKeyPair(ring_pair) => {
            let cloned_pair = ring_pair.clone();
            let pk = PublicKeyComponents::<Vec<_>>::from(cloned_pair.public_key());
            Some(pk)
        }
        _ => None,
    }
    .expect("There is no RsaKeyPair with a public key found");

    let jwk_set: JWKSet<Empty> = JWKSet {
        keys: vec![JWK {
            common: CommonParameters {
                algorithm: Some(Algorithm::Signature(jwa::SignatureAlgorithm::RS256)),
                key_id: Some("2020-01-29".to_string()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                n: BigUint::from_bytes_be(public_key.n.as_slice()),
                e: BigUint::from_bytes_be(public_key.e.as_slice()),
                ..Default::default()
            }),
            additional: Default::default(),
        }],
    };
    jwk_set
}

pub async fn openid_configuration(state: web::Data<AppState>) -> Result<HttpResponse, Error> {
    let keys_response = json!( {
      "issuer": state.exposed_host.to_string(),
      "authorization_endpoint": format!("{}/auth", state.exposed_host),
      "token_endpoint": format!("{}/token", state.exposed_host),
      "jwks_uri": format!("{}/keys", state.exposed_host),
      "userinfo_endpoint": format!("{}/userinfo", state.exposed_host),
      "response_types_supported": [
        "code",
        "id_token",
        "token",
        "id_token token"
      ],
      "grant_types_supported": [
        "authorization_code",
        "implicit"
      ],
      "code_challenge_methods_supported": [
        "S256",
        "plain"
      ],
      "response_modes_supported": [
        "query",
        "fragment"
      ],
      "subject_types_supported": [
        "public"
      ],
      "id_token_signing_alg_values_supported": [
        "RS256"
      ],
      "scopes_supported": [
        "openid",
        "email",
        "groups",
        "profile",
        "offline_access"
      ],
      "token_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post",
        "none"
      ],
      "claims_supported": [
        "aud",
        "email",
        "email_verified",
        "exp",
        "iat",
        "iss",
        "locale",
        "name",
        "sub"
      ]
    });
    Ok(HttpResponse::Ok().json(keys_response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http, test, web, App};
    use serde_json::json;
    use serde_json::Value;
    use std::str;

    #[actix_rt::test]
    async fn test_route_keys() -> Result<(), Error> {
        let exposed_host = "http://localhost:8080".to_string();
        let rsa_keys = Secret::rsa_keypair_from_file("./keys/private_key.der")
            .expect("Cannot read RSA keypair");
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState::new(rsa_keys, exposed_host)))
                .service(web::resource("/").route(web::get().to(keys))),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let response_body = test::read_body(resp).await;
        let body_str = str::from_utf8(&response_body)
            .unwrap_or("Error with parsing result from bytes to string");

        let p: Value = serde_json::from_str(body_str).unwrap();
        println!("Value : {:?}", p);
        assert_eq!(p["keys"][0]["e"], json!("AQAB"));

        Ok(())
    }
}
