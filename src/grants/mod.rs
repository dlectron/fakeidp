//! The OAuth 2.0 token endpoint: `POST /token` with a form-encoded body.
//!
//! One module per grant. This one parses the request, works out which client is
//! calling, and dispatches on `grant_type`. The pieces the grants share (the
//! clients-file checks, the `aud` rule, the response shape) live here too.

pub mod authorization_code;
pub mod client_credentials;
pub mod token_exchange;

use crate::clients::{self, Client, Flow};
use crate::token::oauth_error;
use crate::AppState;
use actix_web::http::header::AUTHORIZATION;
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
use bytes::Bytes;
use data_encoding::{BASE64, BASE64_NOPAD};
use serde_json::{json, Map, Value};

pub const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

pub fn handle(state: &AppState, req: &HttpRequest, body: &Bytes) -> HttpResponse {
    dispatch(state, req, body).unwrap_or_else(Refusal::into_response)
}

fn dispatch(state: &AppState, req: &HttpRequest, body: &Bytes) -> Result<HttpResponse, Refusal> {
    let form = TokenRequest::parse(req, body)?;
    match form.get("grant_type") {
        Some("authorization_code") => authorization_code::exchange(state, &form),
        Some("client_credentials") => client_credentials::grant(state, &form),
        Some(TOKEN_EXCHANGE) => token_exchange::grant(state, &form),
        Some(other) => Err(Refusal::new(
            "unsupported_grant_type",
            format!(
                "Supported grant types are authorization_code, client_credentials and {}, got {}",
                TOKEN_EXCHANGE, other
            ),
        )),
        None => Err(Refusal::invalid_request("Missing grant_type")),
    }
}

/// A refusal at the token endpoint: the RFC 6749 section 5.2 error code and its
/// description. It becomes the response once the grant has returned, which lets
/// the grants use `?` and keeps the `Err` small.
#[derive(Debug)]
pub struct Refusal {
    error: &'static str,
    description: String,
}

impl Refusal {
    pub fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            description: description.into(),
        }
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new("invalid_request", description)
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new("invalid_grant", description)
    }

    fn into_response(self) -> HttpResponse {
        oauth_error(StatusCode::BAD_REQUEST, self.error, &self.description)
    }
}

/// The parsed form, plus the client it names.
///
/// Kept as the list of pairs rather than a map so that a parameter given twice
/// can be seen: Rauthy takes one `resource`, and silently using the last one
/// would hide a client that sends two.
pub struct TokenRequest {
    fields: Vec<(String, String)>,
    client_id: Option<String>,
}

impl TokenRequest {
    fn parse(req: &HttpRequest, body: &Bytes) -> Result<Self, Refusal> {
        let fields =
            serde_urlencoded::from_bytes::<Vec<(String, String)>>(body).map_err(|err| {
                Refusal::invalid_request(format!(
                    "Request body is not valid form encoding: {}",
                    err
                ))
            })?;
        let mut form = Self {
            fields,
            client_id: None,
        };

        // The client may say who it is in the Authorization header
        // (client_secret_basic), in the form (client_secret_post, or a public
        // client), or both. Both with different ids is a misconfigured client.
        let basic = basic_client_id(req)?;
        let posted = form.single("client_id")?.map(str::to_string);
        form.client_id = match (basic, posted) {
            (Some(basic), Some(posted)) if basic != posted => {
                return Err(Refusal::invalid_request(
                    "client_id in the Authorization header and in the form differ",
                ))
            }
            (Some(basic), _) => Some(basic),
            (None, posted) => posted,
        };
        Ok(form)
    }

    /// The first non-empty value of a field.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(key, value)| key == name && !value.is_empty())
            .map(|(_, value)| value.as_str())
    }

    /// The value of a field that may be given at most once.
    pub fn single(&self, name: &str) -> Result<Option<&str>, Refusal> {
        if self.fields.iter().filter(|(key, _)| key == name).count() > 1 {
            return Err(Refusal::invalid_request(format!(
                "{} must not be given more than once",
                name
            )));
        }
        Ok(self.get(name))
    }

    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }
}

/// The client id of an `Authorization: Basic` header, if there is one. The secret
/// next to it is read and ignored: this IdP authenticates nobody.
fn basic_client_id(req: &HttpRequest) -> Result<Option<String>, Refusal> {
    let header = match req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        Some(header) => header,
        None => return Ok(None),
    };
    let encoded = match header.split_once(' ') {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("basic") => rest.trim(),
        // A Bearer header or something else entirely is not client authentication.
        _ => return Ok(None),
    };
    let decoded = BASE64
        .decode(encoded.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(encoded.as_bytes()))
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| {
            Refusal::invalid_request("Authorization header is not valid Basic credentials")
        })?;
    let (client_id, _secret) = decoded.split_once(':').unwrap_or((&decoded, ""));
    // RFC 6749 section 2.3.1: both halves are form-urlencoded before the base64.
    let client_id = form_decode(client_id).ok_or_else(|| {
        Refusal::invalid_request("client_id in the Authorization header is not url encoded")
    })?;
    Ok(Some(client_id).filter(|id| !id.is_empty()))
}

fn form_decode(value: &str) -> Option<String> {
    serde_urlencoded::from_str::<Vec<(String, String)>>(&format!("v={}", value))
        .ok()?
        .into_iter()
        .next()
        .map(|(_, value)| value)
}

/// The grant check a clients file can ask for. A client that is not in the file
/// passes, and is handed back as `None` so the caller knows it has no claims
/// and no resource list.
pub fn check_flow<'a>(
    state: &'a AppState,
    client_id: &str,
    flow: Flow,
) -> Result<Option<&'a Client>, Refusal> {
    let client = clients::find(&state.clients, client_id);
    if let Some(client) = client {
        if !client.allows_flow(flow) {
            return Err(Refusal::new(
                "unauthorized_client",
                format!(
                    "Client {} is not allowed the {} grant",
                    client_id,
                    flow.name()
                ),
            ));
        }
    }
    Ok(client)
}

/// RFC 8707: a target not on the client's `allowed_resources` is refused. Only a
/// file entry has such a list.
pub fn check_target(client: Option<&Client>, target: Option<&str>) -> Result<(), Refusal> {
    if let (Some(client), Some(target)) = (client, target) {
        if !client.allows_resource(target) {
            return Err(Refusal::new(
                "invalid_target",
                format!(
                    "{} is not among the allowed resources of client {}",
                    target, client.client_id
                ),
            ));
        }
    }
    Ok(())
}

/// The `aud` of a token, as Rauthy builds it (RFC 8707): the client itself, plus
/// the target when one was named and it is not the client already. One value is
/// a string, two are an array.
pub fn audience(client_id: &str, target: Option<&str>) -> Value {
    match target {
        Some(target) if target != client_id => json!([client_id, target]),
        _ => json!(client_id),
    }
}

/// How long the token is good for, measured from `iat`. The claim set may have
/// been given an `exp` of its own by the clients file.
pub fn expires_in(claims: &Map<String, Value>, iat: u64) -> u64 {
    claims
        .get("exp")
        .and_then(Value::as_u64)
        .map(|exp| exp.saturating_sub(iat))
        .unwrap_or(crate::token::TOKEN_TTL_SECS)
}

/// RFC 6749 section 5.1: a token response is not to be cached.
pub fn token_response(body: Value) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Pragma", "no-cache"))
        .json(body)
}

#[cfg(test)]
pub(crate) mod testing {
    use crate::clients::Client;
    use crate::token::create_token;
    use crate::AppState;
    use actix_web::{test, web, App, Error};
    use biscuit::jws::Secret;
    use data_encoding::BASE64URL_NOPAD;
    use serde_json::Value;

    pub const EXPOSED_HOST: &str = "http://localhost:8080";

    pub fn test_keys() -> Secret {
        Secret::rsa_keypair_from_file("./keys/private_key.der").expect("Cannot read RSA keypair")
    }

    pub fn clients(json: &str) -> Vec<Client> {
        serde_json::from_str(json).unwrap()
    }

    /// The token endpoint with the given clients file loaded.
    pub async fn app(
        clients: Vec<Client>,
    ) -> impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = Error,
    > {
        let state = AppState::new(test_keys(), EXPOSED_HOST.to_string()).with_clients(clients);
        test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .service(web::resource("/token").route(web::post().to(create_token))),
        )
        .await
    }

    pub fn token_request(body: &str) -> actix_http::Request {
        token_request_with(body, &[])
    }

    pub fn token_request_with(body: &str, headers: &[(&str, &str)]) -> actix_http::Request {
        let mut req = test::TestRequest::post()
            .uri("/token")
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"));
        for (name, value) in headers {
            req = req.insert_header((name.to_string(), value.to_string()));
        }
        req.set_payload(body.to_string()).to_request()
    }

    /// Decode the payload of a JWT without verifying it.
    pub fn decode_claims(jwt: &str) -> Value {
        let payload = jwt.split('.').nth(1).expect("jwt has no payload");
        let decoded = BASE64URL_NOPAD.decode(payload.as_bytes()).unwrap();
        serde_json::from_slice(&decoded).unwrap()
    }

    /// Flip the last character of the signature, which is enough for RS256 to
    /// refuse it.
    pub fn tamper(jwt: &str) -> String {
        let last = if jwt.ends_with('A') { 'B' } else { 'A' };
        format!("{}{}", &jwt[..jwt.len() - 1], last)
    }
}
