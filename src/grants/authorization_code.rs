//! RFC 6749 section 4.1.3 / RFC 7636 section 4.5: swap an authorization code for
//! the tokens that the login screen described.

use super::{token_response, Refusal, TokenRequest};
use crate::token::issue_tokens;
use crate::AppState;
use actix_web::HttpResponse;
use serde_json::json;

pub fn exchange(state: &AppState, form: &TokenRequest) -> Result<HttpResponse, Refusal> {
    let code = form
        .get("code")
        .ok_or_else(|| Refusal::invalid_request("Missing code"))?;

    // Looked up but not yet retired: a request that fails validation below leaves
    // the code exchangeable so it can be retried with a corrected verifier.
    let entry = state.auth_codes.get(code).ok_or_else(|| {
        Refusal::invalid_grant("Authorization code is unknown, already used or expired")
    })?;

    // These two are the only things we are strict about, because a client that
    // gets them wrong is misconfigured rather than exercising an edge case.
    if let Some(redirect_uri) = form.get("redirect_uri") {
        if redirect_uri != entry.redirect_uri {
            return Err(Refusal::invalid_grant(
                "redirect_uri does not match the one used at the authorization endpoint",
            ));
        }
    }
    if let Some(client_id) = form.client_id() {
        if client_id != entry.client_id {
            return Err(Refusal::invalid_grant(
                "client_id does not match the one used at the authorization endpoint",
            ));
        }
    }

    if !entry.verify_pkce(form.get("code_verifier")) {
        return Err(Refusal::invalid_grant(
            "code_verifier does not match the code_challenge",
        ));
    }

    // Validation passed, so the code is spent.
    state.auth_codes.consume(code);

    let tokens = issue_tokens(
        &state.rsa_key_pair,
        &state.exposed_host,
        &entry.client_id,
        &entry.claims,
        entry.nonce.as_deref(),
        entry.scope.as_deref(),
    );

    Ok(token_response(json!({
        "access_token": tokens.access_token,
        "id_token": tokens.id_token,
        "token_type": "Bearer",
        "expires_in": tokens.expires_in,
        "scope": entry.scope.unwrap_or_else(|| "openid".to_string()),
    })))
}
