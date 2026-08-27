//! In-memory store for issued authorization codes (RFC 6749 code flow + RFC 7636 PKCE).
//!
//! Codes are single use and short lived. There is no persistence: restarting the
//! service invalidates every outstanding code, which is fine for a test IdP.
use data_encoding::BASE64URL_NOPAD;
use ring::digest;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// How long an authorization code stays exchangeable.
pub const CODE_TTL_SECS: u64 = 600;

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

/// Everything captured at the login screen, held until the code is exchanged.
#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub nonce: Option<String>,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: String,
    /// The claim set typed into the login form, verbatim.
    pub claims: Map<String, Value>,
    pub expires_at: u64,
}

impl AuthCode {
    /// Check a `code_verifier` against the stored challenge (RFC 7636 section 4.6).
    ///
    /// A code stored without a challenge accepts any verifier: PKCE is optional
    /// here so plain code-flow clients keep working.
    pub fn verify_pkce(&self, code_verifier: Option<&str>) -> bool {
        let challenge = match &self.code_challenge {
            None => return true,
            Some(c) => c,
        };
        let verifier = match code_verifier {
            None => return false,
            Some(v) => v,
        };
        match self.code_challenge_method.as_str() {
            "S256" => {
                let digest = digest::digest(&digest::SHA256, verifier.as_bytes());
                BASE64URL_NOPAD.encode(digest.as_ref()) == *challenge
            }
            // "plain" and anything else we were handed; being lenient is the point.
            _ => verifier == challenge,
        }
    }
}

#[derive(Default)]
pub struct AuthCodeStore {
    codes: Mutex<HashMap<String, AuthCode>>,
}

impl AuthCodeStore {
    /// Store a code, dropping any that have expired in the meantime so a long
    /// running instance does not grow without bound.
    pub fn insert(&self, code: String, entry: AuthCode) {
        let mut codes = self.codes.lock().expect("auth code store poisoned");
        let now = now_secs();
        codes.retain(|_, existing| existing.expires_at > now);
        codes.insert(code, entry);
    }

    /// Look a code up without consuming it. Returns `None` when it is unknown or
    /// expired.
    pub fn get(&self, code: &str) -> Option<AuthCode> {
        let codes = self.codes.lock().expect("auth code store poisoned");
        codes
            .get(code)
            .filter(|entry| entry.expires_at > now_secs())
            .cloned()
    }

    /// Retire a code once it has been exchanged successfully.
    ///
    /// Deliberately separate from [`AuthCodeStore::get`]: a rejected
    /// `code_verifier` leaves the code usable so that a developer debugging their
    /// PKCE implementation can fix the verifier and retry the same code instead of
    /// walking through the login screen again.
    pub fn consume(&self, code: &str) {
        let mut codes = self.codes.lock().expect("auth code store poisoned");
        codes.remove(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_with(challenge: Option<&str>, method: &str) -> AuthCode {
        AuthCode {
            client_id: "test-client".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            nonce: None,
            scope: None,
            code_challenge: challenge.map(str::to_string),
            code_challenge_method: method.to_string(),
            claims: Map::new(),
            expires_at: now_secs() + CODE_TTL_SECS,
        }
    }

    // Test vector from RFC 7636 appendix B.
    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn s256_accepts_matching_verifier() {
        let code = code_with(Some(RFC_CHALLENGE), "S256");
        assert!(code.verify_pkce(Some(RFC_VERIFIER)));
    }

    #[test]
    fn s256_rejects_wrong_or_missing_verifier() {
        let code = code_with(Some(RFC_CHALLENGE), "S256");
        assert!(!code.verify_pkce(Some("not-the-verifier")));
        assert!(!code.verify_pkce(None));
    }

    #[test]
    fn plain_compares_verbatim() {
        let code = code_with(Some("just-a-string"), "plain");
        assert!(code.verify_pkce(Some("just-a-string")));
        assert!(!code.verify_pkce(Some("Just-A-String")));
    }

    #[test]
    fn without_challenge_any_verifier_passes() {
        let code = code_with(None, "plain");
        assert!(code.verify_pkce(None));
        assert!(code.verify_pkce(Some("whatever")));
    }

    #[test]
    fn codes_survive_a_lookup_but_not_a_consume() {
        let store = AuthCodeStore::default();
        store.insert("abc".to_string(), code_with(None, "plain"));
        assert!(store.get("abc").is_some());
        assert!(store.get("abc").is_some());
        store.consume("abc");
        assert!(store.get("abc").is_none());
    }

    #[test]
    fn expired_codes_are_not_returned() {
        let store = AuthCodeStore::default();
        let mut expired = code_with(None, "plain");
        expired.expires_at = now_secs() - 1;
        store.insert("stale".to_string(), expired);
        assert!(store.get("stale").is_none());
    }
}
