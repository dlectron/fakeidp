//! The clients file: `-c`/`--clients` (env `CLIENTS`), a JSON file or a folder of
//! `*.json` files, read once at startup like the users file.
//!
//! A client that is not in the file is allowed every grant and every resource and
//! gets the default claims. The file exists to give a client its own claims, and
//! to provoke the refusals Rauthy gives a client that lacks a grant or asks for a
//! resource it may not have. Nothing in it authenticates anyone.

use crate::users::json_files;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::fs;
use std::path::Path;

/// The grants a client can be restricted to in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flow {
    ClientCredentials,
    TokenExchange,
}

impl Flow {
    pub fn name(self) -> &'static str {
        match self {
            Flow::ClientCredentials => "client_credentials",
            Flow::TokenExchange => "token_exchange",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Client {
    pub client_id: String,
    /// Put into every client-credentials token of this client, over the defaults.
    /// Rauthy refuses custom claims that collide with `sub`, `iss` and the like;
    /// here they win, because minting a token the client should reject is a test.
    #[serde(default)]
    pub claims: Map<String, Value>,
    /// Left out means every grant is allowed.
    #[serde(default)]
    flows: Option<Vec<Flow>>,
    /// Left out means every `resource`/`audience` is allowed.
    #[serde(default)]
    allowed_resources: Option<Vec<String>>,
}

impl Client {
    pub fn allows_flow(&self, flow: Flow) -> bool {
        self.flows
            .as_ref()
            .is_none_or(|flows| flows.contains(&flow))
    }

    pub fn allows_resource(&self, resource: &str) -> bool {
        self.allowed_resources
            .as_ref()
            .is_none_or(|allowed| allowed.iter().any(|a| a == resource))
    }
}

/// Load the clients file. `path` is a JSON file or a folder of `*.json` files, as
/// for the users file.
pub fn load(path: &Path) -> Result<Vec<Client>, String> {
    let mut clients = Vec::new();
    for file in json_files(path)? {
        let text = fs::read_to_string(&file)
            .map_err(|err| format!("Cannot read clients file {}: {}", file.display(), err))?;
        clients.extend(
            parse(&text).map_err(|err| format!("Clients file {}: {}", file.display(), err))?,
        );
    }
    Ok(clients)
}

pub fn find<'a>(clients: &'a [Client], client_id: &str) -> Option<&'a Client> {
    clients.iter().find(|client| client.client_id == client_id)
}

fn parse(text: &str) -> Result<Vec<Client>, String> {
    let entries: Vec<Value> =
        serde_json::from_str(text).map_err(|err| format!("not a JSON array: {}", err))?;
    entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let client: Client = serde_json::from_value(entry)
                .map_err(|err| format!("entry {} is not a client: {}", index, err))?;
            if client.client_id.is_empty() {
                return Err(format!("entry {} has an empty \"client_id\"", index));
            }
            Ok(client)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EXAMPLE: &str = r#"[
        {
            "client_id": "ampsflow-integration",
            "claims": { "name": "Ampsflow integration", "scope": "openid" },
            "flows": ["client_credentials", "token_exchange"],
            "allowed_resources": ["http://localhost:8083", "http://localhost:8084"]
        },
        { "client_id": "no-exchange", "flows": ["client_credentials"] },
        { "client_id": "anything" }
    ]"#;

    #[test]
    fn test_file_entries_restrict_flows_and_resources() {
        let clients = parse(EXAMPLE).unwrap();
        assert_eq!(clients.len(), 3);

        let integration = find(&clients, "ampsflow-integration").unwrap();
        assert_eq!(integration.claims["name"], json!("Ampsflow integration"));
        assert!(integration.allows_flow(Flow::TokenExchange));
        assert!(integration.allows_resource("http://localhost:8083"));
        assert!(!integration.allows_resource("http://localhost:9999"));

        let no_exchange = find(&clients, "no-exchange").unwrap();
        assert!(no_exchange.allows_flow(Flow::ClientCredentials));
        assert!(!no_exchange.allows_flow(Flow::TokenExchange));
        assert!(no_exchange.allows_resource("http://anywhere"));

        let anything = find(&clients, "anything").unwrap();
        assert!(anything.allows_flow(Flow::TokenExchange));
        assert!(anything.claims.is_empty());

        assert!(find(&clients, "unknown").is_none());
    }

    #[test]
    fn test_bad_entries_are_rejected() {
        assert!(parse(r#"{"client_id": "not an array"}"#).is_err());
        assert!(parse(r#"[{"claims": {}}]"#).is_err());
        assert!(parse(r#"[{"client_id": ""}]"#).is_err());
        assert!(parse(r#"[{"client_id": "x", "flows": ["password"]}]"#).is_err());
        assert!(parse(r#"["a-jwt-is-not-a-client"]"#).is_err());
    }
}
