use data_encoding::BASE64URL_NOPAD;
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// A user offered on the login screen: the claim set that logging in as them signs.
pub type User = Map<String, Value>;

/// Claims that only describe the moment a token was minted. They are dropped from
/// encoded JWTs, which were minted in the past, so that logging in as a user
/// copied from a real token does not hand out an already expired one.
const TIME_CLAIMS: [&str; 4] = ["iat", "exp", "nbf", "auth_time"];

/// Load the users offered on the login screen.
///
/// `path` is either a JSON file or a directory, in which case every `*.json` file
/// in it is read in file name order. A directory is what makes this easy to mount
/// in docker compose: the files can be edited on the host without the bind mount
/// going stale, which a single-file mount does as soon as an editor replaces it.
///
/// Each file holds a JSON array. An entry is either a claim set (an object) or an
/// encoded JWT, of which only the payload is used; its signature is not checked.
pub fn load(path: &Path) -> Result<Vec<User>, String> {
    let mut users = Vec::new();
    for file in json_files(path)? {
        let text = fs::read_to_string(&file)
            .map_err(|err| format!("Cannot read users file {}: {}", file.display(), err))?;
        users
            .extend(parse(&text).map_err(|err| format!("Users file {}: {}", file.display(), err))?);
    }
    Ok(users)
}

fn json_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    if !path.is_dir() {
        return Ok(vec![path.to_path_buf()]);
    }
    let entries = fs::read_dir(path)
        .map_err(|err| format!("Cannot read users folder {}: {}", path.display(), err))?;
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|file| file.is_file() && file.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    Ok(files)
}

fn parse(text: &str) -> Result<Vec<User>, String> {
    let entries: Vec<Value> =
        serde_json::from_str(text).map_err(|err| format!("not a JSON array: {}", err))?;
    entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let user = match entry {
                Value::Object(claims) => claims,
                Value::String(jwt) => decode_jwt_payload(&jwt)
                    .map_err(|err| format!("entry {} is not a readable JWT: {}", index, err))?,
                other => {
                    return Err(format!(
                        "entry {} is neither a claim set nor a JWT: {}",
                        index, other
                    ))
                }
            };
            // The login handler refuses to build a token without a subject, so
            // catch it at startup rather than at the first click.
            match user.get("sub").and_then(Value::as_str) {
                Some(sub) if !sub.is_empty() => Ok(user),
                _ => Err(format!("entry {} has no string \"sub\" claim", index)),
            }
        })
        .collect()
}

fn decode_jwt_payload(jwt: &str) -> Result<User, String> {
    let payload = jwt
        .trim()
        .split('.')
        .nth(1)
        .ok_or("expected three dot separated parts")?;
    let bytes = BASE64URL_NOPAD
        .decode(payload.trim_end_matches('=').as_bytes())
        .map_err(|err| err.to_string())?;
    let mut claims: User = serde_json::from_slice(&bytes).map_err(|err| err.to_string())?;
    for claim in TIME_CLAIMS {
        claims.remove(claim);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_claim_sets_are_used_verbatim() {
        let users = parse(r#"[{"sub": "a", "name": "Alice", "exp": 1, "groups": ["x"]}]"#).unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["exp"], json!(1));
        assert_eq!(users[0]["groups"], json!(["x"]));
    }

    #[test]
    fn test_encoded_jwt_contributes_its_payload_without_time_claims() {
        let payload = BASE64URL_NOPAD.encode(br#"{"sub":"b","name":"Bob","exp":1,"iat":1}"#);
        let users = parse(&format!(r#"["eyJhbGciOiJSUzI1NiJ9.{}.c2ln"]"#, payload)).unwrap();
        assert_eq!(users[0]["sub"], json!("b"));
        assert_eq!(users[0]["name"], json!("Bob"));
        assert!(!users[0].contains_key("exp"));
        assert!(!users[0].contains_key("iat"));
    }

    #[test]
    fn test_entries_without_subject_are_rejected() {
        assert!(parse(r#"[{"name": "Nobody"}]"#).is_err());
        assert!(parse(r#"[42]"#).is_err());
        assert!(parse(r#"{"sub": "not an array"}"#).is_err());
    }

    #[test]
    fn test_folder_is_read_in_file_name_order() {
        let dir = std::env::temp_dir().join(format!("fakeidp-users-{}", nanoid::nanoid!(8)));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("b.json"), r#"[{"sub": "second"}]"#).unwrap();
        fs::write(dir.join("a.json"), r#"[{"sub": "first"}]"#).unwrap();
        fs::write(dir.join("notes.txt"), "not json").unwrap();

        let users = load(&dir);
        fs::remove_dir_all(&dir).unwrap();

        let subjects: Vec<Value> = users.unwrap().iter().map(|u| u["sub"].clone()).collect();
        assert_eq!(subjects, vec![json!("first"), json!("second")]);
    }
}
