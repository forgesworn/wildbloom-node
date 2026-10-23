//! Opt-in ICE configuration issuer: a currently granted device exchanges one
//! fresh NIP-98 request for two entries, one for itself and one for the
//! verified person at the other end of a direct send.  If any configured URL
//! is TURN, each entry holds short-lived TURN REST credentials.  If every URL
//! is STUN, nothing is minted and no secret is held: both entries carry the
//! URLs with an empty username and credential.
//!
//! Credentials use coturn's `use-auth-secret` form: the username is
//! `<expires>:<label>` and the credential is the padded base64 HMAC-SHA1 of the
//! username under the shared `static-auth-secret`.  The label is 16 fresh
//! random bytes per credential, so the TURN server learns nothing that names
//! the device, the request or a relay session.
//!
//! The shared secret never leaves this module except as HMAC input.  It is
//! never logged, echoed or returned.
use super::{
    ApiError, Grants, cors,
    device_auth::{DeviceAuth, Refusals},
    no_store,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha1::Sha1;
use std::{collections::BTreeSet, ffi::OsString, path::Path, sync::Arc};

pub const TURN_PATH: &str = "turn/v1/credentials";
/// Environment form of the shared secret.  Child processes never inherit it;
/// prefer `--turn-secret-file`.
pub const SECRET_ENV: &str = "WILDBLOOM_TURN_SECRET";
/// Lifetime of every credential, from the moment it is issued: 15 minutes,
/// which covers a direct send's 600-second session with room to spare,
/// because Drop asks for credentials just before it opens the session.
pub const CREDENTIAL_TTL: u64 = 15 * 60;
/// Per-device issuance budget within any rolling hour, separate from the
/// pairing issuer's.
pub const RATE_LIMIT: u32 = 30;
pub const MAX_URLS: usize = 4;
pub const MAX_URL_BYTES: usize = 256;
pub const MIN_SECRET_BYTES: usize = 32;
pub const MAX_SECRET_BYTES: usize = 256;
const LABEL_BYTES: usize = 16;
const SCHEMES: [&str; 3] = ["stun:", "turn:", "turns:"];
static REFUSALS: Refusals = Refusals {
    unauthorised: "TURN credential request is not authorised",
    spent: "TURN credential budget is spent",
    replayed: "TURN credential request was already used",
};

/// coturn's `static-auth-secret`.  Debug output is redacted.
#[derive(Clone)]
pub struct TurnSecret(Arc<str>);

impl std::fmt::Debug for TurnSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TurnSecret([redacted])")
    }
}

impl TurnSecret {
    /// Strip exactly one trailing `\n` or `\r\n`, then require 32 to 256
    /// bytes of printable ASCII (`!` to `~`) other than `"`, `'` and `#`.
    /// Anything else is refused rather than trimmed, so the node never signs
    /// with a secret that differs from the line coturn reads.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let value = value
            .strip_suffix("\r\n")
            .or_else(|| value.strip_suffix('\n'))
            .unwrap_or(value);
        if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&value.len()) {
            return Err("the TURN secret must be 32 to 256 bytes");
        }
        if !value
            .bytes()
            .all(|byte| matches!(byte, b'!'..=b'~') && !matches!(byte, b'"' | b'\'' | b'#'))
        {
            return Err(
                "the TURN secret must be printable ASCII without spaces, quotes or #, with at most one trailing newline",
            );
        }
        Ok(Self(Arc::from(value)))
    }

    pub fn from_file(path: &Path) -> Result<Self, &'static str> {
        let bytes = wildbloom_checkout::read_private_file(path)
            .map_err(|_| "the TURN secret file must be an absolute, private (0600) regular file")?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "the TURN secret file is not ASCII")?;
        Self::parse(text)
    }

    /// Exactly one source: the file or the environment variable.
    pub fn from_sources(file: Option<&Path>, env: Option<OsString>) -> Result<Self, &'static str> {
        match (file, env) {
            (Some(path), None) => Self::from_file(path),
            (None, Some(value)) => {
                Self::parse(value.to_str().ok_or("WILDBLOOM_TURN_SECRET is not ASCII")?)
            }
            _ => Err(
                "--turn-issuer needs exactly one of --turn-secret-file or WILDBLOOM_TURN_SECRET",
            ),
        }
    }

    /// coturn's TURN REST credential: padded base64 of HMAC-SHA1(secret, username).
    pub fn credential(&self, username: &str) -> Option<String> {
        let mut mac = Hmac::<Sha1>::new_from_slice(self.0.as_bytes()).ok()?;
        mac.update(username.as_bytes());
        Some(STANDARD.encode(mac.finalize().into_bytes()))
    }
}

/// Validate the configured ICE URLs against the direct-send `ice` entry: 1 to
/// 4 distinct `stun:`, `turn:` or `turns:` URLs of at most 256 bytes of
/// printable ASCII (no spaces, quotes or backslashes).  STUN alone is valid;
/// see [`has_turn_url`] for when a secret is needed.
pub fn ice_urls(urls: &[String]) -> Result<Vec<String>, &'static str> {
    if urls.is_empty() || urls.len() > MAX_URLS {
        return Err("--turn-url must be given 1 to 4 times");
    }
    for url in urls {
        let rest = SCHEMES
            .iter()
            .find_map(|scheme| url.strip_prefix(scheme))
            .ok_or("each --turn-url must start with stun:, turn: or turns:")?;
        if rest.is_empty()
            || url.len() > MAX_URL_BYTES
            || !url
                .bytes()
                .all(|byte| matches!(byte, b'!'..=b'~') && !matches!(byte, b'"' | b'\\'))
        {
            return Err(
                "each --turn-url must be at most 256 bytes of printable ASCII without spaces, quotes or backslashes",
            );
        }
    }
    if urls.iter().collect::<BTreeSet<_>>().len() != urls.len() {
        return Err("--turn-url values must be distinct");
    }
    Ok(urls.to_vec())
}

/// Whether any URL is `turn:` or `turns:`, which is when credentials are
/// minted and the shared secret is required.
pub fn has_turn_url(urls: &[String]) -> bool {
    urls.iter()
        .any(|url| url.starts_with("turn:") || url.starts_with("turns:"))
}

/// One entry of the direct-send `ice` list, members in canonical order.
/// `Debug` hides the username and credential.
#[derive(Serialize)]
pub struct IceServer {
    pub credential: String,
    pub urls: Vec<String>,
    pub username: String,
}

impl std::fmt::Debug for IceServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IceServer")
            .field("urls", &self.urls)
            .finish_non_exhaustive()
    }
}

/// `own` is for the caller, `peer` for the verified person at the other end.
/// `Debug` shows only the expiry and the URLs.
#[derive(Debug, Serialize)]
pub struct TurnCredentials {
    pub expires: u64,
    pub own: IceServer,
    pub peer: IceServer,
}

#[derive(Clone)]
pub struct TurnIssuer {
    auth: DeviceAuth,
    urls: Arc<[String]>,
    /// Present exactly when a URL is TURN.
    secret: Option<TurnSecret>,
}

impl TurnIssuer {
    /// `urls` must already have passed [`ice_urls`]. `secret` is needed if
    /// and only if [`has_turn_url`] holds for them; a TURN issuer without one
    /// answers 503.
    pub fn new(grants: Grants, urls: Vec<String>, secret: Option<TurnSecret>) -> Self {
        Self {
            auth: DeviceAuth::new(grants, TURN_PATH, RATE_LIMIT, &REFUSALS),
            urls: Arc::from(urls),
            secret,
        }
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route(&format!("/{TURN_PATH}"), post(issue))
            .with_state(self.clone())
            .layer(cors(&[Method::POST]))
    }

    fn mint(&self, expires: u64) -> Result<IceServer, ApiError> {
        let unavailable = || {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "TURN credentials are unavailable",
            )
        };
        // STUN alone: nothing to mint, so no label and no credential.
        if !has_turn_url(&self.urls) {
            return Ok(IceServer {
                credential: String::new(),
                urls: self.urls.to_vec(),
                username: String::new(),
            });
        }
        let secret = self.secret.as_ref().ok_or_else(unavailable)?;
        let mut label = [0_u8; LABEL_BYTES];
        getrandom::fill(&mut label).map_err(|_| unavailable())?;
        let username = format!("{expires}:{}", URL_SAFE_NO_PAD.encode(label));
        let credential = secret.credential(&username).ok_or_else(unavailable)?;
        Ok(IceServer {
            credential,
            urls: self.urls.to_vec(),
            username,
        })
    }
}

async fn issue(State(issuer): State<TurnIssuer>, request: Request<Body>) -> Response {
    let result = async {
        issuer.auth.authorise(request).await?;
        let expires = issuer.auth.now().saturating_add(CREDENTIAL_TTL);
        Ok::<_, ApiError>(TurnCredentials {
            expires,
            own: issuer.mint(expires)?,
            peer: issuer.mint(expires)?,
        })
    }
    .await;
    match result {
        Ok(credentials) => {
            tracing::info!("issued a pair of ICE configurations");
            let mut response = (StatusCode::CREATED, Json(credentials)).into_response();
            no_store(&mut response);
            response
        }
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic: 36 bytes of printable ASCII.
    const SECRET: &str = "synthetic-wildbloom-turn-secret-0001";
    /// The direct-send vector's example username.
    const USERNAME: &str = "1800003600:dGVzdC1sYWJlbA";
    /// Computed independently with Python's standard library:
    /// python3 -c 'import hmac,hashlib,base64;print(base64.b64encode(hmac.new(b"synthetic-wildbloom-turn-secret-0001",b"1800003600:dGVzdC1sYWJlbA",hashlib.sha1).digest()).decode())'
    /// (prints +6BIq3pAPedG8tQLugmFVhUF7K4=; openssl dgst -sha1 -hmac agrees).
    const EXPECTED: &str = "+6BIq3pAPedG8tQLugmFVhUF7K4=";

    #[test]
    fn credentials_match_an_independent_hmac_sha1() {
        let secret = TurnSecret::parse(SECRET).unwrap();
        assert_eq!(secret.credential(USERNAME).unwrap(), EXPECTED);
        // The trim rule reaches the HMAC key: a file or variable ending in
        // one newline signs exactly as the bare secret does.
        for suffixed in [format!("{SECRET}\n"), format!("{SECRET}\r\n")] {
            let secret = TurnSecret::parse(&suffixed).unwrap();
            assert_eq!(secret.credential(USERNAME).unwrap(), EXPECTED);
        }
        assert_ne!(
            TurnSecret::parse(&format!("{SECRET}x"))
                .unwrap()
                .credential(USERNAME)
                .unwrap(),
            EXPECTED
        );
    }

    #[test]
    fn debug_never_shows_a_credential_or_username() {
        let server = || IceServer {
            credential: EXPECTED.to_owned(),
            urls: vec!["turn:turn.example.net:3478?transport=udp".to_owned()],
            username: USERNAME.to_owned(),
        };
        let credentials = TurnCredentials {
            expires: 1_800_003_600,
            own: server(),
            peer: server(),
        };
        for printed in [
            format!("{:?}", server()),
            format!("{credentials:?}"),
            format!("{credentials:#?}"),
        ] {
            assert!(!printed.contains(EXPECTED), "{printed}");
            assert!(!printed.contains("dGVzdC1sYWJlbA"), "{printed}");
            assert!(printed.contains("turn.example.net"), "{printed}");
        }
    }

    #[test]
    fn secrets_follow_the_exact_trim_rule() {
        let base = "a".repeat(MIN_SECRET_BYTES);
        assert!(TurnSecret::parse(&base).is_ok());
        assert!(TurnSecret::parse(&"a".repeat(MIN_SECRET_BYTES - 1)).is_err());
        assert!(TurnSecret::parse(&"a".repeat(MAX_SECRET_BYTES)).is_ok());
        assert!(TurnSecret::parse(&"a".repeat(MAX_SECRET_BYTES + 1)).is_err());
        assert!(TurnSecret::parse(&format!("{}\n", "a".repeat(MIN_SECRET_BYTES - 1))).is_err());
        // Every printable character other than quotes and # is allowed.
        let printable = (b'!'..=b'~')
            .filter(|byte| !matches!(byte, b'"' | b'\'' | b'#'))
            .map(char::from)
            .collect::<String>();
        assert!(TurnSecret::parse(&printable).is_ok());
        for refused in [
            format!("{base}\n\n"),
            format!("{base}\r\n\n"),
            format!("{base}\n\r\n"),
            format!("{base}\r"),
            format!("{base} "),
            format!(" {base}"),
            format!("\n{base}"),
            format!("{base}\t"),
            format!("aaaa aaaa{base}"),
            format!("{base}\""),
            format!("{base}'"),
            format!("{base}#comment"),
            format!("{base}é"),
            format!("{base}\u{0}"),
            String::new(),
        ] {
            assert!(TurnSecret::parse(&refused).is_err(), "{refused:?}");
        }
        let secret = TurnSecret::parse(SECRET).unwrap();
        assert!(!format!("{secret:?}").contains(SECRET));
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_must_be_absolute_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("turn-secret");
        std::fs::write(&path, format!("{SECRET}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let secret = TurnSecret::from_file(&path).unwrap();
        assert_eq!(secret.credential(USERNAME).unwrap(), EXPECTED);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(TurnSecret::from_file(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o604)).unwrap();
        assert!(TurnSecret::from_file(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(TurnSecret::from_file(Path::new("turn-secret")).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(TurnSecret::from_file(&link).is_err());
        assert!(TurnSecret::from_file(&dir.path().join("missing")).is_err());

        let doubled = dir.path().join("doubled");
        std::fs::write(&doubled, format!("{SECRET}\n\n")).unwrap();
        std::fs::set_permissions(&doubled, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(TurnSecret::from_file(&doubled).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn exactly_one_secret_source_is_accepted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("turn-secret");
        std::fs::write(&path, SECRET).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(TurnSecret::from_sources(Some(&path), None).is_ok());
        assert!(TurnSecret::from_sources(None, Some(OsString::from(SECRET))).is_ok());
        assert!(
            TurnSecret::from_sources(None, Some(OsString::from(format!("{SECRET}\n")))).is_ok()
        );
        assert!(TurnSecret::from_sources(Some(&path), Some(OsString::from(SECRET))).is_err());
        assert!(TurnSecret::from_sources(None, None).is_err());
        assert!(TurnSecret::from_sources(None, Some(OsString::new())).is_err());
    }

    #[test]
    fn a_secret_is_needed_only_when_a_url_is_turn() {
        let owned = |urls: &[&str]| urls.iter().map(|url| (*url).to_owned()).collect::<Vec<_>>();
        assert!(!has_turn_url(&owned(&["stun:stun.example.net:3478"])));
        assert!(has_turn_url(&owned(&[
            "stun:turn.example.net:3478",
            "turn:turn.example.net:3478"
        ])));
        assert!(has_turn_url(&owned(&["turns:turn.example.net:5349"])));
    }

    #[test]
    fn ice_urls_follow_the_direct_send_rules() {
        let owned = |urls: &[&str]| urls.iter().map(|url| (*url).to_owned()).collect::<Vec<_>>();
        for accepted in [
            &["turn:turn.example.net:3478"][..],
            &["turns:turn.example.net:5349?transport=tcp"][..],
            &["stun:stun.example.net:3478"][..],
            &[
                "stun:turn.example.net:3478",
                "turn:turn.example.net:3478?transport=udp",
                "turn:turn.example.net:3478?transport=tcp",
                "turns:turn.example.net:5349?transport=tcp",
            ][..],
        ] {
            assert_eq!(ice_urls(&owned(accepted)).unwrap(), owned(accepted));
        }
        let longest = format!("turn:{}", "a".repeat(MAX_URL_BYTES - 5));
        assert!(ice_urls(std::slice::from_ref(&longest)).is_ok());
        let too_long = format!("{longest}a");
        for refused in [
            Vec::new(),
            owned(&[
                "turn:a.example",
                "turn:b.example",
                "turn:c.example",
                "turn:d.example",
                "turn:e.example",
            ]),
            owned(&["http://turn.example.net/"]),
            owned(&["TURN:turn.example.net"]),
            owned(&["turn:"]),
            owned(&["turn turn.example.net"]),
            owned(&["turn:turn.example.net:3478 "]),
            owned(&["turn:turn.example.net\n"]),
            owned(&["turn:turn.example.net\"x"]),
            owned(&["turn:turn.example.net\\x"]),
            owned(&["turn:tûrn.example.net"]),
            owned(&["turn:turn.example.net", "turn:turn.example.net"]),
            vec![too_long],
        ] {
            assert!(ice_urls(&refused).is_err(), "{refused:?}");
        }
    }
}
