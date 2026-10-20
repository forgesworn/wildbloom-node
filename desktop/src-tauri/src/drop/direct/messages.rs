//! The `wildbloom-direct/1` messages (`docs/PROTOCOL.md`, "Direct send"),
//! carried one per `foregather-exchange/1` message.  Every message is one
//! JSON object in strict canonical form, so a reader parses it, checks it,
//! serialises it again with [`canonical`] and compares the bytes.  The rules
//! and their order follow the page's reader (`src/direct/messages.ts` in the
//! web repository), so both ends refuse the same messages with the same
//! `stop` reason.
//!
//! Nothing here logs a message: `invite` carries a TURN credential and
//! `answer` the envelope key.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use wildbloom_envelope::InputKey;

/// The profile name.
pub const PROFILE: &str = "wildbloom-direct/1";
/// The largest message: the exchange profile's payload bound.
pub const MESSAGE_BYTES: usize = 16_379;
/// Messages each side may send, indexes 0 to 7.
pub const MESSAGES_PER_SIDE: usize = 8;
/// ICE restarts Drop may make, at its indexes 2 to 6.
pub const RESTARTS: usize = 5;
/// The largest session description.
pub const SDP_BYTES: usize = 8_000;
pub const ICE_SERVERS: usize = 4;
pub const URLS_PER_SERVER: usize = 4;
pub const URL_BYTES: usize = 256;
pub const CREDENTIAL_BYTES: usize = 256;
/// The largest file in v1, and the `max` Drop offers.
pub const MAX_FILE_BYTES: u64 = 250_000_000;
/// The refusal of a manifest larger than Drop's `max`.
pub const TOO_BIG: &str = "size is above max";
/// JavaScript's `Number.MAX_SAFE_INTEGER`.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Who sent a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Drop,
    Page,
}

/// What a `stop` says, and what a reader's refusal sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// A person stopped or closed the page.
    Cancelled,
    /// This end cannot use what the other offered.
    Unsupported,
    /// A protocol, connection or verification failure.
    Failed,
}

impl StopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Unsupported => "unsupported",
            Self::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "cancelled" => Some(Self::Cancelled),
            "unsupported" => Some(Self::Unsupported),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// One ICE server: exactly `{"credential","urls","username"}`.  The same
/// shape is a TURN credential from the node's issuer and an `ice` entry.
/// `Debug` hides the username and credential.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IceServer {
    pub credential: String,
    pub urls: Vec<String>,
    pub username: String,
}

impl std::fmt::Debug for IceServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceServer")
            .field("urls", &self.urls)
            .finish_non_exhaustive()
    }
}

/// ECMAScript `WhiteSpace` and `LineTerminator`: what `\s` matches in the
/// page's URL rule.
fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}')
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// A `stun:`, `turn:` or `turns:` URL of at most 256 bytes with no
/// whitespace.
pub fn valid_ice_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("stun:")
        .or_else(|| url.strip_prefix("turn:"))
        .or_else(|| url.strip_prefix("turns:"));
    rest.is_some_and(|rest| !rest.is_empty() && !rest.chars().any(is_js_whitespace))
        && url.len() <= URL_BYTES
}

pub fn is_turn_url(url: &str) -> bool {
    url.starts_with("turn:") || url.starts_with("turns:")
}

impl IceServer {
    /// The syntax rules of one `ice` entry: 1 to 4 URLs, and a username and
    /// credential of 1 to 256 bytes without control characters.
    pub fn well_formed(&self) -> bool {
        (1..=URLS_PER_SERVER).contains(&self.urls.len())
            && self.urls.iter().all(|url| valid_ice_url(url))
            && [&self.username, &self.credential].iter().all(|secret| {
                !secret.is_empty()
                    && secret.len() <= CREDENTIAL_BYTES
                    && !secret.chars().any(is_control)
            })
    }

    pub fn has_turn(&self) -> bool {
        self.urls.iter().any(|url| is_turn_url(url))
    }

    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("credential".into(), Value::String(self.credential.clone()));
        map.insert(
            "urls".into(),
            Value::Array(self.urls.iter().cloned().map(Value::String).collect()),
        );
        map.insert("username".into(), Value::String(self.username.clone()));
        Value::Object(map)
    }
}

impl Drop for IceServer {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.username);
        zeroize::Zeroize::zeroize(&mut self.credential);
    }
}

/// The file the page offers: exactly the metadata it will seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub size: u64,
    pub media_type: String,
}

/// One `wildbloom-direct/1` message.  `invite` is always `dir: "to-drop"`,
/// the only direction v1 specifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Invite {
        hide: bool,
        ice: Vec<IceServer>,
        id: String,
        max: u64,
    },
    Manifest(Manifest),
    Accept {
        sdp: String,
    },
    Decline,
    Answer {
        key: InputKey,
        sdp: String,
    },
    Restart {
        sdp: String,
    },
    RestartAnswer {
        sdp: String,
    },
    Stop {
        reason: StopReason,
    },
}

impl Message {
    pub fn event(&self) -> &'static str {
        match self {
            Self::Invite { .. } => "invite",
            Self::Manifest(_) => "manifest",
            Self::Accept { .. } => "accept",
            Self::Decline => "decline",
            Self::Answer { .. } => "answer",
            Self::Restart { .. } => "restart",
            Self::RestartAnswer { .. } => "restart-answer",
            Self::Stop { .. } => "stop",
        }
    }
}

// -------------------------------------------------------------- canonical form

/// Writes a string as the protocol requires: only `"`, `\` and U+0000 to
/// U+001F escaped, short escapes where JSON has them and lower-case `\u00xx`
/// otherwise; everything else, `/` and non-ASCII included, literal.  A Rust
/// string cannot hold a lone surrogate.
fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0}'..='\u{1f}' => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// The canonical text of `value`: no whitespace, members in ascending order
/// of their names (as UTF-16 code units, which is `Array.prototype.sort`'s
/// order and byte order for ASCII names), integers from 0 to 2^53 - 1 in
/// shortest form, booleans, and no `null`.  `None` for anything else.
pub fn canonical(value: &Value) -> Option<String> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Some(out)
}

fn write_value(out: &mut String, value: &Value) -> Option<()> {
    match value {
        Value::Null => return None,
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            let n = number.as_u64().filter(|n| *n <= MAX_SAFE_INTEGER)?;
            out.push_str(&n.to_string());
        }
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, &map[key])?;
            }
            out.push('}');
        }
    }
    Some(())
}

/// Why a message could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("the message breaks a rule of wildbloom-direct/1")]
    Invalid,
    #[error("the message is larger than the exchange carries")]
    TooLarge,
}

/// The bytes a sender puts on the exchange.  Every message is checked by the
/// same rules a reader applies, so Drop never sends what the page refuses.
pub fn encode(message: &Message) -> Result<Vec<u8>, EncodeError> {
    let mut map = Map::new();
    map.insert("event".into(), Value::String(message.event().into()));
    map.insert("v".into(), Value::from(1u64));
    let string = |text: &str| Value::String(text.to_owned());
    match message {
        Message::Invite { hide, ice, id, max } => {
            let ice_ok = (1..=ICE_SERVERS).contains(&ice.len())
                && ice.iter().all(IceServer::well_formed)
                && ice.iter().any(IceServer::has_turn);
            if !ice_ok || !canonical_id(id) || !(1..=MAX_FILE_BYTES).contains(max) {
                return Err(EncodeError::Invalid);
            }
            map.insert("dir".into(), string("to-drop"));
            map.insert("hide".into(), Value::Bool(*hide));
            map.insert(
                "ice".into(),
                Value::Array(ice.iter().map(IceServer::to_value).collect()),
            );
            map.insert("id".into(), string(id));
            map.insert("max".into(), Value::from(*max));
        }
        Message::Manifest(manifest) => {
            if !valid_name(&manifest.name)
                || !valid_media_type(&manifest.media_type)
                || manifest.size > MAX_SAFE_INTEGER
            {
                return Err(EncodeError::Invalid);
            }
            map.insert("name".into(), string(&manifest.name));
            map.insert("size".into(), Value::from(manifest.size));
            map.insert("type".into(), string(&manifest.media_type));
        }
        Message::Accept { sdp } | Message::Restart { sdp } | Message::RestartAnswer { sdp } => {
            check_sdp(sdp).map_err(|_| EncodeError::Invalid)?;
            map.insert("sdp".into(), string(sdp));
        }
        Message::Answer { key, sdp } => {
            check_sdp(sdp).map_err(|_| EncodeError::Invalid)?;
            map.insert("key".into(), string(key.to_wbk1().as_str()));
            map.insert("sdp".into(), string(sdp));
        }
        Message::Decline => {}
        Message::Stop { reason } => {
            map.insert("reason".into(), string(reason.as_str()));
        }
    }
    let text = zeroize::Zeroizing::new(canonical(&Value::Object(map)).ok_or(EncodeError::Invalid)?);
    if text.len() > MESSAGE_BYTES {
        return Err(EncodeError::TooLarge);
    }
    Ok(text.as_bytes().to_vec())
}

// ------------------------------------------------------------------ checking

/// A message a reader refuses: `stop` is the reason it sends (`failed` or
/// `unsupported`) and `detail` is for tests, never for a person or a log
/// line that leaves the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub stop: StopReason,
    pub detail: &'static str,
}

fn failed(detail: &'static str) -> Refusal {
    Refusal {
        stop: StopReason::Failed,
        detail,
    }
}

fn unsupported(detail: &'static str) -> Refusal {
    Refusal {
        stop: StopReason::Unsupported,
        detail,
    }
}

/// What a reader knows when it reads a message.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// Who sent it.
    pub from: Side,
    /// The sender's exchange message index.
    pub index: usize,
    /// The page's build-time ICE allowlist, for `invite`.  Drop reads only
    /// the page's messages, which never carry servers.
    pub ice_allowlist: &'a [&'a str],
    /// The `max` Drop offered, for `manifest`.
    pub max: Option<u64>,
}

/// The events each side may send at each index.  `stop` is allowed wherever
/// a message is, except Drop's first.
fn allowed_events(from: Side, index: usize) -> &'static [&'static str] {
    if index >= MESSAGES_PER_SIDE {
        return &[];
    }
    match (from, index) {
        (Side::Drop, 0) => &["invite"],
        (Side::Drop, 1) => &["accept", "decline", "stop"],
        (Side::Drop, i) if i <= 1 + RESTARTS => &["restart", "stop"],
        (Side::Page, 0) => &["manifest", "stop"],
        (Side::Page, 1) => &["answer", "stop"],
        (Side::Page, i) if i <= 1 + RESTARTS => &["restart-answer", "stop"],
        _ => &["stop"],
    }
}

fn has_exactly(map: &Map<String, Value>, names: &[&str]) -> bool {
    map.len() == names.len() && names.iter().all(|name| map.contains_key(*name))
}

/// 16 bytes in canonical unpadded base64url: the last character carries four
/// padding bits, so only `A`, `Q`, `g` and `w` can end it.
pub fn canonical_id(text: &str) -> bool {
    text.len() == 22
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && matches!(text.as_bytes()[21], b'A' | b'Q' | b'g' | b'w')
}

/// A name that is a fixed point of the shared name rule.
pub fn valid_name(name: &str) -> bool {
    wildbloom_envelope::sanitise_name(name) == name
}

/// A lower-case media type, 1 to 255 UTF-16 units, no control characters.
pub fn valid_media_type(media_type: &str) -> bool {
    (1..=255).contains(&utf16_len(media_type))
        && !media_type.chars().any(is_control)
        && media_type.to_lowercase() == media_type
}

/// The shape of a session description both ends accept: printable ASCII
/// with CRLF line ends, at most 8,000 bytes, starting `v=0`, one data-channel
/// media section and a SHA-256 fingerprint.
pub fn check_sdp(sdp: &str) -> Result<(), &'static str> {
    if sdp.is_empty() || sdp.len() > SDP_BYTES {
        return Err("the description is empty or over 8,000 bytes");
    }
    if !sdp
        .bytes()
        .all(|b| b == b'\r' || b == b'\n' || (0x20..=0x7e).contains(&b))
    {
        return Err("the description is not printable ASCII");
    }
    if !sdp.starts_with("v=0\r\n") || !sdp.ends_with("\r\n") {
        return Err("the description does not start with v=0 or end in CRLF");
    }
    let bytes = sdp.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        let bare_lf = b == b'\n' && (i == 0 || bytes[i - 1] != b'\r');
        let bare_cr = b == b'\r' && bytes.get(i + 1) != Some(&b'\n');
        if bare_lf || bare_cr {
            return Err("the description has a bare line feed or carriage return");
        }
    }
    let lines: Vec<&str> = sdp[..sdp.len() - 2].split("\r\n").collect();
    let media: Vec<&&str> = lines.iter().filter(|line| line.starts_with("m=")).collect();
    let data_channel = |line: &str| {
        line.strip_prefix("m=application ")
            .and_then(|rest| rest.strip_suffix(" UDP/DTLS/SCTP webrtc-datachannel"))
            .is_some_and(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
    };
    if media.len() != 1 || !data_channel(media[0]) {
        return Err("the description must have exactly one data-channel media section");
    }
    if !lines
        .iter()
        .any(|line| line.starts_with("a=fingerprint:sha-256 "))
    {
        return Err("the description has no SHA-256 fingerprint");
    }
    Ok(())
}

fn read_ice(value: &Value, allowlist: &[&str]) -> Result<Vec<IceServer>, Refusal> {
    let Some(entries) = value.as_array() else {
        return Err(failed("ice must hold 1 to 4 servers"));
    };
    if !(1..=ICE_SERVERS).contains(&entries.len()) {
        return Err(failed("ice must hold 1 to 4 servers"));
    }
    let mut servers = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(map) = entry.as_object() else {
            return Err(failed("an ice server has the wrong members"));
        };
        if !has_exactly(map, &["credential", "urls", "username"]) {
            return Err(failed("an ice server has the wrong members"));
        }
        let Some(urls) = map["urls"].as_array() else {
            return Err(failed("urls must hold 1 to 4 URLs"));
        };
        if !(1..=URLS_PER_SERVER).contains(&urls.len()) {
            return Err(failed("urls must hold 1 to 4 URLs"));
        }
        let mut list = Vec::with_capacity(urls.len());
        for url in urls {
            match url.as_str() {
                Some(url) if valid_ice_url(url) => list.push(url.to_owned()),
                _ => return Err(failed("an ice URL is malformed")),
            }
        }
        let (Some(username), Some(credential)) =
            (map["username"].as_str(), map["credential"].as_str())
        else {
            return Err(failed("a username or credential is malformed"));
        };
        let server = IceServer {
            credential: credential.to_owned(),
            urls: list,
            username: username.to_owned(),
        };
        if !server.well_formed() {
            return Err(failed("a username or credential is malformed"));
        }
        servers.push(server);
    }
    // Syntax first; only then the page's own policy, so a refusal for policy
    // is always `unsupported`.
    if servers
        .iter()
        .flat_map(|server| &server.urls)
        .any(|url| !allowlist.contains(&url.as_str()))
    {
        return Err(unsupported("an ice URL is not on the build-time allowlist"));
    }
    if !servers.iter().any(IceServer::has_turn) {
        return Err(unsupported("no TURN URL"));
    }
    Ok(servers)
}

fn read_invite(body: &Map<String, Value>, cx: &Context<'_>) -> Result<Message, Refusal> {
    if !has_exactly(body, &["dir", "event", "hide", "ice", "id", "max", "v"]) {
        return Err(failed("invite members"));
    }
    let dir = match body["dir"].as_str() {
        Some(dir @ ("to-drop" | "from-drop")) => dir,
        _ => return Err(failed("unknown direction")),
    };
    let Some(hide) = body["hide"].as_bool() else {
        return Err(failed("hide must be a boolean"));
    };
    let id = match body["id"].as_str() {
        Some(id) if canonical_id(id) => id.to_owned(),
        _ => return Err(failed("id is not 16 canonical base64url bytes")),
    };
    let max = match body["max"].as_u64() {
        Some(max) if max >= 1 => max,
        _ => return Err(failed("max must be at least 1")),
    };
    let ice = read_ice(&body["ice"], cx.ice_allowlist)?;
    if dir == "from-drop" {
        return Err(unsupported("this page sends; it does not receive"));
    }
    if max > MAX_FILE_BYTES {
        return Err(unsupported("max is above the 250,000,000 byte cap"));
    }
    Ok(Message::Invite { hide, ice, id, max })
}

/// Characters that change how a name is drawn, or that cannot be seen at
/// all, which the shared name rule lets through: the bidirectional controls
/// (so `invoice` + U+202E + `fdp.terminal` is drawn as `invoicelanimret.pdf`),
/// the zero-width and word-joining characters, the deprecated formatting
/// characters, the tag characters and the byte order mark.  A direct send's
/// manifest refuses a name holding any of them; the list is the protocol's
/// and the page's (`DISGUISING_CHARACTERS` in `src/direct/messages.ts`).
/// Only direct send refuses them: the shared name rule is unchanged.
pub fn is_disguising(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

fn read_manifest(body: &Map<String, Value>, cx: &Context<'_>) -> Result<Message, Refusal> {
    if !has_exactly(body, &["event", "name", "size", "type", "v"]) {
        return Err(failed("manifest members"));
    }
    let name = match body["name"].as_str() {
        Some(name) if valid_name(name) => name.to_owned(),
        _ => return Err(failed("name is not a fixed point of the name rule")),
    };
    if name.chars().any(is_disguising) {
        return Err(failed("name holds a character that disguises it"));
    }
    let media_type = match body["type"].as_str() {
        Some(media_type) if valid_media_type(media_type) => media_type.to_owned(),
        _ => return Err(failed("type is not a lower-case media type")),
    };
    let Some(size) = body["size"].as_u64() else {
        return Err(failed("size must be an integer"));
    };
    if cx.max.is_some_and(|max| size > max) {
        return Err(unsupported(TOO_BIG));
    }
    Ok(Message::Manifest(Manifest {
        name,
        size,
        media_type,
    }))
}

fn read_sdp(body: &Map<String, Value>, members: &[&str]) -> Result<String, Refusal> {
    if !has_exactly(body, members) {
        return Err(failed("sdp message members"));
    }
    let Some(sdp) = body["sdp"].as_str() else {
        return Err(failed("sdp must be a string"));
    };
    check_sdp(sdp).map_err(failed)?;
    Ok(sdp.to_owned())
}

fn read_answer(body: &Map<String, Value>) -> Result<Message, Refusal> {
    if !has_exactly(body, &["event", "key", "sdp", "v"]) {
        return Err(failed("answer members"));
    }
    let key = body["key"]
        .as_str()
        .and_then(|key| InputKey::parse_wbk1(key).ok())
        .ok_or(failed("key is not a canonical wbk1_ key"))?;
    let sdp = read_sdp(body, &["event", "key", "sdp", "v"])?;
    Ok(Message::Answer { key, sdp })
}

fn read_stop(body: &Map<String, Value>) -> Result<Message, Refusal> {
    if !has_exactly(body, &["event", "reason", "v"]) {
        return Err(failed("stop members"));
    }
    body["reason"]
        .as_str()
        .and_then(StopReason::parse)
        .map(|reason| Message::Stop { reason })
        .ok_or(failed("unknown stop reason"))
}

/// Reads one exchange message.  A refusal carries the `stop` reason the
/// reader sends: `unsupported` for a version, direction, ICE server or size
/// this end cannot use, and `failed` for anything else that is not exactly
/// the message.
pub fn decode(bytes: &[u8], cx: &Context<'_>) -> Result<Message, Refusal> {
    if bytes.len() > MESSAGE_BYTES {
        return Err(failed("message over 16,379 bytes"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| failed("not UTF-8"))?;
    let parsed: Value = serde_json::from_str(text).map_err(|_| failed("not JSON"))?;
    let Value::Object(body) = &parsed else {
        return Err(failed("not an object"));
    };
    let again = zeroize::Zeroizing::new(canonical(&parsed).ok_or(failed("not canonical (value)"))?);
    if again.as_str() != text {
        return Err(failed("not canonical (bytes)"));
    }
    match body.get("v") {
        Some(Value::Number(version)) if version.as_u64() == Some(1) => {}
        Some(Value::Number(_)) => return Err(unsupported("version")),
        _ => return Err(failed("missing or malformed version")),
    }
    let event = match body.get("event").and_then(Value::as_str) {
        Some(event) if allowed_events(cx.from, cx.index).contains(&event) => event,
        _ => return Err(failed("event not allowed here")),
    };
    match event {
        "invite" => read_invite(body, cx),
        "manifest" => read_manifest(body, cx),
        "accept" => read_sdp(body, &["event", "sdp", "v"]).map(|sdp| Message::Accept { sdp }),
        "restart" => read_sdp(body, &["event", "sdp", "v"]).map(|sdp| Message::Restart { sdp }),
        "restart-answer" => {
            read_sdp(body, &["event", "sdp", "v"]).map(|sdp| Message::RestartAnswer { sdp })
        }
        "decline" if has_exactly(body, &["event", "v"]) => Ok(Message::Decline),
        "decline" => Err(failed("decline members")),
        "answer" => read_answer(body),
        "stop" => read_stop(body),
        _ => Err(failed("unknown event")),
    }
}

/// The envelope length E the manifest implies: FSWNENC2's padded plaintext
/// for the metadata and the file, its 56-byte header and a 16-byte tag per
/// MiB record.  `None` for a manifest that could not be sealed.
pub fn envelope_bytes(manifest: &Manifest) -> Option<u64> {
    wildbloom_envelope::envelope_bytes(&manifest.name, &manifest.media_type, manifest.size).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../../../../vectors/wildbloom-direct-v1.json"
        ))
        .unwrap()
    }

    fn side(text: &str) -> Side {
        match text {
            "drop" => Side::Drop,
            "page" => Side::Page,
            other => panic!("unknown side {other}"),
        }
    }

    fn allowlist(fixture: &Value) -> Vec<&str> {
        fixture["iceAllowlist"]
            .as_array()
            .unwrap()
            .iter()
            .map(|url| url.as_str().unwrap())
            .collect()
    }

    #[test]
    fn the_vector_limits_are_the_codes() {
        let fixture = vectors();
        assert_eq!(fixture["profile"], PROFILE);
        assert_eq!(
            fixture["exchangeProfile"],
            foregather_kit::exchange::PROFILE
        );
        assert_eq!(fixture["session"]["namespace"], "wildbloom.drop");
        assert_eq!(fixture["session"]["purpose"], super::super::PURPOSE);
        let limits = &fixture["limits"];
        assert_eq!(limits["messageBytes"], MESSAGE_BYTES);
        assert_eq!(MESSAGE_BYTES, foregather_kit::exchange::MAX_PAYLOAD);
        assert_eq!(limits["messagesPerSide"], MESSAGES_PER_SIDE);
        assert_eq!(limits["restarts"], RESTARTS);
        assert_eq!(limits["sdpBytes"], SDP_BYTES);
        assert_eq!(limits["iceServers"], ICE_SERVERS);
        assert_eq!(limits["urlsPerServer"], URLS_PER_SERVER);
        assert_eq!(limits["urlBytes"], URL_BYTES);
        assert_eq!(limits["credentialBytes"], CREDENTIAL_BYTES);
        assert_eq!(limits["maxPlaintextBytes"], MAX_FILE_BYTES);
    }

    /// Every valid message reads, has its SHA-256, and writes back byte for
    /// byte.
    #[test]
    fn every_valid_vector_round_trips() {
        let fixture = vectors();
        let allow = allowlist(&fixture);
        let messages = fixture["messages"].as_array().unwrap();
        assert!(messages.len() >= 12);
        for vector in messages {
            let name = vector["name"].as_str().unwrap();
            let text = vector["text"].as_str().unwrap();
            assert_eq!(
                crate::drop::hex_lower(&Sha256::digest(text.as_bytes())),
                vector["sha256"].as_str().unwrap(),
                "{name}"
            );
            let cx = Context {
                from: side(vector["from"].as_str().unwrap()),
                index: vector["index"].as_u64().unwrap() as usize,
                ice_allowlist: &allow,
                max: Some(MAX_FILE_BYTES),
            };
            let message = decode(text.as_bytes(), &cx).unwrap_or_else(|r| panic!("{name}: {r:?}"));
            assert_eq!(encode(&message).unwrap(), text.as_bytes(), "{name}");
        }
    }

    /// Every refused message is refused with the reason the vector names.
    #[test]
    fn every_refused_vector_is_refused_with_its_reason() {
        let fixture = vectors();
        let allow = allowlist(&fixture);
        let refusals = fixture["refusals"].as_array().unwrap();
        assert!(refusals.len() >= 47);
        for vector in refusals {
            let name = vector["name"].as_str().unwrap();
            let cx = Context {
                from: side(vector["from"].as_str().unwrap()),
                index: vector["index"].as_u64().unwrap() as usize,
                ice_allowlist: &allow,
                max: Some(MAX_FILE_BYTES),
            };
            let refusal = decode(vector["text"].as_str().unwrap().as_bytes(), &cx)
                .map(|m| m.event())
                .expect_err(name);
            assert_eq!(
                refusal.stop.as_str(),
                vector["stopReason"].as_str().unwrap(),
                "{name}: {}",
                refusal.detail
            );
        }
    }

    /// The disguising-character vectors pass the shared name rule, so they
    /// are refused by the direct-send rule and not before it.
    #[test]
    fn disguised_names_are_refused_by_their_own_rule() {
        let fixture = vectors();
        let mut seen = 0;
        for vector in fixture["refusals"].as_array().unwrap() {
            let text = vector["text"].as_str().unwrap();
            let Ok(Value::Object(body)) = serde_json::from_str::<Value>(text) else {
                continue;
            };
            let Some(name) = body.get("name").and_then(Value::as_str) else {
                continue;
            };
            if !name.chars().any(is_disguising) {
                continue;
            }
            seen += 1;
            assert!(valid_name(name), "{name:?} is not a fixed point");
            let cx = Context {
                from: Side::Page,
                index: 0,
                ice_allowlist: &[],
                max: Some(MAX_FILE_BYTES),
            };
            let refusal = decode(text.as_bytes(), &cx).map(|m| m.event()).unwrap_err();
            assert_eq!(refusal.detail, "name holds a character that disguises it");
            assert_eq!(refusal.stop, StopReason::Failed);
        }
        assert!(seen >= 5, "{seen}");
    }

    #[test]
    fn the_disguising_list_is_the_protocols() {
        let character = |code: u32| char::from_u32(code).unwrap();
        for code in [
            0x061C, 0x180E, 0x200B, 0x200F, 0x202A, 0x202E, 0x2060, 0x2064, 0x2066, 0x2069, 0x206A,
            0x206F, 0xFEFF, 0xE0000, 0xE0041, 0xE007F,
        ] {
            assert!(is_disguising(character(code)), "U+{code:04X}");
        }
        for code in [
            0x061B, 0x061D, 0x180D, 0x180F, 0x200A, 0x2010, 0x2029, 0x202F, 0x205F, 0x2065, 0x2070,
            0xFEFE, 0xFF00, 0xDFFFF, 0xE0080, 0x61, 0x2E, 0x20, 0xE9,
        ] {
            assert!(!is_disguising(character(code)), "U+{code:04X}");
        }
    }

    #[test]
    fn the_envelope_lengths_follow_the_manifest() {
        let fixture = vectors();
        let envelopes = fixture["envelopes"].as_array().unwrap();
        assert_eq!(envelopes[0]["envelopeBytes"], 65_608);
        for vector in envelopes {
            let manifest = Manifest {
                name: vector["name"].as_str().unwrap().into(),
                size: vector["size"].as_u64().unwrap(),
                media_type: vector["type"].as_str().unwrap().into(),
            };
            let metadata = format!(
                "{{\"name\":{},\"size\":{},\"type\":{}}}",
                serde_json::to_string(&manifest.name).unwrap(),
                manifest.size,
                serde_json::to_string(&manifest.media_type).unwrap()
            );
            assert_eq!(
                metadata.len() as u64,
                vector["metadataBytes"].as_u64().unwrap()
            );
            assert_eq!(
                envelope_bytes(&manifest),
                vector["envelopeBytes"].as_u64(),
                "{}",
                manifest.name
            );
            let padded = vector["paddedBytes"].as_u64().unwrap();
            let records = vector["records"].as_u64().unwrap();
            assert_eq!(padded.div_ceil(1024 * 1024), records);
            assert_eq!(
                56 + padded + 16 * records,
                vector["envelopeBytes"].as_u64().unwrap()
            );
        }
    }

    /// The brief's check: the protocol's escaping is written here by hand, so
    /// compare it with `serde_json` (which the protocol says agrees) for every
    /// ASCII character and a few that are not.
    #[test]
    fn string_escaping_matches_serde_json_and_the_rule() {
        let mut probes: Vec<String> = (0u32..0x80)
            .map(|c| char::from_u32(c).unwrap().to_string())
            .collect();
        probes.extend(
            [
                "Café",
                "\u{2028}\u{2029}",
                "\u{feff}",
                "😀",
                "a/b\\c\"d",
                "\u{7f}",
                "\u{1f}",
                "\u{85}",
            ]
            .map(str::to_owned),
        );
        for probe in probes {
            let mut ours = String::new();
            write_string(&mut ours, &probe);
            assert_eq!(ours, serde_json::to_string(&probe).unwrap(), "{probe:?}");
        }
        let mut sample = String::new();
        write_string(&mut sample, "\"\\/\u{7}\u{8}\u{c}\n\r\t\u{1f}\u{7f}é😀");
        assert_eq!(
            sample,
            "\"\\\"\\\\/\\u0007\\b\\f\\n\\r\\t\\u001f\u{7f}é😀\""
        );
    }

    #[test]
    fn canonical_refuses_null_floats_negatives_and_unsafe_integers() {
        for text in [
            "null",
            "1.0",
            "-1",
            "2.5e8",
            "9007199254740992",
            "18446744073709551616",
            "{\"a\":null}",
        ] {
            let value: Value = serde_json::from_str(text).unwrap();
            assert_eq!(canonical(&value), None, "{text}");
        }
        let value: Value =
            serde_json::from_str("{\"b\":[true,false,9007199254740991],\"a\":\"x\"}").unwrap();
        assert_eq!(
            canonical(&value).unwrap(),
            "{\"a\":\"x\",\"b\":[true,false,9007199254740991]}"
        );
    }

    #[test]
    fn readers_refuse_byte_order_marks_trailing_text_and_oversize() {
        let cx = Context {
            from: Side::Page,
            index: 0,
            ice_allowlist: &[],
            max: Some(MAX_FILE_BYTES),
        };
        let good = br#"{"event":"manifest","name":"a.txt","size":1,"type":"text/plain","v":1}"#;
        assert!(decode(good, &cx).is_ok());
        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend_from_slice(good);
        assert_eq!(decode(&bom, &cx).unwrap_err().stop, StopReason::Failed);
        let mut trailing = good.to_vec();
        trailing.push(b' ');
        assert_eq!(decode(&trailing, &cx).unwrap_err().stop, StopReason::Failed);
        assert_eq!(
            decode(&vec![b' '; MESSAGE_BYTES + 1], &cx)
                .unwrap_err()
                .detail,
            "message over 16,379 bytes"
        );
        assert_eq!(decode(b"\xff", &cx).unwrap_err().detail, "not UTF-8");
        // An oversized manifest name is not a fixed point.
        let long = format!(
            "{{\"event\":\"manifest\",\"name\":\"{}\",\"size\":1,\"type\":\"text/plain\",\"v\":1}}",
            "a".repeat(181)
        );
        assert_eq!(
            decode(long.as_bytes(), &cx).unwrap_err().stop,
            StopReason::Failed
        );
        // A size above what Drop offered is unsupported.
        let small = Context {
            max: Some(10),
            ..cx
        };
        let over = br#"{"event":"manifest","name":"a.txt","size":11,"type":"text/plain","v":1}"#;
        assert_eq!(
            decode(over, &small).unwrap_err().stop,
            StopReason::Unsupported
        );
    }

    fn sdp() -> String {
        "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:sha-256 AA:BB\r\n".into()
    }

    fn ice() -> IceServer {
        IceServer {
            credential: "c3ludGhldGljLWNyZWRlbnRpYWw=".into(),
            urls: vec!["turn:turn.example.net:3478?transport=udp".into()],
            username: "1800003600:dGVzdC1sYWJlbA".into(),
        }
    }

    #[test]
    fn writers_refuse_what_readers_would() {
        let id = "AAECAwQFBgcICQoLDA0ODw".to_owned();
        let invite = |ice: Vec<IceServer>, id: &str, max: u64| Message::Invite {
            hide: true,
            ice,
            id: id.into(),
            max,
        };
        assert!(encode(&invite(vec![ice()], &id, MAX_FILE_BYTES)).is_ok());
        assert_eq!(encode(&invite(vec![], &id, 1)), Err(EncodeError::Invalid));
        assert_eq!(
            encode(&invite(vec![ice()], &id, MAX_FILE_BYTES + 1)),
            Err(EncodeError::Invalid)
        );
        assert_eq!(
            encode(&invite(vec![ice()], &id, 0)),
            Err(EncodeError::Invalid)
        );
        assert_eq!(
            encode(&invite(vec![ice()], "AAECAwQFBgcICQoLDA0ODx", 1)),
            Err(EncodeError::Invalid)
        );
        let mut stun_only = ice();
        stun_only.urls = vec!["stun:turn.example.net:3478".into()];
        assert_eq!(
            encode(&invite(vec![stun_only], &id, 1)),
            Err(EncodeError::Invalid)
        );
        let mut empty = ice();
        empty.credential = String::new();
        assert_eq!(
            encode(&invite(vec![empty], &id, 1)),
            Err(EncodeError::Invalid)
        );
        assert!(encode(&Message::Accept { sdp: sdp() }).is_ok());
        assert_eq!(
            encode(&Message::Accept {
                sdp: sdp().replace("\r\n", "\n")
            }),
            Err(EncodeError::Invalid)
        );
        assert_eq!(
            encode(&Message::Restart {
                sdp: format!("{}a=x:{}\r\n", sdp(), "y".repeat(SDP_BYTES))
            }),
            Err(EncodeError::Invalid)
        );
        // Drop's own messages read back at Drop's indexes.
        let cx = |index| Context {
            from: Side::Drop,
            index,
            ice_allowlist: &["turn:turn.example.net:3478?transport=udp"],
            max: None,
        };
        for (index, message) in [
            (0, invite(vec![ice()], &id, MAX_FILE_BYTES)),
            (1, Message::Accept { sdp: sdp() }),
            (1, Message::Decline),
            (2, Message::Restart { sdp: sdp() }),
            (6, Message::Restart { sdp: sdp() }),
            (
                7,
                Message::Stop {
                    reason: StopReason::Cancelled,
                },
            ),
        ] {
            let bytes = encode(&message).unwrap();
            assert_eq!(decode(&bytes, &cx(index)).unwrap(), message, "{index}");
        }
        // A sixth restart is at index 7, where only stop is allowed.
        let bytes = encode(&Message::Restart { sdp: sdp() }).unwrap();
        assert_eq!(decode(&bytes, &cx(7)).unwrap_err().stop, StopReason::Failed);
        assert_eq!(decode(&bytes, &cx(8)).unwrap_err().stop, StopReason::Failed);
    }

    #[test]
    fn debug_hides_credentials() {
        let text = format!("{:?}", ice());
        assert!(!text.contains("c3ludGhldGlj") && !text.contains("dGVzdC1sYWJlbA"));
        assert!(text.contains("turn:turn.example.net"));
    }
}
