//! Opt-in operator checkout. No listener, wallet keys or automatic network activity.
//! The daemon mounts these routes only with a private operator profile and
//! bounded, pinned receiving backends. It never wraps Blossom routes.
mod auth;
mod contract;
mod http;
mod ledger;
mod phoenixd;
mod profile;
mod service;
mod transport;
pub use phoenixd::Phoenixd;
pub use profile::{RuntimeProfile, read_private_file};
pub use transport::{Destination, HttpNoteTransport, HttpRefundTransport};

pub use auth::{Principal, authenticate};
pub use contract::*;
pub use http::router;
pub use ledger::Ledger;
pub use service::{Checkout, NoteTransport, RefundTransport, SensitiveUrl, TransportFailure};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("checkout is busy or its admission limit has been reached")]
    Busy,
    #[error("invalid checkout request or configuration")]
    Invalid,
    #[error("checkout authentication failed")]
    Unauthorised,
    #[error("order not found")]
    NotFound,
    #[error("conflicting or already pending payment operation")]
    Conflict,
    #[error("quote expired")]
    Expired,
    #[error("storage capacity unavailable")]
    Capacity,
    #[error("payment outcome requires reconciliation")]
    Pending,
    #[error("receiving backend unavailable")]
    Unavailable,
    #[error("checkout state unavailable")]
    Internal,
}
// Never expose SQLite, backend or LNURLcash error text: it can contain assets,
// signed authorisation or a request URL. Operators inspect private state instead.
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Internal
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Internal
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::Invalid
    }
}
pub(crate) fn now() -> Result<u64, Error> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Internal)?
        .as_secs())
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}
pub(crate) fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests;
