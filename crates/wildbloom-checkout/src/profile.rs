//! Explicit operator wiring. Credentials are read only from private local files.
use crate::{Checkout, Config, Destination, Error, HttpNoteTransport, Ledger, Phoenixd};
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use wildbloom_core::Store;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProfile {
    pub checkout: Config,
    pub state: PathBuf,
    pub browser_origins: Vec<String>,
    pub phoenixd: Option<PhoenixProfile>,
    #[serde(default)]
    pub notes: Vec<NoteProfile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoenixProfile {
    pub destination: Destination,
    pub password_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteProfile {
    pub endpoint: String,
    pub destination: Destination,
}

pub fn read_private_file(path: &Path) -> Result<Vec<u8>, Error> {
    if !path.is_absolute() {
        return Err(Error::Invalid);
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err(Error::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Invalid);
        }
    }
    let file = std::fs::File::open(path)?;
    wildbloom_private_state::check_file(&file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(Error::Invalid);
        }
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

impl RuntimeProfile {
    pub fn read(path: &Path) -> Result<Self, Error> {
        let profile: Self = serde_json::from_slice(&read_private_file(path)?)?;
        profile.checkout.validate()?;
        if !profile.state.is_absolute()
            || profile.browser_origins.is_empty()
            || profile.browser_origins.len() > 16
        {
            return Err(Error::Invalid);
        }
        for origin in &profile.browser_origins {
            let parsed = crate::contract::endpoint(origin, profile.checkout.allow_loopback_http)?;
            if parsed.origin().ascii_serialization() != *origin {
                return Err(Error::Invalid);
            }
        }
        Ok(profile)
    }

    pub fn open(self, store: Store, public_origin: &str) -> Result<axum::Router, Error> {
        // No silent proxy/host rewrite or clearnet payment fallback for a Tor node.
        if self.checkout.origin != public_origin
            || self.state == store.config().root
            || self.state.starts_with(store.config().root.join("blobs"))
        {
            return Err(Error::Invalid);
        }
        let ledger = Ledger::open(&self.state)?;
        let lightning = self
            .phoenixd
            .map(|profile| {
                let password = String::from_utf8(read_private_file(&profile.password_file)?)
                    .map_err(|_| Error::Invalid)?;
                Phoenixd::new(
                    profile.destination,
                    password.trim_end_matches(['\r', '\n']).into(),
                    ledger.clone(),
                )
                .map(|backend| Arc::new(backend) as Arc<dyn toll_booth::backends::LightningBackend>)
            })
            .transpose()?;
        let notes = if self.notes.is_empty() {
            None
        } else {
            Some(Arc::new(HttpNoteTransport::new(
                self.notes
                    .into_iter()
                    .map(|p| (p.endpoint, p.destination))
                    .collect(),
            )?) as Arc<dyn crate::NoteTransport>)
        };
        let checkout = Checkout::new(self.checkout, ledger, store, lightning, notes)?;
        if checkout.rails().is_empty() {
            return Err(Error::Invalid);
        }
        let origins = self
            .browser_origins
            .into_iter()
            .map(|origin| origin.parse())
            .collect::<Result<Vec<axum::http::HeaderValue>, _>>()
            .map_err(|_| Error::Invalid)?;
        let cors = tower_http::cors::CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
            ]);
        Ok(crate::router(checkout).layer(cors))
    }
}
