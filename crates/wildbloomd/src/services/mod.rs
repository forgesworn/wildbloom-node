//! Explicit public discovery. No profile means no route, signing or relay I/O.
mod contract;
mod publisher;
mod relay;
#[cfg(test)]
mod tests;

use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use contract::{Availability, Description, ListingState, PROFILE, Payment, Service};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use wildbloom_checkout::{Checkout, Rail};
use wildbloom_core::Store;

#[derive(Debug, thiserror::Error)]
#[error("public service configuration, snapshot, signer or relay was refused or unavailable")]
pub struct Error;

fn heartbeat() -> u64 {
    1800
}
fn ttl() -> u64 {
    7200
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub service_pubkey: String,
    pub identifier: String,
    pub name: String,
    pub about: String,
    pub origins: Vec<String>,
    pub browser_origins: Vec<String>,
    #[serde(default)]
    pub withdrawn: bool,
    pub announcement: Option<Announcement>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Announcement {
    pub signer: PathBuf,
    #[serde(default)]
    pub signer_args: Vec<String>,
    pub state_dir: PathBuf,
    pub transport: relay::Transport,
    pub relays: Vec<relay::Destination>,
    #[serde(default = "heartbeat")]
    pub heartbeat_seconds: u64,
    #[serde(default = "ttl")]
    pub ttl_seconds: u64,
}
impl Profile {
    pub fn read(path: &Path) -> Result<Self, Error> {
        serde_json::from_slice(&wildbloom_checkout::read_private_file(path).map_err(|_| Error)?)
            .map_err(|_| Error)
    }
}
#[derive(Clone)]
pub struct Services {
    profile: Arc<Profile>,
    store: Store,
    checkout: Option<Checkout>,
    free: bool,
    mirrors_enabled: bool,
    limits: Arc<Mutex<(Instant, u32)>>,
    workers: Arc<tokio::sync::Semaphore>,
}
impl Services {
    // All admission and transport inputs are supplied by the running daemon;
    // none are duplicated in the public service profile.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: Profile,
        store: Store,
        checkout: Option<Checkout>,
        origin: &str,
        open_shelter: bool,
        mirrors_enabled: bool,
        private_keys: &[String],
        proxy: Option<&url::Url>,
        no_tor: bool,
    ) -> Result<Self, Error> {
        // Initial release binds one explicitly configured origin to the running listener.
        // Neither Host nor forwarding headers can advertise a different node.
        if profile.origins != [origin.to_owned()]
            || (!open_shelter && checkout.is_none())
            || private_keys.contains(&profile.service_pubkey)
            || profile.browser_origins.is_empty()
            || profile.browser_origins.len() > 16
        {
            return Err(Error);
        }
        let mut seen = std::collections::BTreeSet::new();
        for origin in &profile.browser_origins {
            let parsed = contract::endpoint(&format!("{origin}/"), true, true)?;
            if parsed.origin().ascii_serialization() != *origin || !seen.insert(origin) {
                return Err(Error);
            }
        }
        if let Some(a) = &profile.announcement {
            if !a.signer.is_absolute()
                || !a.state_dir.is_absolute()
                || a.state_dir.starts_with(&store.config().root)
                || a.state_dir.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
                || a.signer_args.len() > 32
                || a.signer_args.iter().any(|a| a.len() > 2048)
                || !(300..=3600).contains(&a.heartbeat_seconds)
                || !(600..=86400).contains(&a.ttl_seconds)
                || a.ttl_seconds < a.heartbeat_seconds.saturating_mul(2)
            {
                return Err(Error);
            }
            relay::validate(a, proxy, no_tor)?;
        }
        let services = Self {
            profile: Arc::new(profile),
            store,
            checkout,
            free: open_shelter,
            mirrors_enabled,
            limits: Arc::new(Mutex::new((Instant::now(), 0))),
            workers: Arc::new(tokio::sync::Semaphore::new(4)),
        };
        let at = now()?;
        services.snapshot(at, false)?.template(at)?;
        Ok(services)
    }
    pub fn snapshot(&self, observed_at: u64, withdraw: bool) -> Result<Description, Error> {
        // A failed read yields unknown, never a fabricated accepting state.
        let committed = self.store.committed_bytes().ok();
        let quota = self.store.quota_bytes();
        let free_bytes = committed.map(|used| quota.saturating_sub(used));
        let mut services = Vec::new();
        if self.free {
            // shelter-kit v0.5.0 guest admission retains this exact high watermark.
            // Accepting means some new positive-sized mirror can fit, not max_blob_bytes.
            let high = (quota / 5)
                .max((quota / 10).saturating_add(1))
                .min(quota.saturating_sub(1));
            let availability = if !self.mirrors_enabled {
                Availability::Paused
            } else {
                match free_bytes {
                    Some(free) if free > high => Availability::Accepting,
                    Some(_) => Availability::Full,
                    None => Availability::Unknown,
                }
            };
            services.push(Service::Free { id: "free-mirror".into(), revision: 1, availability,
                operation: "mirror".into(), authorisation: "bud-11".into(), retention: "best-effort".into(),
                eviction_policy: "Guest mirrors are evictable, oldest first, under storage pressure. Direct uploads from unknown keys are refused.".into() });
        }
        let checkout = self.checkout.as_ref().map(|checkout| {
            for offer in &checkout.config().offers {
                let availability = match free_bytes {
                    Some(free) if free >= offer.capacity_bytes => Availability::Accepting,
                    Some(_) => Availability::Full,
                    None => Availability::Unknown,
                };
                services.push(Service::paid(offer, availability));
            }
            let rails = checkout.rails();
            Payment {
                protocol: "wildbloom-checkout-v1".into(),
                origin: checkout.config().origin.clone(),
                network: checkout.config().network,
                issuers: if rails.contains(&Rail::Lnurlcash) {
                    checkout.config().issuers.clone()
                } else {
                    Vec::new()
                },
                rails,
            }
        });
        let state = if withdraw || self.profile.withdrawn {
            for service in &mut services {
                service.pause();
            }
            ListingState::Withdrawn
        } else {
            ListingState::Published
        };
        let ttl = self
            .profile
            .announcement
            .as_ref()
            .map_or(7200, |a| a.ttl_seconds);
        let result = Description {
            profile: PROFILE.into(),
            service_pubkey: self.profile.service_pubkey.clone(),
            identifier: self.profile.identifier.clone(),
            name: self.profile.name.clone(),
            about: self.profile.about.clone(),
            origins: self.profile.origins.clone(),
            max_blob_bytes: self.store.config().max_blob_bytes,
            observed_at,
            expires_at: observed_at.checked_add(ttl).ok_or(Error)?,
            state,
            checkout,
            services,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn router(&self) -> Result<Router, Error> {
        let origins = self
            .profile
            .browser_origins
            .iter()
            .map(|o| o.parse())
            .collect::<Result<Vec<axum::http::HeaderValue>, _>>()
            .map_err(|_| Error)?;
        Ok(Router::new()
            .route("/services/v1", get(snapshot))
            .with_state(self.clone())
            .layer(
                tower_http::cors::CorsLayer::new()
                    .allow_origin(origins)
                    .allow_methods([axum::http::Method::GET]),
            )
            .layer(axum::middleware::map_response(no_store)))
    }
    pub fn start(&self, proxy: Option<url::Url>) -> Result<Option<publisher::Publisher>, Error> {
        self.profile
            .announcement
            .clone()
            .map(|a| publisher::Publisher::start(self.clone(), a, proxy))
            .transpose()
    }
}
pub fn now() -> Result<u64, Error> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error)?
        .as_secs())
}
async fn snapshot(State(services): State<Services>) -> Response {
    let permit = match services.workers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
    };
    {
        let Ok(mut window) = services.limits.lock() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        if window.0.elapsed() >= Duration::from_secs(60) {
            *window = (Instant::now(), 0);
        }
        if window.1 >= 120 {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        window.1 += 1;
    }
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        services.snapshot(now()?, false)
    })
    .await;
    match result {
        Ok(Ok(d)) => axum::Json(d).into_response(),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
async fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}
