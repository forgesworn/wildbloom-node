//! The one gate in front of every route that hands a currently granted device
//! something on request: the pairing issuer and the TURN credential issuer.
//!
//! A request passes only with a checkout-profile NIP-98 `POST` (exact `u` and
//! `method`, a `payload` tag for the empty body, at most 60 seconds old) signed
//! by a device whose grant is active.  Owners and recovery identities are not
//! devices and are refused.  Each route keeps its own rolling-hour budget per
//! device, checked before the single-use event id is spent, so a refused
//! request spends neither.
use super::{ApiError, Grants};
use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::StatusCode,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

/// Every budget is counted over the same rolling window.
pub const RATE_WINDOW: u64 = 60 * 60;
/// NIP-98 freshness in the checkout profile is 60 s old or 30 s ahead.
const REPLAY_WINDOW: u64 = 120;

/// The refusal texts a route returns, so each keeps its own wording.
pub struct Refusals {
    pub unauthorised: &'static str,
    pub spent: &'static str,
    pub replayed: &'static str,
}

#[derive(Clone)]
pub struct DeviceAuth {
    grants: Grants,
    path: &'static str,
    limit: u32,
    refusals: &'static Refusals,
    rate: Arc<Mutex<HashMap<String, VecDeque<u64>>>>,
}

impl DeviceAuth {
    /// `path` is the route without a leading slash; `limit` is the number of
    /// requests one device may make in any `RATE_WINDOW`.
    pub fn new(
        grants: Grants,
        path: &'static str,
        limit: u32,
        refusals: &'static Refusals,
    ) -> Self {
        Self {
            grants,
            path,
            limit,
            refusals,
            rate: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn now(&self) -> u64 {
        self.grants.now()
    }

    /// Verify the request and charge the device's budget.  Returns the
    /// device key; nothing else about the request is kept.
    pub async fn authorise(&self, request: Request<Body>) -> Result<String, ApiError> {
        if request.uri().query().is_some() {
            return Err(ApiError::bad_request("queries are not accepted"));
        }
        let header = super::single_authorization(request.headers())?.to_owned();
        let body = to_bytes(request.into_body(), 1024)
            .await
            .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "body is too large"))?;
        if !body.is_empty() {
            return Err(ApiError::bad_request("the request body must be empty"));
        }
        let now = self.grants.now();
        let principal = wildbloom_checkout::authenticate(
            &header,
            &format!("{}{}", self.grants.inner.origin, self.path),
            "POST",
            &body,
            now,
        )
        .map_err(|_| ApiError::unauthorised(self.refusals.unauthorised))?;
        let device = principal.pubkey().to_owned();
        if !self.grants.is_active_device(&device) {
            return Err(ApiError::forbidden("the device has no active grant"));
        }
        // Sliding window, checked before the replay row is written so a
        // refused request spends neither budget nor the event id.
        let mut rate = self.rate.lock().map_err(|_| ApiError::unavailable())?;
        for window in rate.values_mut() {
            while window
                .front()
                .is_some_and(|issued| now.saturating_sub(*issued) >= RATE_WINDOW)
            {
                window.pop_front();
            }
        }
        rate.retain(|_, window| !window.is_empty());
        if rate
            .get(&device)
            .is_some_and(|window| window.len() >= self.limit as usize)
        {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                self.refusals.spent,
            ));
        }
        if !self
            .grants
            .consume_event(principal.event_id(), now.saturating_add(REPLAY_WINDOW))?
        {
            return Err(ApiError::conflict(self.refusals.replayed));
        }
        rate.entry(device.clone()).or_default().push_back(now);
        drop(rate);
        Ok(device)
    }
}
