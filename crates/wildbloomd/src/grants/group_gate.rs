//! The gate in front of the core router in group mode.
//!
//! Group keys are core friend grants with a far-future sentinel expiry; this
//! gate enforces what the sentinel cannot: the real expiry, revocation and
//! reset on every request, the scopes, the group ceiling, and authenticated
//! reads confined to the signer's group (`docs/GROUP-GRANTS.md` section 6).
//!
//! It verifies each group token itself on the node's clock, completes group
//! uploads, preflights and deletes through the store, and hands reads, lists
//! and mirrors to the core once they are allowed.  Requests from owners,
//! friends and device-grant keys reach the core as before; their reads need a
//! token and show only what they hold themselves.
use super::{
    CORE_GRANT_SENTINEL, Grants, blob_hash, bounded_body, claims,
    group::{ActiveGrant, Who, core_group_grant_id},
    group_db::GroupId,
    group_event::{Refusal, Scope},
    group_token::{self, Token, Verb},
};
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, task::spawn_blocking};
use wildbloom_core::{
    ClaimSpec, DeleteOutcome, RetentionTier, StoreError,
    store::{BlobMetadata, UploadStart},
};

/// Largest mirror request body the gate reads to find the blob.
const MIRROR_BODY_BYTES: usize = 8 * 1024;
/// Largest core descriptor the gate reads back from an admitted mirror.
const DESCRIPTOR_BYTES: usize = 64 * 1024;

enum Route {
    /// `GET` or `HEAD` of `/<sha256>[.<ext>]`.
    Read(Option<String>),
    List,
    Upload,
    Preflight,
    Mirror,
    Delete(Option<String>),
    /// A CORS preflight.
    Options,
    /// `/`, `/healthz` and anything the core answers without storing.
    Other,
}

fn classify(request: &Request) -> Route {
    let path = request.uri().path();
    let single = path
        .strip_prefix('/')
        .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'));
    let hash = || blob_hash(path).map(str::to_owned);
    match (request.method(), path) {
        (&Method::OPTIONS, _)
            if request
                .headers()
                .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD) =>
        {
            Route::Options
        }
        (&Method::PUT, "/upload") => Route::Upload,
        (&Method::HEAD, "/upload") => Route::Preflight,
        (&Method::PUT, "/mirror") => Route::Mirror,
        (&Method::GET | &Method::HEAD, "/healthz") => Route::Other,
        (&Method::GET, path) if path.starts_with("/list/") => Route::List,
        (&Method::GET | &Method::HEAD, _) if single => Route::Read(hash()),
        (&Method::DELETE, _) if single => Route::Delete(hash()),
        _ => Route::Other,
    }
}

/// Every group-mode `GET` and `HEAD` answer says that no shared cache may
/// keep it and that the answer depends on who asked.
fn read_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.append(header::VARY, HeaderValue::from_static("Authorization"));
}

fn preflight() -> Response {
    let mut response = Response::new(Body::empty());
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, HEAD, PUT, DELETE, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(
            "authorization, content-type, content-length, range, x-sha-256, x-content-length, x-content-type",
        ),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("3600"),
    );
    headers.insert(
        header::VARY,
        HeaderValue::from_static(
            "origin, access-control-request-method, access-control-request-headers",
        ),
    );
    response
}

pub async fn group_gate(State(grants): State<Grants>, request: Request, next: Next) -> Response {
    if !grants.group_enabled() {
        return next.run(request).await;
    }
    let route = classify(&request);
    let is_read = matches!(route, Route::Read(_) | Route::List);
    let result = match route {
        Route::Other => return next.run(request).await,
        Route::Options => return preflight(),
        Route::Read(hash) => grants.group_read(request, next, hash).await,
        Route::List => grants.group_list(request, next).await,
        Route::Upload => grants.group_upload(request, next).await,
        Route::Preflight => grants.group_preflight(request, next).await,
        Route::Mirror => grants.group_mirror(request, next).await,
        Route::Delete(hash) => grants.group_delete(request, next, hash).await,
    };
    let mut response = result.unwrap_or_else(IntoResponse::into_response);
    if is_read || response.headers().get(header::CACHE_CONTROL).is_none() {
        if is_read {
            read_headers(&mut response);
        } else {
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
    }
    response
}

fn absent() -> Refusal {
    Refusal::new(StatusCode::NOT_FOUND, "absent")
}

fn not_granted() -> Refusal {
    Refusal::forbidden("not-granted")
}

fn bad_request() -> Refusal {
    Refusal::bad("bad-request")
}

fn internal() -> Refusal {
    Refusal::new(StatusCode::INTERNAL_SERVER_ERROR, "internal")
}

fn store_refusal(error: StoreError) -> Refusal {
    match error {
        StoreError::QuotaExceeded => Refusal::new(StatusCode::INSUFFICIENT_STORAGE, "node-full"),
        StoreError::FriendLimitExceeded => {
            Refusal::new(StatusCode::INSUFFICIENT_STORAGE, "device-full")
        }
        StoreError::BlobTooLarge { .. } => Refusal::new(StatusCode::PAYLOAD_TOO_LARGE, "too-large"),
        StoreError::LengthMismatch | StoreError::HashMismatch | StoreError::InvalidHash => {
            bad_request()
        }
        StoreError::Tombstoned | StoreError::AdmissionRejected => Refusal::forbidden("refused"),
        StoreError::MissingBlob | StoreError::NotClaimant => absent(),
        error => {
            tracing::error!(reason = %error, "group storage operation failed");
            internal()
        }
    }
}

fn group_full() -> Refusal {
    Refusal::new(StatusCode::INSUFFICIENT_STORAGE, "group-full")
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn canonical_hash(value: Option<&str>) -> Option<String> {
    value
        .filter(|hash| super::event::is_canonical_key(hash))
        .map(str::to_owned)
}

fn extension_for(content_type: &str) -> &'static str {
    match content_type.split(';').next().unwrap_or_default().trim() {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/avif" => "avif",
        "audio/mpeg" => "mp3",
        "audio/ogg" => "ogg",
        "audio/wav" => "wav",
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "application/json" => "json",
        "text/markdown" => "md",
        "text/plain" => "txt",
        _ => "bin",
    }
}

/// The hash a mirror request names, as the core reads it from the source URL.
fn mirror_hash(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        url: String,
    }
    let request: Request = serde_json::from_slice(body).ok()?;
    let url = url::Url::parse(&request.url).ok()?;
    let segment = url.path_segments()?.next_back()?;
    blob_hash(&format!("/{segment}")).map(str::to_owned)
}

fn claim_spec(group: &GroupId, signer: &str, bytes: u64, content_type: &str) -> ClaimSpec {
    ClaimSpec {
        signer_pubkey: signer.to_owned(),
        retention_tier: RetentionTier::Friend,
        declared_type: content_type.to_owned(),
        grant_id: Some(core_group_grant_id(&group.0, &group.1)),
        claim_expires_at: Some(CORE_GRANT_SENTINEL),
        byte_limit: Some(bytes),
        class: None,
    }
}

/// A member that may use `scope` right now.
struct Granted {
    group: GroupId,
    active: ActiveGrant,
}

impl Grants {
    fn verify_group_token(
        &self,
        headers: &HeaderMap,
        verb: Verb,
        hash: Option<&str>,
    ) -> Result<Token, Refusal> {
        let state = self.group_state()?;
        group_token::verify(headers, verb, hash, &state.hosts, self.now())
    }

    async fn blocking<R: Send + 'static>(
        &self,
        work: impl FnOnce(&Grants) -> Result<R, Refusal> + Send + 'static,
    ) -> Result<R, Refusal> {
        let grants = self.clone();
        spawn_blocking(move || work(&grants))
            .await
            .map_err(|_| Refusal::unavailable())?
    }

    fn core_store(&self) -> Result<wildbloom_core::Store, Refusal> {
        self.inner
            .app
            .get()
            .map(|app| app.store().clone())
            .ok_or_else(Refusal::unavailable)
    }

    /// The member's active grant when it allows `scope`; `Ok(None)` for an
    /// authority key, whose requests the core judges; a refusal otherwise.
    fn member_with(&self, signer: &str, scope: Scope) -> Result<Option<Granted>, Refusal> {
        match self.group_who(signer) {
            Who::Member {
                group,
                active: Some(active),
            } if active.allows(scope) => Ok(Some(Granted { group, active })),
            Who::Authority => Ok(None),
            _ => Err(not_granted()),
        }
    }

    /// `GET` and `HEAD` of a blob: a `get` token from a key with an active
    /// `get` grant, and a blob its group holds.  A blob another group or the
    /// owner holds answers as one nobody holds.
    async fn group_read(
        &self,
        request: Request,
        next: Next,
        hash: Option<String>,
    ) -> Result<Response, Refusal> {
        let token = self.verify_group_token(request.headers(), Verb::Get, hash.as_deref())?;
        let held = match self.group_who(&token.signer) {
            Who::Member {
                group,
                active: Some(active),
            } if active.allows(Scope::Get) => {
                let hash = hash.ok_or_else(absent)?;
                self.blocking(move |grants| {
                    grants.with_holdings(&group, |held| held.contains(&hash))
                })
                .await?
            }
            Who::Authority => {
                let hash = hash.ok_or_else(absent)?;
                let store = self.core_store()?;
                let signer = token.signer;
                self.blocking(move |_| {
                    claims::holds_claim(&store, &signer, &hash).map_err(|_| Refusal::unavailable())
                })
                .await?
            }
            _ => return Err(not_granted()),
        };
        if !held {
            return Err(absent());
        }
        Ok(next.run(request).await)
    }

    /// `GET /list/<pubkey>` stays self-only and needs an `upload` grant.
    async fn group_list(&self, request: Request, next: Next) -> Result<Response, Refusal> {
        let token = self.verify_group_token(request.headers(), Verb::List, None)?;
        self.member_with(&token.signer, Scope::Upload)?;
        Ok(next.run(request).await)
    }

    /// `PUT /upload`: checked, then written through the store as a friend
    /// claim in the signer's group.
    async fn group_upload(&self, request: Request, next: Next) -> Result<Response, Refusal> {
        let headers = request.headers();
        let hash = canonical_hash(header_text(headers, "x-sha-256")).ok_or_else(bad_request)?;
        let length = header_text(headers, "content-length")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(bad_request)?;
        let content_type = header_text(headers, "content-type")
            .filter(|value| !value.is_empty() && value.len() <= 255)
            .unwrap_or("application/octet-stream")
            .to_owned();
        let token = self.verify_group_token(headers, Verb::Upload, Some(&hash))?;
        let Some(granted) = self.member_with(&token.signer, Scope::Upload)? else {
            return Ok(next.run(request).await);
        };
        let bytes = granted.active.bytes.ok_or_else(internal)?;
        let permit = self
            .group_writes()
            .ok_or_else(Refusal::unavailable)?
            .try_acquire_owned()
            .map_err(|_| Refusal::new(StatusCode::TOO_MANY_REQUESTS, "busy"))?;

        // The group ceiling is enforced before a byte is read.
        let ceiling = self.group_ceiling(&granted.group.0).ok_or_else(internal)?;
        let (held, admitted) = {
            let (group, hash) = (granted.group.clone(), hash.clone());
            self.blocking(move |grants| {
                let held = grants.with_holdings(&group, |held| held.contains(&hash))?;
                let need = if held { 0 } else { length };
                let admitted = grants.reserve_group_bytes(&group, ceiling, need)?;
                Ok((held, admitted))
            })
            .await?
        };
        let admitted = admitted.ok_or_else(group_full)?;

        let claim = claim_spec(&granted.group, &token.signer, bytes, &content_type);
        let store = self.core_store()?;
        let started = {
            let (store, hash) = (store.clone(), hash.clone());
            spawn_blocking(move || store.begin_claimed_upload(&hash, length, claim))
                .await
                .map_err(|_| internal())?
                .map_err(store_refusal)?
        };
        let (metadata, created) = match started {
            UploadStart::Existing(metadata) => (metadata, false),
            UploadStart::Reserved(reservation) => {
                let mut options = tokio::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                options.mode(0o600);
                let mut file = options
                    .open(reservation.temp_path())
                    .await
                    .map_err(|_| internal())?;
                let (_, body) = request.into_parts();
                let mut stream = bounded_body(body).into_data_stream();
                let mut hasher = Sha256::new();
                let mut received = 0_u64;
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|_| bad_request())?;
                    received = received
                        .checked_add(chunk.len() as u64)
                        .filter(|received| *received <= reservation.expected_size())
                        .ok_or_else(bad_request)?;
                    hasher.update(&chunk);
                    file.write_all(&chunk).await.map_err(|_| internal())?;
                }
                if received != reservation.expected_size() {
                    return Err(bad_request());
                }
                file.flush().await.map_err(|_| internal())?;
                file.sync_all().await.map_err(|_| internal())?;
                drop(file);
                let actual = hex::encode(hasher.finalize());
                let metadata = spawn_blocking(move || reservation.commit(&actual, received))
                    .await
                    .map_err(|_| internal())?
                    .map_err(store_refusal)?;
                (metadata, true)
            }
        };
        {
            let (group, metadata) = (granted.group.clone(), metadata.clone());
            self.blocking(move |grants| {
                grants.with_holdings(&group, |held| held.insert(&metadata.sha256, metadata.size))
            })
            .await?;
        }
        drop(admitted);
        drop(permit);
        // 201 when the signer's group did not hold the blob, whatever any
        // other group or the owner holds: the status is not an oracle.
        let status = if held && !created {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        };
        Ok(self.descriptor(status, &metadata))
    }

    fn descriptor(&self, status: StatusCode, metadata: &BlobMetadata) -> Response {
        let url = format!(
            "{}/{}.{}",
            self.inner.origin.trim_end_matches('/'),
            metadata.sha256,
            extension_for(&metadata.content_type)
        );
        let mut response = (
            status,
            axum::Json(serde_json::json!({
                "url": url,
                "sha256": metadata.sha256,
                "size": metadata.size,
                "type": metadata.content_type,
                "uploaded": metadata.uploaded,
                "class": null,
            })),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }

    /// `HEAD /upload` (BUD-06): the same decision as the upload, without a body.
    async fn group_preflight(&self, request: Request, next: Next) -> Result<Response, Refusal> {
        let headers = request.headers();
        let hash = canonical_hash(header_text(headers, "x-sha-256")).ok_or_else(bad_request)?;
        let length = header_text(headers, "x-content-length")
            .ok_or(Refusal::new(StatusCode::LENGTH_REQUIRED, "bad-request"))?
            .parse::<u64>()
            .map_err(|_| bad_request())?;
        let content_type = header_text(headers, "x-content-type")
            .filter(|value| !value.is_empty() && value.len() <= 255)
            .ok_or_else(bad_request)?
            .to_owned();
        let token = self.verify_group_token(headers, Verb::Upload, Some(&hash))?;
        let Some(granted) = self.member_with(&token.signer, Scope::Upload)? else {
            return Ok(next.run(request).await);
        };
        let bytes = granted.active.bytes.ok_or_else(internal)?;
        let ceiling = self.group_ceiling(&granted.group.0).ok_or_else(internal)?;
        let (group, held_hash) = (granted.group.clone(), hash.clone());
        let fits = self
            .blocking(move |grants| {
                grants.with_holdings(&group, |held| {
                    held.contains(&held_hash) || held.total().saturating_add(length) <= ceiling
                })
            })
            .await?;
        if !fits {
            return Err(group_full());
        }
        let claim = claim_spec(&granted.group, &token.signer, bytes, &content_type);
        let store = self.core_store()?;
        spawn_blocking(move || store.check_claimed_upload(&hash, length, &claim))
            .await
            .map_err(|_| internal())?
            .map_err(store_refusal)?;
        Ok(Response::new(Body::empty()))
    }

    /// `PUT /mirror`: the core fetches and stores; the gate decides who may
    /// ask, refuses a full group first, and takes back a mirror that would
    /// put the group over its ceiling.
    async fn group_mirror(&self, request: Request, next: Next) -> Result<Response, Refusal> {
        let (parts, body) = request.into_parts();
        let body = to_bytes(body, MIRROR_BODY_BYTES)
            .await
            .map_err(|_| Refusal::new(StatusCode::PAYLOAD_TOO_LARGE, "too-large"))?;
        let hash = mirror_hash(&body);
        let token = self.verify_group_token(&parts.headers, Verb::Upload, hash.as_deref())?;
        let granted = self.member_with(&token.signer, Scope::Upload)?;
        let request = Request::from_parts(parts, Body::from(body));
        let Some(granted) = granted else {
            return Ok(next.run(request).await);
        };
        let ceiling = self.group_ceiling(&granted.group.0).ok_or_else(internal)?;
        let held_before = {
            let (group, hash) = (granted.group.clone(), hash.clone());
            self.blocking(move |grants| {
                grants.with_holdings(&group, |held| {
                    (
                        hash.as_deref().is_some_and(|hash| held.contains(hash)),
                        held.total(),
                    )
                })
            })
            .await?
        };
        if !held_before.0 && held_before.1 >= ceiling {
            return Err(group_full());
        }
        let response = next.run(request).await;
        if !response.status().is_success() {
            return Ok(response);
        }
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, DESCRIPTOR_BYTES)
            .await
            .map_err(|_| internal())?;
        let descriptor: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        let named = descriptor["sha256"]
            .as_str()
            .zip(descriptor["size"].as_u64())
            .map(|(hash, size)| (hash.to_owned(), size));
        if let Some((hash, size)) = named {
            let group = granted.group.clone();
            let store = self.core_store()?;
            let signer = token.signer.clone();
            let over = self
                .blocking(move |grants| {
                    grants.with_holdings(&group, |held| {
                        held.insert(&hash, size);
                        if !held_before.0 && held.total() > ceiling {
                            // The claim is new, so taking it back loses nothing.
                            let _ = store.delete_claim(&hash, &signer);
                            held.remove(&hash);
                            return true;
                        }
                        false
                    })
                })
                .await?;
            if over {
                return Err(group_full());
            }
        }
        Ok(Response::from_parts(parts, Body::from(bytes)))
    }

    /// `DELETE /<sha256>`: a `delete` token and one of an active `delete`
    /// grant (the signer's own claim), an active `purge` grant (every claim
    /// the group holds), or a `delete` grant that ended less than seven days
    /// ago (the signer's own claim).  A delete token is spent once.
    async fn group_delete(
        &self,
        request: Request,
        next: Next,
        hash: Option<String>,
    ) -> Result<Response, Refusal> {
        let token = self.verify_group_token(request.headers(), Verb::Delete, hash.as_deref())?;
        let (group, purge) = match self.group_who(&token.signer) {
            Who::Authority => return Ok(next.run(request).await),
            Who::Member { group, active } => {
                let purge = active.is_some_and(|active| active.allows(Scope::Purge));
                let own = active.is_some_and(|active| active.allows(Scope::Delete))
                    || self.group_in_grace(&token.signer, Scope::Delete);
                if !purge && !own {
                    return Err(not_granted());
                }
                (group, purge)
            }
            Who::Stranger => return Err(not_granted()),
        };
        let hash = hash.ok_or_else(absent)?;
        let store = self.core_store()?;
        let deleted = {
            let hash = hash.clone();
            self.blocking(move |grants| {
                let fresh = grants.spend_group_token(&token.event_id, token.expiration)?;
                let claimants = if purge {
                    grants.group_devices(&group)
                } else {
                    vec![token.signer.clone()]
                };
                let mut holders = Vec::new();
                for key in claimants {
                    if claims::holds_claim(&store, &key, &hash)
                        .map_err(|_| Refusal::unavailable())?
                    {
                        holders.push(key);
                    }
                }
                if holders.is_empty() {
                    return Err(absent());
                }
                if !fresh {
                    return Err(Refusal::conflict("spent"));
                }
                let mut blob_deleted = false;
                for key in &holders {
                    match store.delete_claim(&hash, key) {
                        Ok(DeleteOutcome::BlobDeleted) => blob_deleted = true,
                        Ok(DeleteOutcome::ClaimRemoved)
                        | Err(StoreError::NotClaimant | StoreError::MissingBlob) => {}
                        Err(error) => return Err(store_refusal(error)),
                    }
                }
                // The group still holds the blob while any of its keys claims it.
                let mut still = false;
                for key in grants.group_devices(&group) {
                    still |= claims::holds_claim(&store, &key, &hash)
                        .map_err(|_| Refusal::unavailable())?;
                }
                if !still {
                    grants.with_holdings(&group, |held| held.remove(&hash))?;
                }
                Ok(blob_deleted)
            })
            .await?
        };
        let mut response = axum::Json(serde_json::json!({
            "sha256": hash,
            "blobDeleted": deleted,
        }))
        .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        Ok(response)
    }
}
