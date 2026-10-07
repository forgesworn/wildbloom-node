use crate::{Checkout, Error, authenticate, now};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Admission {
    concurrent: Arc<tokio::sync::Semaphore>,
    window: Mutex<(Instant, u32)>,
}
async fn admit(
    State(limits): State<Arc<Admission>>,
    request: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let permit = match limits.concurrent.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Error::Busy.into_response(),
    };
    {
        let mut window = match limits.window.lock() {
            Ok(window) => window,
            Err(_) => return Error::Internal.into_response(),
        };
        if window.0.elapsed() >= Duration::from_secs(60) {
            *window = (Instant::now(), 0);
        }
        if window.1 >= 120 {
            return Error::Busy.into_response();
        }
        window.1 += 1;
    }
    // A dropped HTTP request must not free its slot while SQLite or a journalled
    // receiving operation is still executing. Keep the permit with the worker.
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        runtime.block_on(next.run(request))
    })
    .await
    .unwrap_or_else(|_| Error::Internal.into_response())
}

/// Opt-in routes. Mount at the origin root; URL rewriting breaks exact NIP-98
/// binding. Host and forwarded headers are never used to construct signed URLs.
pub fn router(checkout: Checkout) -> Router {
    Router::new()
        .route("/checkout/v1/offers", get(offers))
        .route("/checkout/v1/orders", post(handle))
        .route("/checkout/v1/orders/{id}", get(handle))
        .route("/checkout/v1/orders/{id}/lightning", post(handle))
        .route("/checkout/v1/orders/{id}/lnurlcash", post(handle))
        .route("/checkout/v1/orders/{id}/check", post(handle))
        .with_state(checkout)
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(Admission {
                concurrent: Arc::new(tokio::sync::Semaphore::new(4)),
                window: Mutex::new((Instant::now(), 0)),
            }),
            admit,
        ))
        .layer(axum::middleware::map_response(no_store))
}
async fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}
async fn offers(State(c): State<Checkout>) -> impl IntoResponse {
    axum::Json(
        serde_json::json!({"version":1,"seller_id":c.config().seller_id,"seller_name":c.config().seller_name,"node_origin":c.config().origin,"network":c.config().network,"offers":c.config().offers,"rails":c.rails(),"issuers":c.config().issuers}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Consent {
    quote_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Note {
    quote_digest: String,
    note: String,
}
async fn handle(State(c): State<Checkout>, request: Request<Body>) -> Response {
    match execute(c, request).await {
        Ok(order) => axum::Json(order).into_response(),
        Err(error) => error.into_response(),
    }
}
async fn execute(c: Checkout, request: Request<Body>) -> Result<crate::Order, Error> {
    let (parts, body) = request.into_parts();
    if parts.uri.query().is_some() {
        return Err(Error::Invalid);
    }
    let path = parts.uri.path();
    let mut headers = parts.headers.get_all(header::AUTHORIZATION).iter();
    let header = headers
        .next()
        .ok_or(Error::Unauthorised)?
        .to_str()
        .map_err(|_| Error::Unauthorised)?;
    if headers.next().is_some() {
        return Err(Error::Unauthorised);
    }
    let body = tokio::time::timeout(Duration::from_secs(10), to_bytes(body, 16_384))
        .await
        .map_err(|_| Error::Invalid)?
        .map_err(|_| Error::Invalid)?;
    let url = format!("{}{}", c.config().origin.trim_end_matches('/'), path);
    let principal = authenticate(header, &url, parts.method.as_str(), &body, now()?)?;
    if path == "/checkout/v1/orders" {
        return c.quote(&principal, serde_json::from_slice(&body)?).await;
    }
    let tail = path
        .strip_prefix("/checkout/v1/orders/")
        .ok_or(Error::NotFound)?;
    let (id, action) = tail.split_once('/').unwrap_or((tail, ""));
    match action {
        "" => c.order(&principal, id),
        "lightning" => {
            let input: Consent = serde_json::from_slice(&body)?;
            c.lightning(&principal, id, &input.quote_digest).await
        }
        "lnurlcash" => {
            let input: Note = serde_json::from_slice(&body)?;
            c.lnurlcash(&principal, id, &input.quote_digest, &input.note)
                .await
        }
        "check" => {
            let input: Consent = serde_json::from_slice(&body)?;
            c.check(&principal, id, &input.quote_digest).await
        }
        _ => Err(Error::NotFound),
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let code = match self {
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Unauthorised => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Expired => StatusCode::GONE,
            Self::Conflict | Self::Pending => StatusCode::CONFLICT,
            Self::Capacity => StatusCode::SERVICE_UNAVAILABLE,
            Self::Unavailable => StatusCode::BAD_GATEWAY,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            code,
            axum::Json(serde_json::json!({"error":self.to_string()})),
        )
            .into_response()
    }
}
