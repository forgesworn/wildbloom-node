//! Loopback-only synthetic receiving services for browser/daemon acceptance.
//! Never package this example or use its public test keys for real money.
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use bitcoin::{
    hashes::{Hash, sha256},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
};
use lightning_invoice::{Currency, InvoiceBuilder};
use lightning_types::payment::PaymentSecret;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[derive(Default)]
struct Data {
    invoices: HashMap<String, Value>,
    paid: bool,
    spent: HashSet<String>,
    outputs: HashSet<String>,
    creates: usize,
    rotations: usize,
}
#[derive(Clone)]
struct Fixture {
    origin: String,
    data: Arc<Mutex<Data>>,
}
fn key() -> SecretKey {
    SecretKey::from_slice(&[7; 32]).unwrap()
}
fn pubkey() -> String {
    PublicKey::from_secret_key(&Secp256k1::new(), &key()).to_string()
}
fn certificate(hash: &str) -> String {
    let message = Message::from_digest(lnurlcash_core::note_signature_digest_for_hash(hash, 10000));
    let (recovery, signature) = Secp256k1::new()
        .sign_ecdsa_recoverable(&message, &key())
        .serialize_compact();
    let mut bytes = signature.to_vec();
    bytes.push(recovery.to_i32() as u8);
    hex::encode(bytes)
}
async fn invoice(State(f): State<Fixture>, body: String) -> Result<Json<Value>, StatusCode> {
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let amount = form
        .get("amountSat")
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let expiry = form
        .get("expirySeconds")
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let id = form.get("externalId").ok_or(StatusCode::BAD_REQUEST)?;
    let preimage = sha256::Hash::hash(id.as_bytes()).to_byte_array();
    let hash = sha256::Hash::hash(&preimage);
    let signed = InvoiceBuilder::new(Currency::Bitcoin)
        .description(id.clone())
        .amount_milli_satoshis(amount * 1000)
        .payment_hash(hash)
        .payment_secret(PaymentSecret([42; 32]))
        .duration_since_epoch(Duration::from_secs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ))
        .expiry_time(Duration::from_secs(expiry))
        .min_final_cltv_expiry_delta(144)
        .build_signed(|m| Secp256k1::new().sign_ecdsa_recoverable(m, &key()))
        .unwrap()
        .to_string();
    let mut data = f.data.lock().unwrap();
    data.creates += 1;
    data.invoices.insert(hash.to_string(),json!({"paymentHash":hash.to_string(),"invoice":signed,"externalId":id,"preimage":hex::encode(preimage)}));
    Ok(Json(
        json!({"serialized":signed,"paymentHash":hash.to_string()}),
    ))
}
async fn incoming(
    State(f): State<Fixture>,
    Path(hash): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let data = f.data.lock().unwrap();
    let mut row = data
        .invoices
        .get(&hash)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();
    row["isPaid"] = json!(data.paid);
    if !data.paid {
        row["preimage"] = Value::Null;
    }
    Ok(Json(row))
}
async fn note(
    State(f): State<Fixture>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let k1 = q.get("k1").ok_or(StatusCode::BAD_REQUEST)?;
    let hash = lnurlcash_core::hash_k1(k1).map_err(|_| StatusCode::BAD_REQUEST)?;
    let data = f.data.lock().unwrap();
    if data.spent.contains(k1) || (k1 != &hex::encode([6; 32]) && !data.outputs.contains(&hash)) {
        return Ok(Json(json!({"status":"ERROR","reason":"unavailable"})));
    }
    Ok(Json(
        json!({"tag":"withdrawRequest","callback":format!("{}callback",f.origin),"k1":k1,"minWithdrawable":10000,"maxWithdrawable":10000,"mintPubkey":pubkey(),"sig":certificate(&hash)}),
    ))
}
async fn rotate(
    State(f): State<Fixture>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let k1 = q.get("k1").ok_or(StatusCode::BAD_REQUEST)?;
    let output = q.get("p1").ok_or(StatusCode::BAD_REQUEST)?;
    let mut data = f.data.lock().unwrap();
    if !data.spent.insert(k1.clone()) {
        return Ok(Json(json!({"status":"ERROR","reason":"spent"})));
    }
    data.outputs.insert(output.clone());
    data.rotations += 1;
    Ok(Json(json!({"status":"OK","sig":certificate(output)})))
}
async fn pay(State(f): State<Fixture>) -> Json<Value> {
    f.data.lock().unwrap().paid = true;
    Json(json!({"ok":true}))
}
async fn info(State(f): State<Fixture>) -> Json<Value> {
    let data = f.data.lock().unwrap();
    Json(
        json!({"origin":f.origin,"mint_pubkey":pubkey(),"invoice_creations":data.creates,"note_rotations":data.rotations}),
    )
}
#[tokio::main]
async fn main() {
    let port = std::env::args()
        .nth(1)
        .expect("loopback port")
        .parse::<u16>()
        .unwrap();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let fixture = Fixture {
        origin: format!(
            "http://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        ),
        data: Arc::default(),
    };
    let app = Router::new()
        .route("/", get(info))
        .route("/fixture/pay", post(pay))
        .route("/createinvoice", post(invoice))
        .route("/payments/incoming/{hash}", get(incoming))
        .route("/w", get(note))
        .route("/callback", get(rotate))
        .with_state(fixture);
    axum::serve(listener, app).await.unwrap();
}
