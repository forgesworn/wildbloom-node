use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use bitcoin::{
    hashes::{Hash, sha256},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
};
use lightning_invoice::{Currency, InvoiceBuilder};
use lightning_types::payment::PaymentSecret;
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use toll_booth::{
    backends::LightningBackend,
    types::{BackendError, Invoice, InvoiceStatus},
};
use wildbloom_core::{Store, StoreConfig};

fn keys(n: u8) -> Keys {
    Keys::parse(&hex::encode([n; 32])).unwrap()
}
fn auth(
    keys: &Keys,
    url: &str,
    method: &str,
    body: &[u8],
    time: u64,
    extra: Vec<Vec<String>>,
) -> String {
    let mut tags = vec![
        vec!["u".into(), url.into()],
        vec!["method".into(), method.into()],
    ];
    if method == "POST" {
        tags.push(vec!["payload".into(), digest(body)]);
    }
    tags.extend(extra);
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
        .custom_created_at(Timestamp::from(time))
        .finalize(keys)
        .unwrap();
    format!(
        "Nostr {}",
        STANDARD.encode(serde_json::to_vec(&event).unwrap())
    )
}
fn principal(n: u8) -> Principal {
    let k = keys(n);
    let url = "https://node.example/checkout/v1/orders";
    authenticate(
        &auth(&k, url, "POST", b"{}", now().unwrap(), vec![]),
        url,
        "POST",
        b"{}",
        now().unwrap(),
    )
    .unwrap()
}
fn mint_key() -> SecretKey {
    SecretKey::from_slice(&[7; 32]).unwrap()
}
fn mint_pubkey() -> String {
    PublicKey::from_secret_key(&Secp256k1::new(), &mint_key()).to_string()
}
fn config() -> Config {
    Config {
        origin: "https://node.example/".into(),
        seller_id: "synthetic-operator".into(),
        seller_name: "Synthetic operator".into(),
        network: Network::Bitcoin,
        quote_seconds: 600,
        allow_loopback_http: false,
        tor_only: false,
        offers: vec![Offer {
            id: "small".into(),
            revision: 1,
            capacity_bytes: 100,
            duration_seconds: 3600,
            grace_seconds: 60,
            price_msat: 10_000,
            delivery_bytes: 1000,
            delivery_policy: "Operator test delivery policy".into(),
            retention_policy: "Test retention terms".into(),
            refund_policy: "Operator handles refunds directly".into(),
        }],
        issuers: vec![Issuer {
            id: "test-mint".into(),
            note_endpoint: "https://mint.example/w".into(),
            callback: "https://mint.example/callback".into(),
            mint_pubkey: mint_pubkey(),
        }],
    }
}
fn request(id: &str, rail: Rail) -> QuoteRequest {
    QuoteRequest {
        request_id: id.into(),
        offer_id: "small".into(),
        rail,
        issuer_id: (rail == Rail::Lnurlcash).then(|| "test-mint".into()),
        renews: None,
        refund_to: None,
    }
}
fn invoice(amount: u64, network: Currency, expiry: u64, preimage: [u8; 32]) -> Invoice {
    let hash = sha256::Hash::hash(&preimage);
    let signed = InvoiceBuilder::new(network)
        .description("synthetic storage".into())
        .amount_milli_satoshis(amount)
        .payment_hash(hash)
        .payment_secret(PaymentSecret([42; 32]))
        .duration_since_epoch(Duration::from_secs(now().unwrap()))
        .expiry_time(Duration::from_secs(expiry))
        .min_final_cltv_expiry_delta(144)
        .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &mint_key()))
        .unwrap();
    Invoice {
        bolt11: signed.to_string(),
        payment_hash: hash.to_string(),
    }
}
struct Lightning {
    invoice: Mutex<Invoice>,
    status: Mutex<InvoiceStatus>,
    creates: AtomicUsize,
    checks: AtomicUsize,
    fail: bool,
}
impl Lightning {
    fn new() -> Self {
        Self {
            invoice: Mutex::new(invoice(10_000, Currency::Bitcoin, 300, [3; 32])),
            status: Mutex::new(InvoiceStatus {
                paid: true,
                preimage: Some(hex::encode([3; 32])),
            }),
            creates: AtomicUsize::new(0),
            checks: AtomicUsize::new(0),
            fail: false,
        }
    }
}
#[async_trait::async_trait]
impl LightningBackend for Lightning {
    async fn create_invoice(
        &self,
        amount: u64,
        _memo: Option<&str>,
    ) -> Result<Invoice, BackendError> {
        assert_eq!(amount, 10);
        self.creates.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(BackendError::Request("secret backend diagnostic".into()));
        }
        Ok(self.invoice.lock().unwrap().clone())
    }
    async fn check_invoice(&self, _hash: &str) -> Result<InvoiceStatus, BackendError> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        Ok(self.status.lock().unwrap().clone())
    }
}
struct Fixture {
    root: tempfile::TempDir,
    ledger: Ledger,
    store: Store,
    lightning: Arc<Lightning>,
    checkout: Checkout,
}
impl Fixture {
    fn new() -> Self {
        Self::with_lightning(Lightning::new())
    }
    fn with_lightning(lightning: Lightning) -> Self {
        let root = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(&root.path().join("checkout")).unwrap();
        let store = Store::open(StoreConfig {
            root: root.path().join("storage"),
            quota_bytes: 1000,
            max_blob_bytes: 100,
        })
        .unwrap();
        let lightning = Arc::new(lightning);
        let checkout = Checkout::new(
            config(),
            ledger.clone(),
            store.clone(),
            Some(lightning.clone()),
            None,
        )
        .unwrap();
        Self {
            root,
            ledger,
            store,
            lightning,
            checkout,
        }
    }
    async fn quoted(&self) -> (Principal, Order) {
        let p = principal(1);
        let order = self
            .checkout
            .quote(&p, request("one", Rail::Lightning))
            .await
            .unwrap();
        (p, order)
    }
}
#[test]
fn authentication_binds_exact_body_url_method_time_and_signature() {
    let key = keys(1);
    let url = "https://node.example/checkout/v1/orders";
    let t = now().unwrap();
    let header = auth(&key, url, "POST", b"{}", t, vec![]);
    assert!(authenticate(&header, url, "POST", b"{}", t).is_ok());
    for (u, m, b, time) in [
        (
            "https://other.example/checkout/v1/orders",
            "POST",
            b"{}".as_slice(),
            t,
        ),
        (url, "GET", b"{}".as_slice(), t),
        (url, "POST", b"{ }".as_slice(), t),
        (url, "POST", b"{}".as_slice(), t + 61),
        (url, "POST", b"{}".as_slice(), t - 31),
    ] {
        assert!(authenticate(&header, u, m, b, time).is_err());
    }
    for extra in [
        vec![vec!["u".into(), url.into()]],
        vec![vec!["method".into(), "POST".into()]],
        vec![vec!["payload".into(), digest(b"{}")]],
    ] {
        assert!(
            authenticate(
                &auth(&key, url, "POST", b"{}", t, extra),
                url,
                "POST",
                b"{}",
                t
            )
            .is_err()
        );
    }
    let mut value: serde_json::Value = serde_json::from_slice(
        &STANDARD
            .decode(header.strip_prefix("Nostr ").unwrap())
            .unwrap(),
    )
    .unwrap();
    value["sig"] = serde_json::json!("00".repeat(64));
    let forged = format!(
        "Nostr {}",
        STANDARD.encode(serde_json::to_vec(&value).unwrap())
    );
    assert!(authenticate(&forged, url, "POST", b"{}", t).is_err());
    assert!(authenticate(&auth(&key, url, "GET", b"", t, vec![]), url, "GET", b"", t).is_ok());
}
#[test]
fn configuration_refuses_unreviewed_transports_and_bad_terms() {
    let mut c = config();
    assert!(c.validate().is_ok());
    c.tor_only = true;
    assert!(c.validate().is_err());
    for origin in [
        "http://node.example/",
        "https://node.example/path",
        "https://user@node.example/",
        "https://test.onion/",
        "https://node.example/?secret=x",
    ] {
        let mut c = config();
        c.origin = origin.into();
        assert!(c.validate().is_err());
    }
    let mut c = config();
    c.issuers[0].callback = "https://other.example/callback".into();
    assert!(c.validate().is_err());
    let mut c = config();
    c.offers[0].price_msat = 999;
    assert!(c.validate().is_err());
}
#[tokio::test]
async fn durable_quotes_reserve_capacity_and_do_not_reprice_or_cross_signers() {
    let f = Fixture::new();
    let (p, o) = f.quoted().await;
    assert_eq!(o.state, State::Quoted);
    assert_eq!(f.store.committed_bytes().unwrap(), 100);
    let (a, b) = tokio::join!(
        f.checkout.quote(&p, request("one", Rail::Lightning)),
        f.checkout.quote(&p, request("one", Rail::Lightning))
    );
    assert_eq!(a.unwrap().quote_digest, b.unwrap().quote_digest);
    assert_eq!(f.store.committed_bytes().unwrap(), 100);
    let mut c = config();
    c.offers[0].price_msat = 50_000;
    let changed = Checkout::new(
        c,
        f.ledger.clone(),
        f.store.clone(),
        Some(f.lightning.clone()),
        None,
    )
    .unwrap();
    assert_eq!(
        changed
            .quote(&p, request("one", Rail::Lightning))
            .await
            .unwrap()
            .quote
            .offer
            .price_msat,
        10_000
    );
    let mut r = request("one", Rail::Lightning);
    r.offer_id = "other".into();
    assert!(matches!(
        f.checkout.quote(&p, r).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        f.checkout.order(&principal(2), &o.quote.order_id),
        Err(Error::NotFound)
    ));
    assert_eq!(f.lightning.creates.load(Ordering::SeqCst), 0);
    let mut c = config();
    c.offers[0].capacity_bytes = 1000;
    let full = Checkout::new(
        c,
        f.ledger.clone(),
        f.store.clone(),
        Some(f.lightning.clone()),
        None,
    )
    .unwrap();
    assert!(matches!(
        full.quote(&principal(2), request("two", Rail::Lightning))
            .await,
        Err(Error::Capacity)
    ));
    assert_eq!(f.lightning.creates.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn settlement_activates_exactly_once_and_survives_restart() {
    let f = Fixture::new();
    let (p, o) = f.quoted().await;
    let id = &o.quote.order_id;
    assert!(matches!(
        f.checkout.lightning(&p, id, "wrong-consent").await,
        Err(Error::Conflict)
    ));
    let issued = f.checkout.lightning(&p, id, &o.quote_digest).await.unwrap();
    assert_eq!(issued.state, State::AwaitingPayment);
    f.checkout.lightning(&p, id, &o.quote_digest).await.unwrap();
    assert_eq!(f.lightning.creates.load(Ordering::SeqCst), 1);
    let active = f.checkout.check(&p, id, &o.quote_digest).await.unwrap();
    assert_eq!(active.state, State::Active);
    let again = f.checkout.check(&p, id, &o.quote_digest).await.unwrap();
    assert_eq!(active.receipt, again.receipt);
    assert_eq!(f.lightning.checks.load(Ordering::SeqCst), 1);
    assert!(
        f.store
            .paid_claim(p.pubkey(), "application/octet-stream", None)
            .unwrap()
            .is_some()
    );
    let path = f.root.path().join("checkout");
    drop(f.checkout);
    drop(f.ledger);
    let ledger = Ledger::open(&path).unwrap();
    let c = Checkout::new(config(), ledger, f.store, Some(f.lightning), None).unwrap();
    assert_eq!(c.order(&p, id).unwrap().receipt, active.receipt);
}
#[tokio::test]
async fn crash_after_activation_replays_original_result() {
    let f = Fixture::new();
    let (p, o) = f.quoted().await;
    let id = &o.quote.order_id;
    f.checkout.lightning(&p, id, &o.quote_digest).await.unwrap();
    f.ledger
        .settle(
            id,
            State::AwaitingPayment,
            &format!("lightning:{}", digest(&[3; 32])),
            None,
        )
        .unwrap();
    let original = f.store.activate_paid_sale(id).unwrap(); // process dies before ledger commit
    let path = f.root.path().join("checkout");
    drop(f.checkout);
    drop(f.ledger);
    let ledger = Ledger::open(&path).unwrap();
    let c = Checkout::new(config(), ledger, f.store, None, None).unwrap();
    let receipt = c
        .check(&p, id, &o.quote_digest)
        .await
        .unwrap()
        .receipt
        .unwrap();
    assert_eq!(receipt.writes_until, original.writes_until);
}
#[tokio::test]
async fn ambiguous_invoice_creation_never_creates_a_second_invoice() {
    let mut backend = Lightning::new();
    backend.fail = true;
    let f = Fixture::with_lightning(backend);
    let (p, o) = f.quoted().await;
    let id = &o.quote.order_id;
    assert!(matches!(
        f.checkout.lightning(&p, id, &o.quote_digest).await,
        Err(Error::Pending)
    ));
    assert!(matches!(
        f.checkout.lightning(&p, id, &o.quote_digest).await,
        Err(Error::Pending)
    ));
    assert_eq!(f.lightning.creates.load(Ordering::SeqCst), 1);
    let recovered_invoice = f.lightning.invoice.lock().unwrap().clone();
    f.checkout
        .recover_invoice(id, recovered_invoice)
        .await
        .unwrap();
    assert_eq!(
        f.checkout
            .check(&p, id, &o.quote_digest)
            .await
            .unwrap()
            .state,
        State::Active
    );
}
#[tokio::test]
async fn rejects_wrong_invoice_amount_network_hash_expiry_and_bad_preimage() {
    for bad in [
        invoice(20_000, Currency::Bitcoin, 300, [3; 32]),
        invoice(10_000, Currency::BitcoinTestnet, 300, [3; 32]),
        invoice(10_000, Currency::Bitcoin, 3600, [3; 32]),
        Invoice {
            bolt11: "lnbc10_invalid".into(),
            payment_hash: "ab".repeat(32),
        },
    ] {
        let backend = Lightning::new();
        *backend.invoice.lock().unwrap() = bad;
        let f = Fixture::with_lightning(backend);
        let (p, o) = f.quoted().await;
        assert!(matches!(
            f.checkout
                .lightning(&p, &o.quote.order_id, &o.quote_digest)
                .await,
            Err(Error::Pending)
        ));
        assert!(f.store.paid_allowance(&o.quote.order_id).unwrap().is_none());
    }
    let f = Fixture::new();
    let (p, o) = f.quoted().await;
    f.checkout
        .lightning(&p, &o.quote.order_id, &o.quote_digest)
        .await
        .unwrap();
    f.lightning.status.lock().unwrap().preimage = Some(hex::encode([4; 32]));
    assert!(matches!(
        f.checkout
            .check(&p, &o.quote.order_id, &o.quote_digest)
            .await,
        Err(Error::Pending)
    ));
    assert!(f.store.paid_allowance(&o.quote.order_id).unwrap().is_none());
}

fn certificate(output_hash: &str, amount: u64) -> String {
    let message = Message::from_digest(lnurlcash_core::note_signature_digest_for_hash(
        output_hash,
        amount,
    ));
    let (recovery, compact) = Secp256k1::new()
        .sign_ecdsa_recoverable(&message, &mint_key())
        .serialize_compact();
    let mut bytes = compact.to_vec();
    bytes.push(recovery.to_i32() as u8);
    hex::encode(bytes)
}
#[derive(Clone, Copy, PartialEq)]
enum MintMode {
    Normal,
    DropFirst,
    RecoverReplacement,
    BadCallback,
    BadAmount,
    BadKey,
    BadCertificate,
}
struct Mint {
    mode: MintMode,
    requests: Mutex<Vec<String>>,
    db: std::path::PathBuf,
    refund_settled: Mutex<Option<Arc<AtomicBool>>>,
    drop_refund_response: AtomicBool,
}
#[async_trait::async_trait]
impl NoteTransport for Mint {
    async fn get(&self, url: &SensitiveUrl) -> Result<Vec<u8>, TransportFailure> {
        let mut requests = self.requests.lock().unwrap();
        requests.push(url.expose().into());
        let u = url::Url::parse(url.expose()).unwrap();
        let pairs: std::collections::BTreeMap<_, _> = u.query_pairs().collect();
        if u.path() == "/callback" {
            if let Some(pr) = pairs.get("pr") {
                let db = rusqlite::Connection::open(&self.db).unwrap();
                let journal: String = db
                    .query_row(
                        "SELECT refund FROM orders WHERE state='refund_required'",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert!(journal.contains(pr.as_ref()));
                self.refund_settled
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .store(true, Ordering::SeqCst);
                if self.drop_refund_response.swap(false, Ordering::SeqCst) {
                    return Err(TransportFailure);
                }
                return Ok(serde_json::to_vec(&serde_json::json!({
                    "status":"OK", "pr":pr, "verify":"https://mint.example/verify/refund"
                }))
                .unwrap());
            }
            // Assert the replacement and exact request are durable BEFORE money moves.
            let db = rusqlite::Connection::open(&self.db).unwrap();
            let raw: String = db
                .query_row(
                    "SELECT rotation FROM orders WHERE state='lnurl_pending'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let journal: crate::ledger::Rotation = serde_json::from_str(&raw).unwrap();
            assert_eq!(journal.request_url, url.expose());
            assert_eq!(
                lnurlcash_core::hash_k1(&journal.new_secret).unwrap(),
                pairs["p1"]
            );
            if matches!(
                self.mode,
                MintMode::DropFirst | MintMode::RecoverReplacement
            ) && requests.iter().filter(|r| r.contains("/callback?")).count() == 1
            {
                return Err(TransportFailure);
            }
            let sig = if self.mode == MintMode::BadCertificate {
                "00".repeat(65)
            } else {
                certificate(&pairs["p1"], 10_000)
            };
            return Ok(serde_json::to_vec(&serde_json::json!({"status":"OK","sig":sig})).unwrap());
        }
        assert_eq!(u.path(), "/w");
        let k1 = &pairs["k1"];
        if k1 != &hex::encode([6; 32]) && self.mode != MintMode::RecoverReplacement {
            return Ok(br#"{"status":"ERROR","reason":"unknown note"}"#.to_vec());
        }
        let callback = if self.mode == MintMode::BadCallback {
            "https://evil.example/callback"
        } else {
            "https://mint.example/callback"
        };
        let amount = if self.mode == MintMode::BadAmount {
            20_000
        } else {
            10_000
        };
        let pubkey = if self.mode == MintMode::BadKey {
            "02".to_owned() + &"00".repeat(32)
        } else {
            mint_pubkey()
        };
        let hash = lnurlcash_core::hash_k1(k1).unwrap();
        Ok(serde_json::to_vec(&serde_json::json!({"tag":"withdrawRequest","callback":callback,"k1":k1,"minWithdrawable":amount,"maxWithdrawable":amount,"mintPubkey":pubkey,"sig":certificate(&hash,amount)})).unwrap())
    }
}
fn note() -> String {
    format!(
        "https://mint.example/w?k1={}&amount=999",
        hex::encode([6; 32])
    )
}
fn notes(f: &Fixture, mode: MintMode) -> (Checkout, Arc<Mint>) {
    let mint = Arc::new(Mint {
        mode,
        requests: Mutex::new(vec![]),
        db: f.root.path().join("checkout/checkout.sqlite3"),
        refund_settled: Mutex::new(None),
        drop_refund_response: AtomicBool::new(false),
    });
    (
        Checkout::new(
            config(),
            f.ledger.clone(),
            f.store.clone(),
            None,
            Some(mint.clone()),
        )
        .unwrap(),
        mint,
    )
}

struct RefundNet {
    settled: Arc<AtomicBool>,
    invoice: Invoice,
    requests: Mutex<Vec<String>>,
}
#[async_trait::async_trait]
impl RefundTransport for RefundNet {
    async fn get(&self, url: &SensitiveUrl) -> Result<Vec<u8>, TransportFailure> {
        self.requests.lock().unwrap().push(url.expose().into());
        let parsed = url::Url::parse(url.expose()).unwrap();
        let value = match (parsed.host_str().unwrap(), parsed.path()) {
            ("buyer.example", "/.well-known/lnurlp/customer") => serde_json::json!({
                "tag":"payRequest", "callback":"https://buyer.example/callback",
                "minSendable":10_000, "maxSendable":10_000, "metadata":"[]"
            }),
            ("buyer.example", "/callback") => serde_json::json!({
                "pr":self.invoice.bolt11, "verify":"https://buyer.example/verify/refund"
            }),
            ("buyer.example" | "mint.example", "/verify/refund") => serde_json::json!({
                "settled":self.settled.load(Ordering::SeqCst), "pr":self.invoice.bolt11,
                "preimage":self.settled.load(Ordering::SeqCst).then(|| hex::encode([9;32]))
            }),
            _ => return Err(TransportFailure),
        };
        Ok(serde_json::to_vec(&value).unwrap())
    }
}

#[tokio::test]
async fn failed_lnurlcash_fulfilment_refunds_once_from_the_journalled_asset() {
    let f = Fixture::new();
    let (checkout, mint) = notes(&f, MintMode::RecoverReplacement);
    let settled = Arc::new(AtomicBool::new(false));
    *mint.refund_settled.lock().unwrap() = Some(settled.clone());
    mint.drop_refund_response.store(true, Ordering::SeqCst);
    let refund_net = Arc::new(RefundNet {
        settled,
        invoice: invoice(10_000, Currency::Bitcoin, 300, [9; 32]),
        requests: Mutex::new(Vec::new()),
    });
    let checkout = checkout.with_refunds(refund_net.clone());
    let p = principal(1);
    let mut request = request("automatic-refund", Rail::Lnurlcash);
    request.refund_to = Some("customer@buyer.example".into());
    let order = checkout.quote(&p, request).await.unwrap();
    assert!(matches!(
        checkout
            .lnurlcash(&p, &order.quote.order_id, &order.quote_digest, &note())
            .await,
        Err(Error::Pending)
    ));
    rusqlite::Connection::open(f.root.path().join("storage/wildbloom.sqlite3"))
        .unwrap()
        .execute(
            "UPDATE paid_sales SET expires=?1 WHERE id=?2",
            rusqlite::params![(now().unwrap() - 1) as i64, order.quote.order_id],
        )
        .unwrap();
    assert_eq!(
        checkout
            .check(&p, &order.quote.order_id, &order.quote_digest)
            .await
            .unwrap()
            .state,
        State::RefundRequired
    );
    assert!(matches!(
        checkout.refund(&order.quote.order_id).await,
        Err(Error::Pending)
    ));
    let pending = checkout.order(&p, &order.quote.order_id).unwrap();
    assert_eq!(pending.state, State::RefundRequired);
    assert_eq!(pending.refund.unwrap().status, RefundStatus::Pending);
    let melts = mint
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request.contains("pr="))
        .count();
    let refunded = checkout.refund(&order.quote.order_id).await.unwrap();
    assert_eq!(refunded.state, State::Refunded);
    let receipt = refunded.refund.unwrap();
    assert_eq!(receipt.status, RefundStatus::Completed);
    assert_eq!(receipt.amount_msat, 10_000);
    assert!(receipt.refunded_at.is_some());
    assert_eq!(
        mint.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.contains("pr="))
            .count(),
        melts,
        "settlement proof completes a lost-response refund without spending twice"
    );
    let issuer_requests = mint.requests.lock().unwrap().len();
    let refund_requests = refund_net.requests.lock().unwrap().len();
    assert_eq!(
        checkout.refund(&order.quote.order_id).await.unwrap().state,
        State::Refunded
    );
    assert_eq!(mint.requests.lock().unwrap().len(), issuer_requests);
    assert_eq!(refund_net.requests.lock().unwrap().len(), refund_requests);
    let public =
        serde_json::to_string(&checkout.order(&p, &order.quote.order_id).unwrap()).unwrap();
    let private = f.ledger.get(&order.quote.order_id).unwrap().unwrap();
    let journal = private.refund.unwrap();
    assert!(!public.contains(&journal.invoice));
    assert!(!public.contains(&journal.request_url));
    assert!(!public.contains(&private.rotation.unwrap().new_secret));
}
#[tokio::test]
async fn lnurlcash_rotates_before_activation_and_public_state_contains_no_assets() {
    let f = Fixture::new();
    let (c, mint) = notes(&f, MintMode::Normal);
    let p = principal(1);
    let o = c.quote(&p, request("note", Rail::Lnurlcash)).await.unwrap();
    let result = c
        .lnurlcash(&p, &o.quote.order_id, &o.quote_digest, &note())
        .await
        .unwrap();
    assert_eq!(result.state, State::Active);
    let public = serde_json::to_string(&result).unwrap();
    let journal = f
        .ledger
        .get(&o.quote.order_id)
        .unwrap()
        .unwrap()
        .rotation
        .unwrap();
    assert!(!public.contains(&hex::encode([6; 32])));
    assert!(!public.contains(&journal.new_secret));
    assert!(!public.contains("k1="));
    assert!(journal.certificate.is_some());
    let count = mint.requests.lock().unwrap().len();
    c.order(&p, &o.quote.order_id).unwrap();
    assert_eq!(mint.requests.lock().unwrap().len(), count);
    assert!(format!("{:?}", SensitiveUrl::for_test(note())).contains("REDACTED"));
    // The same input cannot buy a second allowance, even if a broken mint says
    // it is still outstanding; the local note identity is globally unique.
    let other = principal(2);
    let second = c
        .quote(&other, request("note2", Rail::Lnurlcash))
        .await
        .unwrap();
    assert!(matches!(
        c.lnurlcash(
            &other,
            &second.quote.order_id,
            &second.quote_digest,
            &note()
        )
        .await,
        Err(Error::Conflict)
    ));
}
#[tokio::test]
async fn ambiguous_rotation_recovers_after_restart_without_changing_secret_or_request() {
    for mode in [MintMode::DropFirst, MintMode::RecoverReplacement] {
        let f = Fixture::new();
        let (c, mint) = notes(&f, mode);
        let p = principal(1);
        let o = c.quote(&p, request("note", Rail::Lnurlcash)).await.unwrap();
        let id = &o.quote.order_id;
        assert!(matches!(
            c.lnurlcash(&p, id, &o.quote_digest, &note()).await,
            Err(Error::Pending)
        ));
        assert_eq!(c.order(&p, id).unwrap().state, State::LnurlPending);
        let original = f.ledger.get(id).unwrap().unwrap().rotation.unwrap();
        assert!(matches!(
            c.lnurlcash(&p, id, &o.quote_digest, &note()).await,
            Err(Error::Conflict)
        ));
        let path = f.root.path().join("checkout");
        drop(c);
        drop(f.checkout);
        drop(f.ledger);
        let ledger = Ledger::open(&path).unwrap();
        let c = Checkout::new(config(), ledger.clone(), f.store, None, Some(mint.clone())).unwrap();
        assert_eq!(
            c.check(&p, id, &o.quote_digest).await.unwrap().state,
            State::Active
        );
        let recovered = ledger.get(id).unwrap().unwrap().rotation.unwrap();
        assert_eq!(recovered.new_secret, original.new_secret);
        assert_eq!(recovered.request_url, original.request_url);
        let requests = mint.requests.lock().unwrap();
        let mutations: Vec<_> = requests
            .iter()
            .filter(|r| r.contains("/callback?"))
            .collect();
        if mode == MintMode::DropFirst {
            assert_eq!(mutations.len(), 2);
            assert_eq!(mutations[0], mutations[1]);
        } else {
            assert_eq!(mutations.len(), 1);
        }
    }
}
#[tokio::test]
async fn lnurlcash_rejects_wrong_issuer_value_certificate_and_mutating_input_urls() {
    for mode in [
        MintMode::BadCallback,
        MintMode::BadAmount,
        MintMode::BadKey,
        MintMode::BadCertificate,
    ] {
        let f = Fixture::new();
        let (c, mint) = notes(&f, mode);
        let p = principal(1);
        let o = c.quote(&p, request("note", Rail::Lnurlcash)).await.unwrap();
        assert!(
            c.lnurlcash(&p, &o.quote.order_id, &o.quote_digest, &note())
                .await
                .is_err()
        );
        assert!(f.store.paid_allowance(&o.quote.order_id).unwrap().is_none());
        if mode != MintMode::BadCertificate {
            assert_eq!(mint.requests.lock().unwrap().len(), 1);
        } else {
            assert!(
                f.ledger
                    .get(&o.quote.order_id)
                    .unwrap()
                    .unwrap()
                    .rotation
                    .is_some()
            );
        }
    }
    let f = Fixture::new();
    let (c, mint) = notes(&f, MintMode::Normal);
    let p = principal(1);
    let o = c.quote(&p, request("note", Rail::Lnurlcash)).await.unwrap();
    for input in [
        format!("{}&p1=bad", note()),
        format!("{}&k1=bad", note()),
        note().replace("mint.example", "evil.example"),
    ] {
        assert!(
            c.lnurlcash(&p, &o.quote.order_id, &o.quote_digest, &input)
                .await
                .is_err()
        );
    }
    assert!(mint.requests.lock().unwrap().is_empty());
    let mut changed = config();
    changed.issuers[0].callback = "https://mint.example/other".into();
    let c = Checkout::new(
        changed,
        f.ledger.clone(),
        f.store.clone(),
        None,
        Some(mint.clone()),
    )
    .unwrap();
    assert!(matches!(
        c.lnurlcash(&p, &o.quote.order_id, &o.quote_digest, &note())
            .await,
        Err(Error::Unavailable)
    ));
    assert!(mint.requests.lock().unwrap().is_empty());
}

#[test]
fn private_ledger_lock_permissions_and_future_schema_are_enforced() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ledger");
    let ledger = Ledger::open(&path).unwrap();
    assert!(matches!(Ledger::open(&path), Err(Error::Conflict)));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [
            &path,
            &path.join("checkout.sqlite3"),
            &path.join("checkout.sqlite3-wal"),
        ] {
            assert_eq!(
                std::fs::metadata(p).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }
    drop(ledger);
    let db = rusqlite::Connection::open(path.join("checkout.sqlite3")).unwrap();
    db.execute_batch("PRAGMA user_version=999").unwrap();
    drop(db);
    assert!(matches!(Ledger::open(&path), Err(Error::Invalid)));
}
#[test]
fn version_one_checkout_migrates_in_place_for_refund_journals() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ledger");
    std::fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let database = path.join("checkout.sqlite3");
    let db = rusqlite::Connection::open(&database).unwrap();
    db.execute_batch(
        "CREATE TABLE orders (
            id TEXT PRIMARY KEY NOT NULL, signer TEXT NOT NULL, request TEXT NOT NULL,
            quote TEXT NOT NULL, digest TEXT NOT NULL, state TEXT NOT NULL,
            invoice TEXT, payment_hash TEXT UNIQUE, rotation TEXT, note_id TEXT UNIQUE,
            settlement TEXT UNIQUE, receipt TEXT
        ); PRAGMA user_version=1;",
    )
    .unwrap();
    drop(db);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    drop(Ledger::open(&path).unwrap());
    let db = rusqlite::Connection::open(database).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    let columns: Vec<String> = db
        .prepare("PRAGMA table_info(orders)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(columns.contains(&"refund".into()));
}
#[tokio::test]
async fn capacity_saga_recovers_and_expired_quotes_do_not_contact_backend() {
    let f = Fixture::new();
    let (p, o) = f.quoted().await;
    // Capacity reserved, then crash before persisting the quoted state.
    f.ledger
        .state(&o.quote.order_id, State::Quoted, State::Reserving)
        .unwrap();
    let retry = f
        .checkout
        .quote(&p, request("one", Rail::Lightning))
        .await
        .unwrap();
    assert_eq!(retry.state, State::Quoted);
    assert_eq!(f.store.committed_bytes().unwrap(), 100);
    // Move the local quote deadline back to exercise the expiry boundary without sleeping.
    let db = rusqlite::Connection::open(f.root.path().join("checkout/checkout.sqlite3")).unwrap();
    let mut quote = o.quote.clone();
    quote.expires_at = now().unwrap() - 1;
    db.execute(
        "UPDATE orders SET quote=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&quote).unwrap(), o.quote.order_id],
    )
    .unwrap();
    assert!(matches!(
        f.checkout
            .lightning(&p, &o.quote.order_id, &o.quote_digest)
            .await,
        Err(Error::Expired)
    ));
    assert_eq!(f.lightning.creates.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn late_settlement_requires_refund_without_granting_storage() {
    let f = Fixture::new();
    let (p, o) = f.quoted().await;
    f.checkout
        .lightning(&p, &o.quote.order_id, &o.quote_digest)
        .await
        .unwrap();
    // Expire only the underlying hold, as if the process missed its deadline.
    let db = rusqlite::Connection::open(f.root.path().join("storage/wildbloom.sqlite3")).unwrap();
    db.execute(
        "UPDATE paid_sales SET expires=?1 WHERE id=?2",
        rusqlite::params![(now().unwrap() - 1) as i64, o.quote.order_id],
    )
    .unwrap();
    let result = f
        .checkout
        .check(&p, &o.quote.order_id, &o.quote_digest)
        .await
        .unwrap();
    assert_eq!(result.state, State::RefundRequired);
    assert!(result.receipt.is_none());
    assert!(f.store.paid_allowance(&o.quote.order_id).unwrap().is_none());
    assert_eq!(
        f.checkout
            .check(&p, &o.quote.order_id, &o.quote_digest)
            .await
            .unwrap()
            .state,
        State::RefundRequired
    );
}
#[tokio::test]
async fn one_invoice_cannot_settle_two_orders() {
    let f = Fixture::new();
    let (p, o) = f.quoted().await;
    f.checkout
        .lightning(&p, &o.quote.order_id, &o.quote_digest)
        .await
        .unwrap();
    let other = principal(2);
    let second = f
        .checkout
        .quote(&other, request("two", Rail::Lightning))
        .await
        .unwrap();
    assert!(matches!(
        f.checkout
            .lightning(&other, &second.quote.order_id, &second.quote_digest)
            .await,
        Err(Error::Conflict)
    ));
    assert!(
        f.checkout
            .order(&other, &second.quote.order_id)
            .unwrap()
            .invoice
            .is_none()
    );
}
async fn api(
    app: axum::Router,
    key: &Keys,
    path: &str,
    method: &str,
    body: &[u8],
) -> axum::response::Response {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header(
            "authorization",
            auth(
                key,
                &format!("https://node.example{path}"),
                method,
                body,
                now().unwrap(),
                vec![],
            ),
        )
        .body(axum::body::Body::from(body.to_vec()))
        .unwrap();
    app.oneshot(request).await.unwrap()
}
async fn order_response(response: axum::response::Response) -> Order {
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap()
}
fn upload(key: &Keys, bytes: &[u8]) -> axum::http::Request<axum::body::Body> {
    let hash = digest(bytes);
    let time = now().unwrap();
    let tags = [
        ["t".into(), "upload".into()],
        ["server".into(), "node.example".into()],
        ["x".into(), hash.clone()],
        ["expiration".into(), (time + 120).to_string()],
    ];
    let event = EventBuilder::new(Kind::Custom(24_242), "Authorise synthetic upload")
        .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
        .custom_created_at(Timestamp::from(time))
        .finalize(key)
        .unwrap();
    axum::http::Request::builder()
        .method("PUT")
        .uri("/upload")
        .header("content-type", "application/octet-stream")
        .header("content-length", bytes.len())
        .header("x-sha-256", hash)
        .header(
            "authorization",
            format!(
                "Nostr {}",
                STANDARD.encode(serde_json::to_vec(&event).unwrap())
            ),
        )
        .body(axum::body::Body::from(bytes.to_vec()))
        .unwrap()
}
#[tokio::test]
async fn authenticated_http_checkout_unlocks_only_the_paid_signers_blossom_upload() {
    use axum::http::StatusCode;
    use tower::ServiceExt;
    let f = Fixture::new();
    let key = keys(1);
    let blossom = wildbloom_core::AppState::new(
        f.store.clone(),
        wildbloom_core::BlossomConfig {
            server_metadata: Default::default(),
            public_base_url: url::Url::parse("https://node.example/").unwrap(),
            accepted_server_names: vec!["node.example".into()],
            allowed_pubkeys: vec![],
            friend_grants: vec![],
            open_shelter: false,
            max_concurrent_writes: 4,
            mirror_proxy: None,
        },
    )
    .unwrap();
    let app = router(f.checkout.clone()).merge(wildbloom_core::router(blossom));
    let bytes = b"synthetic stored bytes";
    assert_eq!(
        app.clone()
            .oneshot(upload(&key, bytes))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let request = serde_json::to_vec(&request("http", Rail::Lightning)).unwrap();
    let order =
        order_response(api(app.clone(), &key, "/checkout/v1/orders", "POST", &request).await).await;
    let path = format!("/checkout/v1/orders/{}", order.quote.order_id);
    let consent =
        serde_json::to_vec(&serde_json::json!({"quote_digest":order.quote_digest})).unwrap();
    assert_eq!(
        order_response(
            api(
                app.clone(),
                &key,
                &format!("{path}/lightning"),
                "POST",
                &consent
            )
            .await
        )
        .await
        .state,
        State::AwaitingPayment
    );
    assert_eq!(
        app.clone()
            .oneshot(upload(&key, bytes))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // Reading an invoice/order is not a settlement check and causes no network.
    assert_eq!(
        order_response(api(app.clone(), &key, &path, "GET", b"").await)
            .await
            .state,
        State::AwaitingPayment
    );
    assert_eq!(f.lightning.checks.load(Ordering::SeqCst), 0);
    assert_eq!(
        api(app.clone(), &keys(2), &path, "GET", b"").await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        order_response(
            api(
                app.clone(),
                &key,
                &format!("{path}/check"),
                "POST",
                &consent
            )
            .await
        )
        .await
        .state,
        State::Active
    );
    assert_eq!(
        app.clone()
            .oneshot(upload(&keys(2), bytes))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(upload(&key, bytes))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    let download = app
        .oneshot(
            axum::http::Request::builder()
                .uri(format!("/{}", digest(bytes)))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(download.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(download.into_body(), 1000)
            .await
            .unwrap()
            .as_ref(),
        bytes
    );
}
#[tokio::test]
async fn http_rejects_oversized_unauthenticated_and_rewritten_requests() {
    use axum::http::StatusCode;
    use tower::ServiceExt;
    let f = Fixture::new();
    let app = router(f.checkout.clone());
    let path = "/checkout/v1/orders";
    let key = keys(1);
    let unauth = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .body(axum::body::Body::from("{}"))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(unauth).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        api(app.clone(), &key, path, "POST", &vec![b' '; 16385])
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        api(app.clone(), &key, "/checkout/v1/orders?x=1", "POST", b"{}")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let wrong = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "evil.example")
        .header(
            "authorization",
            auth(
                &key,
                "https://evil.example/checkout/v1/orders",
                "POST",
                b"{}",
                now().unwrap(),
                vec![],
            ),
        )
        .body(axum::body::Body::from("{}"))
        .unwrap();
    assert_eq!(
        app.oneshot(wrong).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.lightning.creates.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn renewal_uses_new_settlement_and_preserves_the_stable_allowance() {
    let f = Fixture::new();
    let (p, o) = f.quoted().await;
    f.checkout
        .lightning(&p, &o.quote.order_id, &o.quote_digest)
        .await
        .unwrap();
    let first = f
        .checkout
        .check(&p, &o.quote.order_id, &o.quote_digest)
        .await
        .unwrap()
        .receipt
        .unwrap();
    *f.lightning.invoice.lock().unwrap() = invoice(10_000, Currency::Bitcoin, 300, [4; 32]);
    f.lightning.status.lock().unwrap().preimage = Some(hex::encode([4; 32]));
    let mut req = request("renewal", Rail::Lightning);
    req.renews = Some(first.allowance_id.clone());
    let renewed = f.checkout.quote(&p, req.clone()).await.unwrap();
    f.checkout
        .lightning(&p, &renewed.quote.order_id, &renewed.quote_digest)
        .await
        .unwrap();
    let receipt = f
        .checkout
        .check(&p, &renewed.quote.order_id, &renewed.quote_digest)
        .await
        .unwrap()
        .receipt
        .unwrap();
    assert_eq!(receipt.allowance_id, first.allowance_id);
    assert_eq!(receipt.writes_until, first.writes_until + 3600);
    assert_eq!(
        f.checkout.quote(&p, req).await.unwrap().receipt,
        Some(receipt)
    );
    assert_eq!(
        f.checkout
            .check(&p, &o.quote.order_id, &o.quote_digest)
            .await
            .unwrap()
            .receipt,
        Some(first)
    );
    assert_eq!(f.store.committed_bytes().unwrap(), 100);
}
#[tokio::test]
async fn late_note_recovery_keeps_asset_for_operator_refund() {
    let f = Fixture::new();
    let (c, _mint) = notes(&f, MintMode::RecoverReplacement);
    let p = principal(1);
    let o = c
        .quote(&p, request("late-note", Rail::Lnurlcash))
        .await
        .unwrap();
    assert!(matches!(
        c.lnurlcash(&p, &o.quote.order_id, &o.quote_digest, &note())
            .await,
        Err(Error::Pending)
    ));
    let db = rusqlite::Connection::open(f.root.path().join("storage/wildbloom.sqlite3")).unwrap();
    db.execute(
        "UPDATE paid_sales SET expires=?1 WHERE id=?2",
        rusqlite::params![(now().unwrap() - 1) as i64, o.quote.order_id],
    )
    .unwrap();
    assert_eq!(
        c.check(&p, &o.quote.order_id, &o.quote_digest)
            .await
            .unwrap()
            .state,
        State::RefundRequired
    );
    assert!(
        f.ledger
            .get(&o.quote.order_id)
            .unwrap()
            .unwrap()
            .rotation
            .unwrap()
            .certificate
            .is_some()
    );
    assert!(f.store.paid_allowance(&o.quote.order_id).unwrap().is_none());
}
#[tokio::test]
async fn unpaid_or_unproven_lightning_status_never_activates() {
    let f = Fixture::new();
    let (p, o) = f.quoted().await;
    f.checkout
        .lightning(&p, &o.quote.order_id, &o.quote_digest)
        .await
        .unwrap();
    f.lightning.status.lock().unwrap().paid = false;
    assert_eq!(
        f.checkout
            .check(&p, &o.quote.order_id, &o.quote_digest)
            .await
            .unwrap()
            .state,
        State::AwaitingPayment
    );
    f.lightning.status.lock().unwrap().paid = true;
    f.lightning.status.lock().unwrap().preimage = None;
    assert!(matches!(
        f.checkout
            .check(&p, &o.quote.order_id, &o.quote_digest)
            .await,
        Err(Error::Pending)
    ));
    assert!(f.store.paid_allowance(&o.quote.order_id).unwrap().is_none());
}

async fn http_fixture(router: axum::Router) -> (Destination, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    // A synthetic hostname proves that only the explicit pin is used.
    let pin = Destination {
        origin: format!("http://receiver.example:{}/", address.port()),
        addresses: vec![address],
        allow_loopback_http: true,
    };
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (pin, task)
}
#[tokio::test]
async fn note_http_pins_destination_refuses_redirects_and_bounds_chunked_bodies() {
    use axum::{
        body::{Body, Bytes},
        response::Response,
        routing::get,
    };
    let router = axum::Router::new()
        .route("/note", get(|| async { "synthetic certificate" }))
        .route(
            "/redirect",
            get(|| async { axum::response::Redirect::temporary("/note") }),
        )
        .route(
            "/large",
            get(|| async {
                Response::new(Body::from_stream(futures_util::stream::iter(
                    (0..17).map(|_| Ok::<_, std::io::Error>(Bytes::from(vec![0; 4096]))),
                )))
            }),
        );
    let (pin, task) = http_fixture(router).await;
    let transport = HttpNoteTransport::new(
        ["note", "redirect", "large"]
            .into_iter()
            .map(|p| (format!("{}{p}", pin.origin), pin.clone()))
            .collect(),
    )
    .unwrap();
    // Tests inside the service module construct SensitiveUrl below through helper.
    assert_eq!(
        transport
            .get(&SensitiveUrl::for_test(format!(
                "{}note?k1=synthetic",
                pin.origin
            )))
            .await
            .unwrap(),
        b"synthetic certificate"
    );
    for path in ["redirect", "large", "unapproved"] {
        assert!(
            transport
                .get(&SensitiveUrl::for_test(format!("{}{path}", pin.origin)))
                .await
                .is_err()
        );
    }
    assert!(
        transport
            .get(&SensitiveUrl::for_test(
                "http://unapproved.example/note".into()
            ))
            .await
            .is_err()
    );
    task.abort();
    let mut wrong = pin.clone();
    wrong.allow_loopback_http = false;
    assert!(HttpNoteTransport::new(vec![(format!("{}note", pin.origin), wrong)]).is_err());
    let mut wrong = pin;
    wrong.origin = "http://127.0.0.2/".into();
    assert!(HttpNoteTransport::new(vec![("http://127.0.0.2/note".into(), wrong)]).is_err());
}

#[tokio::test]
async fn phoenix_http_issues_order_bound_invoice_and_reconciles_once() {
    use axum::{
        body::Bytes,
        http::HeaderMap,
        routing::{get, post},
    };
    let f = Fixture::new();
    let signed = invoice(10_000, Currency::Bitcoin, 300, [3; 32]);
    let generated =
        serde_json::json!({"serialized":signed.bolt11,"paymentHash":signed.payment_hash});
    let incoming = serde_json::json!({"paymentHash":signed.payment_hash,"preimage":hex::encode([3;32]),"isPaid":true});
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    let router = axum::Router::new()
        .route(
            "/createinvoice",
            post(move |headers: HeaderMap, body: Bytes| {
                let seen = seen.clone();
                let value = generated.clone();
                async move {
                    assert_eq!(
                        headers.get("authorization").unwrap(),
                        "Basic OnN5bnRoZXRpYy1saW1pdGVk"
                    );
                    seen.lock()
                        .unwrap()
                        .push(String::from_utf8(body.to_vec()).unwrap());
                    axum::Json(value)
                }
            }),
        )
        .route(
            "/payments/incoming/{hash}",
            get(move || {
                let incoming = incoming.clone();
                async move { axum::Json(incoming) }
            }),
        );
    let (pin, task) = http_fixture(router).await;
    let receiver =
        Arc::new(Phoenixd::new(pin, "synthetic-limited".into(), f.ledger.clone()).unwrap());
    let checkout = Checkout::new(
        config(),
        f.ledger.clone(),
        f.store.clone(),
        Some(receiver.clone()),
        None,
    )
    .unwrap();
    let p = principal(1);
    let order = checkout
        .quote(&p, request("http", Rail::Lightning))
        .await
        .unwrap();
    assert!(requests.lock().unwrap().is_empty());
    let id = &order.quote.order_id;
    checkout
        .lightning(&p, id, &order.quote_digest)
        .await
        .unwrap();
    checkout
        .lightning(&p, id, &order.quote_digest)
        .await
        .unwrap();
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let fields: std::collections::HashMap<_, _> =
            url::form_urlencoded::parse(requests[0].as_bytes())
                .into_owned()
                .collect();
        assert_eq!(fields["externalId"], *id);
        assert_eq!(fields["amountSat"], "10");
        let expiry: u64 = fields["expirySeconds"].parse().unwrap();
        assert!((1..=585).contains(&expiry));
    }
    let active = checkout.reconcile(id).await.unwrap();
    assert_eq!(active.state, State::Active);
    assert_eq!(
        checkout.reconcile(id).await.unwrap().receipt,
        active.receipt
    );
    assert!(receiver.check_invoice(&"0".repeat(64)).await.is_err());
    assert!(receiver.send_payment("synthetic").await.is_err());
    let summary = f.ledger.inspect("", 1).unwrap();
    assert_eq!(summary.len(), 1);
    let json = serde_json::to_string(&summary).unwrap();
    assert!(!json.contains(&signed.bolt11));
    assert!(!json.contains(&p.pubkey));
    assert!(
        f.ledger
            .inspect(&summary[0].order_id, 1)
            .unwrap()
            .is_empty()
    );
    assert!(f.ledger.inspect("", 101).is_err());
    task.abort();
}

#[tokio::test]
async fn phoenix_lost_response_finds_original_without_reissuing() {
    use axum::{extract::Query, routing::get};
    let f = Fixture::new();
    let (_, order) = f.quoted().await;
    let id = order.quote.order_id.clone();
    f.ledger
        .state(&id, State::Quoted, State::InvoicePending)
        .unwrap();
    let signed = invoice(10_000, Currency::Bitcoin, 300, [3; 32]);
    let row = serde_json::json!({"paymentHash":signed.payment_hash,"invoice":signed.bolt11,"externalId":id,"isPaid":false});
    let rows = Arc::new(Mutex::new(vec![row.clone()]));
    let served = rows.clone();
    let expected = id.clone();
    let router = axum::Router::new().route(
        "/payments/incoming",
        get(
            move |Query(q): Query<std::collections::HashMap<String, String>>| {
                let served = served.clone();
                let expected = expected.clone();
                async move {
                    assert_eq!(q["externalId"], expected);
                    assert_eq!(q["all"], "true");
                    assert_eq!(q["limit"], "2");
                    axum::Json(served.lock().unwrap().clone())
                }
            },
        ),
    );
    let (pin, task) = http_fixture(router).await;
    let receiver = Phoenixd::new(pin, "synthetic-limited".into(), f.ledger.clone()).unwrap();
    rows.lock().unwrap().clear();
    assert!(matches!(
        receiver.original_invoice(&id).await,
        Err(Error::Pending)
    ));
    *rows.lock().unwrap() = vec![row.clone(), row.clone()];
    assert!(matches!(
        receiver.original_invoice(&id).await,
        Err(Error::Pending)
    ));
    let mut wrong = row.clone();
    wrong["externalId"] = serde_json::json!("wrong");
    *rows.lock().unwrap() = vec![wrong];
    assert!(matches!(
        receiver.original_invoice(&id).await,
        Err(Error::Pending)
    ));
    *rows.lock().unwrap() = vec![row];
    let recovered = receiver.original_invoice(&id).await.unwrap();
    f.checkout.recover_invoice(&id, recovered).await.unwrap();
    assert_eq!(
        f.ledger.get(&id).unwrap().unwrap().order.state,
        State::AwaitingPayment
    );
    assert!(matches!(
        receiver.original_invoice(&id).await,
        Err(Error::Conflict)
    ));
    task.abort();
}

#[tokio::test]
async fn lnurlcash_http_distinct_callback_receives_and_journals_asset() {
    use axum::{extract::Query, routing::get};
    let f = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}/");
    let callback = format!("{origin}callback");
    let response_callback = callback.clone();
    let journal = f.root.path().join("checkout/checkout.sqlite3");
    let router=axum::Router::new()
        .route("/w",get(move |Query(q):Query<std::collections::HashMap<String,String>>| {
            let callback=response_callback.clone(); async move {
                let k1=&q["k1"]; let hash=lnurlcash_core::hash_k1(k1).unwrap();
                axum::Json(serde_json::json!({"tag":"withdrawRequest","callback":callback,"k1":k1,"minWithdrawable":10000,"maxWithdrawable":10000,"mintPubkey":mint_pubkey(),"sig":certificate(&hash,10000)}))
            }
        }))
        .route("/callback",get(move |Query(q):Query<std::collections::HashMap<String,String>>| {
            let journal=journal.clone(); async move {
                let db=rusqlite::Connection::open(journal).unwrap();
                let raw:String=db.query_row("SELECT rotation FROM orders WHERE state='lnurl_pending'",[],|r|r.get(0)).unwrap();
                let rotation:crate::ledger::Rotation=serde_json::from_str(&raw).unwrap();
                assert_eq!(lnurlcash_core::hash_k1(&rotation.new_secret).unwrap(),q["p1"]);
                axum::Json(serde_json::json!({"status":"OK","sig":certificate(&q["p1"],10000)}))
            }
        }));
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let endpoint = format!("{origin}w");
    let pin = Destination {
        origin,
        addresses: vec![address],
        allow_loopback_http: true,
    };
    let transport = HttpNoteTransport::new(vec![
        (endpoint.clone(), pin.clone()),
        (callback.clone(), pin),
    ])
    .unwrap();
    let mut cfg = config();
    cfg.allow_loopback_http = true;
    cfg.issuers[0].note_endpoint = endpoint.clone();
    cfg.issuers[0].callback = callback;
    let checkout = Checkout::new(
        cfg,
        f.ledger.clone(),
        f.store.clone(),
        None,
        Some(Arc::new(transport)),
    )
    .unwrap();
    let p = principal(1);
    let order = checkout
        .quote(&p, request("httpnote", Rail::Lnurlcash))
        .await
        .unwrap();
    let note = format!("{endpoint}?k1={}", hex::encode([6; 32]));
    let result = checkout
        .lnurlcash(&p, &order.quote.order_id, &order.quote_digest, &note)
        .await
        .unwrap();
    assert_eq!(result.state, State::Active);
    assert!(
        f.ledger
            .get(&order.quote.order_id)
            .unwrap()
            .unwrap()
            .rotation
            .unwrap()
            .certificate
            .is_some()
    );
    task.abort();
}

#[test]
fn runtime_profile_rejects_unsafe_origins_and_private_file_paths() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("profile.json");
    let value = serde_json::json!({"checkout":config(),"state":root.path().join("checkout"),"browser_origins":["https://app.example"],"phoenixd":null,"notes":[]});
    let write = |v: &serde_json::Value| {
        std::fs::write(&file, serde_json::to_vec(v).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    };
    write(&value);
    assert!(RuntimeProfile::read(&file).is_ok());
    assert!(read_private_file(std::path::Path::new("relative.json")).is_err());
    for origins in [
        serde_json::json!([]),
        serde_json::json!(["https://app.example/"]),
        serde_json::json!(["https://app.example/path"]),
        serde_json::json!(["http://app.example"]),
    ] {
        let mut invalid = value.clone();
        invalid["browser_origins"] = origins;
        write(&invalid);
        assert!(RuntimeProfile::read(&file).is_err());
    }
    write(&value);
    let f = Fixture::new();
    assert!(
        RuntimeProfile::read(&file)
            .unwrap()
            .open(f.store.clone(), "https://different.example/")
            .is_err()
    );
    // A receiving-less profile cannot expose a checkout accepting quotes.
    assert!(
        RuntimeProfile::read(&file)
            .unwrap()
            .open(f.store, &config().origin)
            .is_err()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_file(&file).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(read_private_file(&link).is_err());
    }
    std::fs::write(&file, vec![0u8; 65537]).unwrap();
    assert!(read_private_file(&file).is_err());
}

#[tokio::test]
async fn checkout_http_rate_limit_has_static_no_store_responses() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let fixture = Fixture::new();
    let app = router(fixture.checkout);
    for _ in 0..120 {
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/checkout/v1/offers")
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/checkout/v1/offers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["cache-control"], "no-store");
}

#[tokio::test]
async fn checkout_http_advertises_bound_lnurlcash_refunds() {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;
    let fixture = Fixture::new();
    let response = router(fixture.checkout)
        .oneshot(
            Request::builder()
                .uri("/checkout/v1/offers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(
        value["features"],
        serde_json::json!(["lnurlcash_refunds_v1"])
    );
}

#[test]
fn offers_fit_the_browser_transport_without_precision_loss() {
    let mut c = config();
    c.offers[0].capacity_bytes = 9_007_199_254_740_992;
    assert!(c.validate().is_err());
    let mut c = config();
    c.seller_name = "hidden\0text".into();
    assert!(c.validate().is_err());
    let mut c = config();
    c.offers[0].refund_policy = "bad\0policy".into();
    assert!(c.validate().is_err());
    let mut c = config();
    let template = c.offers[0].clone();
    c.offers = (0..32)
        .map(|i| {
            let mut o = template.clone();
            o.id = format!("offer-{i}");
            o.delivery_policy = "x".repeat(2048);
            o.retention_policy = "x".repeat(2048);
            o.refund_policy = "x".repeat(2048);
            o
        })
        .collect();
    assert!(c.validate().is_err());
}
