use super::*;
use contract::{Availability, Description, Service, accept_signature, parse_event};
use nostr::prelude::{Event, FinalizeEvent, Keys};
use serde_json::{Value, json};
use wildbloom_checkout::{Config, Ledger, NoteTransport, SensitiveUrl, TransportFailure};
use wildbloom_core::{PaidSale, StoreConfig};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/storage-v1");
fn fixture(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(format!("{FIXTURES}/{name}.json")).unwrap()).unwrap()
}
fn keys(n: u8) -> Keys {
    Keys::parse(&hex::encode([n; 32])).unwrap()
}
fn profile() -> Profile {
    Profile {
        service_pubkey: keys(1).public_key().to_hex(),
        identifier: "test-storage".into(),
        name: "Synthetic storage".into(),
        about: "Synthetic test service".into(),
        origins: vec!["https://storage.example/".into()],
        browser_origins: vec!["https://app.example".into()],
        withdrawn: false,
        announcement: None,
    }
}
fn store(root: &Path) -> Store {
    Store::open(StoreConfig {
        root: root.join("storage"),
        quota_bytes: 1000,
        max_blob_bytes: 1000,
    })
    .unwrap()
}
fn services(
    profile: Profile,
    store: Store,
    checkout: Option<Checkout>,
    free: bool,
) -> Result<Services, Error> {
    Services::new(
        profile,
        store,
        checkout,
        "https://storage.example/",
        free,
        true,
        &[],
        None,
        true,
    )
}
struct Notes;
#[async_trait::async_trait]
impl NoteTransport for Notes {
    async fn get(&self, _: &SensitiveUrl) -> Result<Vec<u8>, TransportFailure> {
        panic!("discovery must not contact a payment backend")
    }
}
fn checkout(store: Store, root: &Path) -> Checkout {
    let d: Description = serde_json::from_value(fixture("paid")["description"].clone()).unwrap();
    let p = d.checkout.unwrap();
    let offer = match &d.services[0] {
        Service::Paid {
            id,
            revision,
            duration_seconds,
            grace_seconds,
            price_msat,
            delivery_bytes,
            delivery_policy,
            retention_policy,
            refund_policy,
            ..
        } => wildbloom_checkout::Offer {
            id: id.clone(),
            revision: *revision as u32,
            capacity_bytes: 600,
            duration_seconds: *duration_seconds,
            grace_seconds: *grace_seconds,
            price_msat: *price_msat,
            delivery_bytes: *delivery_bytes,
            delivery_policy: delivery_policy.clone(),
            retention_policy: retention_policy.clone(),
            refund_policy: refund_policy.clone(),
        },
        _ => panic!(),
    };
    Checkout::new(
        Config {
            origin: "https://storage.example/".into(),
            seller_id: "test-operator".into(),
            seller_name: "Synthetic operator".into(),
            network: p.network,
            quote_seconds: 600,
            offers: vec![offer],
            issuers: p.issuers,
            allow_loopback_http: false,
            tor_only: false,
        },
        Ledger::open(&root.join("ledger")).unwrap(),
        store,
        None,
        Some(Arc::new(Notes)),
    )
    .unwrap()
}
#[test]
fn all_foreign_signed_contract_vectors_agree() {
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(format!("{FIXTURES}/manifest.json")).unwrap())
            .unwrap();
    for name in manifest["cases"].as_array().unwrap() {
        let name = name.as_str().unwrap().strip_suffix(".json").unwrap();
        let f = fixture(name);
        let bytes = serde_json::to_vec(&f["signed_event"]).unwrap();
        let event: Event = serde_json::from_slice(&bytes).unwrap();
        event.verify().unwrap(); // All rejection vectors carry valid signatures.
        let parsed = parse_event(&bytes, f["now"].as_u64().unwrap());
        assert_eq!(parsed.is_ok(), !name.starts_with("reject-"), "{name}");
        if let Ok((e, d)) = parsed {
            let template = d.template(e.created_at.as_secs()).unwrap();
            assert_eq!(template.tags, e.tags);
            let reconstructed: Value = serde_json::from_str(&template.content).unwrap();
            assert_eq!(
                reconstructed,
                serde_json::from_str::<Value>(&e.content).unwrap()
            );
            assert_eq!(d, serde_json::from_value(f["description"].clone()).unwrap());
        }
    }
}
#[test]
fn only_exact_external_signatures_are_accepted() {
    let d: Description =
        serde_json::from_value(fixture("combined")["description"].clone()).unwrap();
    let request = d.template(d.observed_at).unwrap();
    let signed = request.clone().finalize(&keys(1)).unwrap();
    assert!(
        accept_signature(
            &serde_json::to_vec(&signed).unwrap(),
            &request,
            d.observed_at
        )
        .is_ok()
    );
    let mut changed = d.clone();
    changed.services[0].pause();
    let rewritten = changed
        .template(d.observed_at)
        .unwrap()
        .finalize(&keys(1))
        .unwrap();
    assert!(
        accept_signature(
            &serde_json::to_vec(&rewritten).unwrap(),
            &request,
            d.observed_at
        )
        .is_err()
    );
    assert!(
        accept_signature(
            &serde_json::to_vec(&signed).unwrap(),
            &request,
            d.expires_at
        )
        .is_err()
    );
    let mut changed: Value = serde_json::to_value(&signed).unwrap();
    changed["content"] = json!("{}");
    assert!(parse_event(&serde_json::to_vec(&changed).unwrap(), d.observed_at).is_err());
    assert!(parse_event(&vec![b' '; 65537], d.observed_at).is_err());
}
#[test]
fn private_nodes_owner_keys_and_unbound_origins_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    let s = store(temp.path());
    assert!(services(profile(), s.clone(), None, false).is_err());
    let mut p = profile();
    p.origins = vec!["https://other.example/".into()];
    assert!(services(p, s.clone(), None, true).is_err());
    assert!(
        Services::new(
            profile(),
            s.clone(),
            None,
            "https://storage.example/",
            true,
            true,
            &[keys(1).public_key().to_hex()],
            None,
            true
        )
        .is_err()
    );
    let mut p = profile();
    p.origins = vec!["https://localhost/".into()];
    assert!(
        Services::new(
            p,
            s,
            None,
            "https://localhost/",
            true,
            true,
            &[],
            None,
            true
        )
        .is_err()
    );
}
#[test]
fn free_availability_tracks_actual_guest_watermark_and_disabled_transport() {
    let temp = tempfile::tempdir().unwrap();
    let s = store(temp.path());
    let svc = services(profile(), s.clone(), None, true).unwrap();
    assert_eq!(
        svc.snapshot(1, false).unwrap().services[0].availability(),
        Availability::Accepting
    );
    let sale = PaidSale {
        order_id: "hold".into(),
        signer_pubkey: keys(2).public_key().to_hex(),
        capacity_bytes: 800,
        duration_seconds: 600,
        grace_seconds: 0,
        hold_expires_at: now().unwrap() + 600,
        renews: None,
    };
    s.reserve_paid_sale(&sale).unwrap();
    assert_eq!(
        svc.snapshot(1, false).unwrap().services[0].availability(),
        Availability::Full
    );
    // At the high watermark a new positive-sized guest mirror is refused.
    let claim = wildbloom_core::ClaimSpec {
        signer_pubkey: keys(3).public_key().to_hex(),
        retention_tier: wildbloom_core::RetentionTier::Guest,
        byte_limit: None,
        claim_expires_at: None,
        grant_id: None,
        declared_type: "application/octet-stream".into(),
        class: None,
    };
    assert!(s.begin_claimed_upload(&"a".repeat(64), 1, claim).is_err());
    let disabled = Services::new(
        profile(),
        s,
        None,
        "https://storage.example/",
        true,
        false,
        &[],
        None,
        true,
    )
    .unwrap();
    assert_eq!(
        disabled.snapshot(1, false).unwrap().services[0].availability(),
        Availability::Paused
    );
    assert!(
        svc.snapshot(1, true)
            .unwrap()
            .services
            .iter()
            .all(|s| s.availability() == Availability::Paused)
    );
}
#[test]
fn paid_snapshot_tracks_live_holds_and_reopened_store_without_exposing_usage() {
    let temp = tempfile::tempdir().unwrap();
    let s = store(temp.path());
    let svc = services(
        profile(),
        s.clone(),
        Some(checkout(s.clone(), temp.path())),
        false,
    )
    .unwrap();
    assert_eq!(
        svc.snapshot(1, false).unwrap().services[0].availability(),
        Availability::Accepting
    );
    let sale = PaidSale {
        order_id: "held".into(),
        signer_pubkey: keys(2).public_key().to_hex(),
        capacity_bytes: 600,
        duration_seconds: 600,
        grace_seconds: 60,
        hold_expires_at: now().unwrap() + 600,
        renews: None,
    };
    s.reserve_paid_sale(&sale).unwrap();
    let d = svc.snapshot(2, false).unwrap();
    assert_eq!(d.services[0].availability(), Availability::Full);
    let mut competing = sale;
    competing.order_id = "competing".into();
    competing.signer_pubkey = keys(3).public_key().to_hex();
    assert!(s.reserve_paid_sale(&competing).is_err());
    let price = svc.checkout.as_ref().unwrap().config().offers[0].price_msat;
    drop(svc);
    drop(s);
    let reopened = store(temp.path());
    let after = services(
        profile(),
        reopened.clone(),
        Some(checkout(reopened, temp.path())),
        false,
    )
    .unwrap();
    assert_eq!(
        after.snapshot(3, false).unwrap().services[0].availability(),
        Availability::Full
    );
    let value = serde_json::to_value(d).unwrap();
    assert!(value.get("committed_bytes").is_none());
    assert!(value.get("quota_bytes").is_none());
    assert_eq!(value["checkout"]["rails"], json!(["lnurlcash"]));
    assert_eq!(value["services"][0]["price_msat"], json!(price));
}
#[tokio::test]
async fn public_http_is_bound_no_store_cors_limited_and_rate_limited() {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;
    let temp = tempfile::tempdir().unwrap();
    let svc = services(profile(), store(temp.path()), None, true).unwrap();
    let router = svc.router().unwrap();
    for i in 0..120 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/services/v1")
                    .header("host", "attacker.example")
                    .header(
                        "origin",
                        if i == 0 {
                            "https://app.example"
                        } else {
                            "https://attacker.example"
                        },
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_some(),
            i == 0
        );
        let d: Description =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(d.origins, ["https://storage.example/"]);
        assert!(d.observed_at <= now().unwrap());
    }
    let response = router
        .oneshot(
            Request::builder()
                .uri("/services/v1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}
#[test]
fn restart_journal_is_locked_bound_signed_and_monotonic() {
    let temp = tempfile::tempdir().unwrap();
    let svc = services(profile(), store(temp.path()), None, true).unwrap();
    let root = temp.path().join("publisher");
    let mut journal = publisher::Journal::open(&root, &svc).unwrap();
    assert!(publisher::Journal::open(&root, &svc).is_err());
    let at = now().unwrap();
    let event = svc
        .snapshot(at, false)
        .unwrap()
        .template(at)
        .unwrap()
        .finalize(&keys(1))
        .unwrap();
    journal.save(event.clone()).unwrap();
    assert!(journal.save(event.clone()).is_err());
    drop(journal);
    let reopened = publisher::Journal::open(&root, &svc).unwrap();
    assert_eq!(reopened.last.unwrap().id, event.id);
    let mut value = serde_json::to_value(event).unwrap();
    value["content"] = json!("{}");
    std::fs::write(
        root.join("last-event.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert!(publisher::Journal::open(&root, &svc).is_err());
}
#[test]
fn announcement_transport_requires_explicit_public_pins_or_tor_proxy() {
    let temp = tempfile::tempdir().unwrap();
    let s = store(temp.path());
    let mut p = profile();
    p.announcement = Some(Announcement {
        signer: temp.path().join("signer"),
        signer_args: vec![],
        state_dir: temp.path().join("publisher"),
        transport: relay::Transport::Direct,
        relays: vec![relay::Destination {
            url: "wss://relay.example/".into(),
            addresses: vec!["1.1.1.1:443".parse().unwrap()],
        }],
        heartbeat_seconds: 1800,
        ttl_seconds: 7200,
    });
    assert!(services(p, s.clone(), None, true).is_ok());
    for pin in ["127.0.0.1:443", "10.0.0.1:443", "1.1.1.1:80", "[::1]:443"] {
        let mut p = profile();
        p.announcement = Some(Announcement {
            signer: temp.path().join("signer"),
            signer_args: vec![],
            state_dir: temp.path().join("publisher"),
            transport: relay::Transport::Direct,
            relays: vec![relay::Destination {
                url: "wss://relay.example/".into(),
                addresses: vec![pin.parse().unwrap()],
            }],
            heartbeat_seconds: 1800,
            ttl_seconds: 7200,
        });
        assert!(services(p, s.clone(), None, true).is_err(), "{pin}");
    }
    let mut p = profile();
    p.announcement = Some(Announcement {
        signer: temp.path().join("signer"),
        signer_args: vec![],
        state_dir: temp.path().join("publisher"),
        transport: relay::Transport::TorOnly,
        relays: vec![relay::Destination {
            url: "wss://relay.example/".into(),
            addresses: vec![],
        }],
        heartbeat_seconds: 1800,
        ttl_seconds: 7200,
    });
    assert!(services(p, s, None, true).is_err()); // No silent direct fallback.
}
