use crate::{Error, id};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rail {
    Lightning,
    Lnurlcash,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Bitcoin,
    Testnet,
    Regtest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub id: String,
    pub revision: u32,
    pub capacity_bytes: u64,
    pub duration_seconds: u64,
    pub grace_seconds: u64,
    pub price_msat: u64,
    pub delivery_bytes: u64,
    pub delivery_policy: String,
    pub retention_policy: String,
    pub refund_policy: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    pub id: String,
    pub note_endpoint: String,
    pub callback: String,
    pub mint_pubkey: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Exact public origin, with a trailing slash, supplied by the operator.
    pub origin: String,
    pub seller_id: String,
    pub seller_name: String,
    pub network: Network,
    pub quote_seconds: u64,
    pub offers: Vec<Offer>,
    pub issuers: Vec<Issuer>,
    pub allow_loopback_http: bool,
    /// This initial receiving integration refuses Tor-only mode entirely.
    /// A future reviewed onion transport must implement it without fallback.
    pub tor_only: bool,
}
impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        if self.tor_only
            || !id(&self.seller_id)
            || self.seller_name.is_empty()
            || self.seller_name.len() > 256
            || self.seller_name.chars().any(char::is_control)
            || !(60..=86_400).contains(&self.quote_seconds)
            || self.offers.is_empty()
            || self.offers.len() > 32
            || self.issuers.len() > 32
        {
            return Err(Error::Invalid);
        }
        let origin = endpoint(&self.origin, self.allow_loopback_http)?;
        if origin.path() != "/" || origin.as_str() != self.origin {
            return Err(Error::Invalid);
        }
        let mut ids = std::collections::BTreeSet::new();
        for offer in &self.offers {
            if !id(&offer.id)
                || offer.revision == 0
                || !ids.insert(&offer.id)
                || offer.capacity_bytes == 0
                || offer.duration_seconds == 0
                || offer.price_msat == 0
                || offer.price_msat % 1000 != 0
                || offer.delivery_bytes == 0
                || [
                    offer.capacity_bytes,
                    offer.duration_seconds,
                    offer.grace_seconds,
                    offer.price_msat,
                    offer.delivery_bytes,
                ]
                .iter()
                .any(|n| *n > 9_007_199_254_740_991)
                || [
                    &offer.delivery_policy,
                    &offer.retention_policy,
                    &offer.refund_policy,
                ]
                .iter()
                .any(|s| {
                    s.is_empty()
                        || s.len() > 2048
                        || s.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
                })
            {
                return Err(Error::Invalid);
            }
        }
        ids.clear();
        for issuer in &self.issuers {
            let note = endpoint(&issuer.note_endpoint, self.allow_loopback_http)?;
            let callback = endpoint(&issuer.callback, self.allow_loopback_http)?;
            if !id(&issuer.id)
                || !ids.insert(&issuer.id)
                || note.origin() != callback.origin()
                || !lnurlcash_core::protocol::is_compressed_pubkey(&issuer.mint_pubkey)
            {
                return Err(Error::Invalid);
            }
        }
        // Leave room for the offers response wrapper within the browser
        // transport's 64 KiB bound. Numbers must survive JSON/JS exactly.
        if serde_json::to_vec(self)?.len() > 60_000 {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
pub(crate) fn endpoint(value: &str, local: bool) -> Result<Url, Error> {
    let u = Url::parse(value).map_err(|_| Error::Invalid)?;
    let host = u.host_str().ok_or(Error::Invalid)?;
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if value.len() > 2048
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || host.ends_with(".onion")
        || !(u.scheme() == "https" || (local && loopback && u.scheme() == "http"))
    {
        return Err(Error::Invalid);
    }
    Ok(u)
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteRequest {
    pub request_id: String,
    pub offer_id: String,
    pub rail: Rail,
    pub issuer_id: Option<String>,
    pub renews: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_to: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quote {
    pub version: u8,
    pub order_id: String,
    pub seller_id: String,
    pub seller_name: String,
    pub node_origin: String,
    pub signer_pubkey: String,
    pub network: Network,
    pub rail: Rail,
    pub issuer_id: Option<String>,
    pub offer: Offer,
    pub issuer: Option<Issuer>,
    pub created_at: u64,
    pub expires_at: u64,
    pub renews: Option<String>,
    #[serde(default)]
    pub refund_to: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Reserving,
    Quoted,
    Expired,
    InvoicePending,
    AwaitingPayment,
    LnurlPending,
    Settled,
    Active,
    RefundRequired,
    Refunded,
}
impl State {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Reserving => "reserving",
            Self::Quoted => "quoted",
            Self::Expired => "expired",
            Self::InvoicePending => "invoice_pending",
            Self::AwaitingPayment => "awaiting_payment",
            Self::LnurlPending => "lnurl_pending",
            Self::Settled => "settled",
            Self::Active => "active",
            Self::RefundRequired => "refund_required",
            Self::Refunded => "refunded",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub allowance_id: String,
    pub capacity_bytes: u64,
    pub starts_at: u64,
    pub writes_until: u64,
    pub retains_until: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundStatus {
    Pending,
    Completed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundReceipt {
    pub status: RefundStatus,
    pub amount_msat: u64,
    pub payment_hash: String,
    pub refunded_at: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub quote: Quote,
    pub quote_digest: String,
    pub state: State,
    pub invoice: Option<String>,
    pub receipt: Option<Receipt>,
    #[serde(default)]
    pub refund: Option<RefundReceipt>,
}

/// Deliberately minimal local recovery inventory; no payment assets or buyer key.
#[derive(Debug, Serialize, Deserialize)]
pub struct OrderSummary {
    pub order_id: String,
    pub state: State,
    pub rail: Rail,
    pub expires_at: u64,
}
