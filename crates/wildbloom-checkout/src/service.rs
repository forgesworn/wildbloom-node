use crate::ledger::{Record, RefundJournal, Rotation};
use crate::{
    Config, Error, Ledger, Network, Order, Principal, Quote, QuoteRequest, Rail, Receipt, State,
    digest, id, now,
};
use lightning_invoice::{Bolt11Invoice, Currency};
use lnurlcash_core::protocol::{self, MutationKind, Policy};
use std::{fmt, sync::Arc, time::Duration};
use toll_booth::{backends::LightningBackend, types::Invoice};
use wildbloom_core::{PaidSale, Store, StoreError};

/// A URL may contain money. Transport implementations must not log it, follow
/// redirects or send it through telemetry. Access is explicit and Debug redacts it.
pub struct SensitiveUrl(String);
impl SensitiveUrl {
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for SensitiveUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SensitiveUrl([REDACTED])")
    }
}
#[derive(Debug)]
pub struct TransportFailure;
/// The operator supplies a transport with streaming response limits, redirect
/// refusal and an explicit DNS/proxy policy. The shell adds a 15s deadline and
/// rejects bodies over 64KiB, but cannot bound allocations inside this adapter.
#[async_trait::async_trait]
pub trait NoteTransport: Send + Sync {
    async fn get(&self, url: &SensitiveUrl) -> Result<Vec<u8>, TransportFailure>;
}
#[async_trait::async_trait]
pub trait RefundTransport: Send + Sync {
    async fn get(&self, url: &SensitiveUrl) -> Result<Vec<u8>, TransportFailure>;
}
#[derive(Clone)]
pub struct Checkout {
    config: Arc<Config>,
    ledger: Ledger,
    store: Store,
    lightning: Option<Arc<dyn LightningBackend>>,
    notes: Option<Arc<dyn NoteTransport>>,
    refunds: Option<Arc<dyn RefundTransport>>,
    receiving: Arc<tokio::sync::Mutex<()>>,
}
impl Checkout {
    pub fn new(
        config: Config,
        ledger: Ledger,
        store: Store,
        lightning: Option<Arc<dyn LightningBackend>>,
        notes: Option<Arc<dyn NoteTransport>>,
    ) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            ledger,
            store,
            lightning,
            notes,
            refunds: None,
            receiving: Arc::new(tokio::sync::Mutex::new(())),
        })
    }
    pub fn with_refunds(mut self, refunds: Arc<dyn RefundTransport>) -> Self {
        self.refunds = Some(refunds);
        self
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn rails(&self) -> Vec<Rail> {
        let mut rails = Vec::new();
        if self.lightning.is_some() {
            rails.push(Rail::Lightning);
        }
        if self.notes.is_some()
            && self.config.network == Network::Bitcoin
            && !self.config.issuers.is_empty()
        {
            rails.push(Rail::Lnurlcash);
        }
        rails
    }
    fn record(&self, principal: &Principal, id: &str) -> Result<Record, Error> {
        if !crate::id(id) {
            return Err(Error::NotFound);
        }
        self.ledger
            .get(id)?
            .filter(|r| r.order.quote.signer_pubkey == principal.pubkey)
            .ok_or(Error::NotFound)
    }
    pub fn order(&self, principal: &Principal, id: &str) -> Result<Order, Error> {
        Ok(self.record(principal, id)?.order)
    }
    fn consent(&self, principal: &Principal, id: &str, commitment: &str) -> Result<Record, Error> {
        let record = self.record(principal, id)?;
        if record.order.quote_digest != commitment {
            return Err(Error::Conflict);
        }
        Ok(record)
    }
    fn fresh(&self, order: &Order) -> Result<(), Error> {
        if now()? >= order.quote.expires_at {
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub async fn quote(
        &self,
        principal: &Principal,
        request: QuoteRequest,
    ) -> Result<Order, Error> {
        let _guard = self.receiving.try_lock().map_err(|_| Error::Busy)?;
        if !id(&request.request_id)
            || !id(&request.offer_id)
            || request.renews.as_ref().is_some_and(|v| !id(v))
            || request.refund_to.as_ref().is_some_and(|value| {
                value.len() > 320 || !lnurlcash_core::is_lightning_address(value)
            })
        {
            return Err(Error::Invalid);
        }
        let order_id = digest(format!("{}:{}", principal.pubkey, request.request_id).as_bytes());
        let request_json = serde_json::to_string(&request)?;
        if let Some(record) = self.ledger.get(&order_id)? {
            if record.request != request_json {
                return Err(Error::Conflict);
            }
            return self.reserve(record);
        }
        match request.rail {
            Rail::Lightning if request.issuer_id.is_none() && self.lightning.is_some() => {}
            Rail::Lnurlcash
                if self.notes.is_some()
                    && self.config.network == Network::Bitcoin
                    && self
                        .config
                        .issuers
                        .iter()
                        .any(|i| Some(&i.id) == request.issuer_id.as_ref()) => {}
            _ => return Err(Error::Invalid),
        }
        let offer = self
            .config
            .offers
            .iter()
            .find(|o| o.id == request.offer_id)
            .cloned()
            .ok_or(Error::Invalid)?;
        let created_at = now()?;
        let expires_at = created_at
            .checked_add(self.config.quote_seconds)
            .ok_or(Error::Invalid)?;
        // Check the eventual retention arithmetic before holding capacity or money.
        expires_at
            .checked_add(offer.duration_seconds)
            .and_then(|v| v.checked_add(offer.grace_seconds))
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(Error::Invalid)?;
        let quote = Quote {
            version: 1,
            order_id: order_id.clone(),
            seller_id: self.config.seller_id.clone(),
            seller_name: self.config.seller_name.clone(),
            node_origin: self.config.origin.clone(),
            signer_pubkey: principal.pubkey.clone(),
            network: self.config.network,
            rail: request.rail,
            issuer: self
                .config
                .issuers
                .iter()
                .find(|i| Some(&i.id) == request.issuer_id.as_ref())
                .cloned(),
            issuer_id: request.issuer_id,
            offer,
            created_at,
            expires_at,
            renews: request.renews,
            refund_to: request.refund_to,
        };
        self.ledger.insert(&quote, &request_json)?;
        self.reserve(self.ledger.get(&order_id)?.ok_or(Error::Internal)?)
    }
    fn reserve(&self, record: Record) -> Result<Order, Error> {
        let order = record.order;
        if order.state != State::Reserving {
            return Ok(order);
        }
        let q = &order.quote;
        if now()? >= q.expires_at {
            self.ledger
                .state(&q.order_id, State::Reserving, State::Expired)?;
        } else {
            self.store
                .reserve_paid_sale(&PaidSale {
                    order_id: q.order_id.clone(),
                    signer_pubkey: q.signer_pubkey.clone(),
                    capacity_bytes: q.offer.capacity_bytes,
                    duration_seconds: q.offer.duration_seconds,
                    grace_seconds: q.offer.grace_seconds,
                    hold_expires_at: q.expires_at,
                    renews: q.renews.clone(),
                })
                .map_err(|e| match e {
                    StoreError::QuotaExceeded => Error::Capacity,
                    StoreError::InvalidPaidSale | StoreError::PaidAllowanceUnavailable => {
                        Error::Conflict
                    }
                    _ => Error::Internal,
                })?;
            self.ledger
                .state(&q.order_id, State::Reserving, State::Quoted)?;
        }
        Ok(self.ledger.get(&q.order_id)?.ok_or(Error::Internal)?.order)
    }
    /// Create at most one invoice. An interrupted creation stays InvoicePending;
    /// the backend trait cannot safely repeat issuance using an idempotency key.
    pub async fn lightning(
        &self,
        p: &Principal,
        id: &str,
        commitment: &str,
    ) -> Result<Order, Error> {
        let _guard = self.receiving.try_lock().map_err(|_| Error::Busy)?;
        let record = self.consent(p, id, commitment)?;
        if record.order.quote.rail != Rail::Lightning {
            return Err(Error::Conflict);
        }
        if matches!(
            record.order.state,
            State::AwaitingPayment | State::Settled | State::Active | State::RefundRequired
        ) {
            return Ok(record.order);
        }
        if record.order.state == State::InvoicePending {
            return Err(Error::Pending);
        }
        if record.order.state != State::Quoted {
            return Err(Error::Conflict);
        }
        self.fresh(&record.order)?;
        let backend = self.lightning.as_ref().ok_or(Error::Unavailable)?;
        self.ledger
            .state(id, State::Quoted, State::InvoicePending)?;
        let invoice = tokio::time::timeout(
            Duration::from_secs(15),
            backend.create_invoice(record.order.quote.offer.price_msat / 1000, Some(id)),
        )
        .await
        .map_err(|_| Error::Pending)?
        .map_err(|_| Error::Pending)?;
        validate_invoice(&record.order.quote, &invoice, false)?;
        self.ledger
            .invoice(id, &invoice.bolt11, &invoice.payment_hash)?;
        self.order(p, id)
    }
    /// Trusted operator recovery only; there is deliberately no HTTP route.
    /// Recover the original invoice by order memo at the operator's node. This
    /// validates terms but still requires a later authoritative settlement check.
    pub async fn recover_invoice(&self, id: &str, invoice: Invoice) -> Result<(), Error> {
        let _guard = self.receiving.try_lock().map_err(|_| Error::Busy)?;
        let record = self.ledger.get(id)?.ok_or(Error::NotFound)?;
        if record.order.state != State::InvoicePending || record.order.quote.rail != Rail::Lightning
        {
            return Err(Error::Conflict);
        }
        // Recovery accepts an expired invoice: its payment may already have landed.
        validate_invoice(&record.order.quote, &invoice, true)?;
        self.ledger
            .invoice(id, &invoice.bolt11, &invoice.payment_hash)
    }
    pub async fn lnurlcash(
        &self,
        p: &Principal,
        id: &str,
        commitment: &str,
        input: &str,
    ) -> Result<Order, Error> {
        let _guard = self.receiving.try_lock().map_err(|_| Error::Busy)?;
        let record = self.consent(p, id, commitment)?;
        if record.order.quote.rail != Rail::Lnurlcash {
            return Err(Error::Conflict);
        }
        // Never accept another asset during an uncertain mutation. Explicit check
        // replays the journal; it cannot replace the input or replacement secret.
        if record.order.state != State::Quoted {
            return Err(Error::Conflict);
        }
        self.fresh(&record.order)?;
        let issuer = record
            .order
            .quote
            .issuer
            .as_ref()
            .filter(|quoted| self.config.issuers.contains(quoted))
            .ok_or(Error::Unavailable)?;
        if input.len() > 8192 {
            return Err(Error::Invalid);
        }
        let note = lnurlcash_core::resolve_note_input(input).ok_or(Error::Invalid)?;
        let mut url = url::Url::parse(&note).map_err(|_| Error::Invalid)?;
        let mut keys = std::collections::BTreeSet::new();
        for (key, _) in url.query_pairs() {
            if !matches!(key.as_ref(), "k1" | "c" | "sig" | "amount")
                || !keys.insert(key.into_owned())
            {
                return Err(Error::Invalid);
            }
        }
        url.set_query(None);
        if url.as_str() != issuer.note_endpoint || url.fragment().is_some() {
            return Err(Error::Invalid);
        }
        let k1 = lnurlcash_core::note_k1(&note).ok_or(Error::Invalid)?;
        let note_id = lnurlcash_core::note_id_of(&k1).ok_or(Error::Invalid)?;
        let request = protocol::note_info_request(&note).map_err(|_| Error::Invalid)?;
        let body = self.fetch(&request.url).await?;
        let info = protocol::parse_note_info(&body, &note, policy()).map_err(|_| Error::Invalid)?;
        if info.callback != issuer.callback
            || info.mint_pubkey.as_deref() != Some(issuer.mint_pubkey.as_str())
            || info.max_withdrawable != record.order.quote.offer.price_msat
        {
            return Err(Error::Invalid);
        }
        // Information lookup may have taken time: never start accepting funds
        // once the capacity reservation has already expired.
        self.fresh(&record.order)?;
        let secret = lnurlcash_core::generate_note_secret();
        let request = protocol::rotate_request(&info.callback, &info.k1, &secret)
            .map_err(|_| Error::Invalid)?;
        let rotation = Rotation {
            request_url: request.url,
            new_secret: secret,
            outputs: request.outputs,
            issuer: issuer.id.clone(),
            mint_pubkey: issuer.mint_pubkey.clone(),
            endpoint: issuer.note_endpoint.clone(),
            certificate: None,
        };
        // Identity is anchored to endpoint + key, not the renameable issuer ID.
        let identity = digest(
            format!(
                "{}:{}:{}",
                issuer.note_endpoint, issuer.mint_pubkey, note_id
            )
            .as_bytes(),
        );
        self.ledger.rotate(id, &identity, &rotation)?;
        self.rotate(id, &record.order.quote, &rotation).await?;
        self.fulfil(id)?;
        self.order(p, id)
    }
    async fn fetch(&self, url: &str) -> Result<serde_json::Value, Error> {
        let transport = self.notes.as_ref().ok_or(Error::Unavailable)?;
        let url = SensitiveUrl(url.to_owned());
        let bytes = tokio::time::timeout(Duration::from_secs(15), transport.get(&url))
            .await
            .map_err(|_| Error::Pending)?
            .map_err(|_| Error::Pending)?;
        if bytes.len() > 65536 {
            return Err(Error::Pending);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::Pending)
    }
    async fn refund_fetch(&self, url: &str) -> Result<serde_json::Value, Error> {
        let transport = self.refunds.as_ref().ok_or(Error::Unavailable)?;
        let bytes = tokio::time::timeout(
            Duration::from_secs(15),
            transport.get(&SensitiveUrl(url.to_owned())),
        )
        .await
        .map_err(|_| Error::Pending)?
        .map_err(|_| Error::Pending)?;
        if bytes.len() > 65536 {
            return Err(Error::Pending);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::Pending)
    }
    async fn rotate(&self, id: &str, quote: &Quote, rotation: &Rotation) -> Result<(), Error> {
        // Removed or changed issuer configuration must not silently send assets
        // to a new operator. Recovery retains the original journal in all cases.
        if !self.config.issuers.iter().any(|i| {
            i.id == rotation.issuer
                && i.mint_pubkey == rotation.mint_pubkey
                && i.note_endpoint == rotation.endpoint
                && rotation
                    .request_url
                    .starts_with(&format!("{}?", i.callback))
        }) {
            return Err(Error::Unavailable);
        }
        let body = self.fetch(&rotation.request_url).await?;
        let response =
            protocol::parse_mutation(&body, MutationKind::Rotate, &rotation.outputs, policy())
                .map_err(|_| Error::Pending)?;
        let signature = response.signature.ok_or(Error::Pending)?;
        if !lnurlcash_core::verify_note_signature(
            &rotation.new_secret,
            &rotation.endpoint,
            quote.offer.price_msat,
            &signature,
            &rotation.mint_pubkey,
        ) {
            return Err(Error::Pending);
        }
        self.certify(id, rotation, signature)
    }
    fn certify(&self, id: &str, rotation: &Rotation, signature: String) -> Result<(), Error> {
        let reference = format!("lnurlcash:{}", digest(rotation.request_url.as_bytes()));
        let mut certified = rotation.clone();
        certified.certificate = Some(signature);
        self.ledger
            .settle(id, State::LnurlPending, &reference, Some(&certified))
    }
    // A mint need not replay the original rotation response. Check the saved
    // replacement before retrying that exact mutation. A missing/invalid reply
    // cannot prove failure; it only leaves the original journal pending.
    async fn recover_rotation(
        &self,
        id: &str,
        quote: &Quote,
        rotation: &Rotation,
    ) -> Result<bool, Error> {
        let issuer = self
            .config
            .issuers
            .iter()
            .find(|i| Some(*i) == quote.issuer.as_ref())
            .ok_or(Error::Unavailable)?;
        let note = lnurlcash_core::build_note_url(&rotation.endpoint, &rotation.new_secret, None)
            .ok_or(Error::Internal)?;
        let request = protocol::note_info_request(&note).map_err(|_| Error::Internal)?;
        let Ok(body) = self.fetch(&request.url).await else {
            return Ok(false);
        };
        let Ok(info) = protocol::parse_note_info(&body, &note, policy()) else {
            return Ok(false);
        };
        let Some(signature) = info.signature else {
            return Ok(false);
        };
        if info.callback != issuer.callback
            || info.mint_pubkey.as_deref() != Some(rotation.mint_pubkey.as_str())
            || info.max_withdrawable != quote.offer.price_msat
            || !lnurlcash_core::verify_note_signature(
                &rotation.new_secret,
                &rotation.endpoint,
                quote.offer.price_msat,
                &signature,
                &rotation.mint_pubkey,
            )
        {
            return Ok(false);
        }
        self.certify(id, rotation, signature)?;
        Ok(true)
    }
    /// Trusted local operator action, never an HTTP route. Reuses exactly the
    /// buyer reconciliation state machine; it cannot assert settlement or retry
    /// invoice creation. LNURLcash reconciliation can replay the saved mutation.
    pub async fn reconcile(&self, id: &str) -> Result<Order, Error> {
        let record = self.ledger.get(id)?.ok_or(Error::NotFound)?;
        let principal = Principal {
            pubkey: record.order.quote.signer_pubkey,
        };
        self.check(&principal, id, &record.order.quote_digest).await
    }
    /// Trusted local operator action, never an HTTP route. It is available only
    /// for a settled LNURLcash order whose reserved storage could not activate.
    /// The exact invoice and melt are journalled before the note is spent, and a
    /// retry can only resume that same payment.
    pub async fn refund(&self, id: &str) -> Result<Order, Error> {
        let _guard = self.receiving.try_lock().map_err(|_| Error::Busy)?;
        let mut record = self.ledger.get(id)?.ok_or(Error::NotFound)?;
        if record.order.state == State::Refunded {
            return Ok(record.order);
        }
        if record.order.state != State::RefundRequired || record.order.quote.rail != Rail::Lnurlcash
        {
            return Err(Error::Conflict);
        }
        let destination = record
            .order
            .quote
            .refund_to
            .clone()
            .filter(|value| lnurlcash_core::is_lightning_address(value))
            .ok_or(Error::Unavailable)?;
        let rotation = record
            .rotation
            .as_ref()
            .filter(|rotation| rotation.certificate.is_some())
            .ok_or(Error::Pending)?;
        let mut prepared_now = false;
        if record.refund.is_none() {
            let pay_url = lnurlcash_core::resolve_mint_input(&destination).ok_or(Error::Invalid)?;
            let pay_body = self.refund_fetch(&pay_url).await?;
            let pay = protocol::parse_pay_request(&pay_body).map_err(|_| Error::Pending)?;
            same_origin(&pay_url, &pay.callback)?;
            let amount = record.order.quote.offer.price_msat;
            if amount < pay.min_sendable || amount > pay.max_sendable {
                return Err(Error::Unavailable);
            }
            let invoice_request =
                protocol::invoice_request(&pay.callback, amount).map_err(|_| Error::Pending)?;
            let invoice_body = self.refund_fetch(&invoice_request.url).await?;
            let invoice =
                protocol::parse_invoice(&invoice_body, amount).map_err(|_| Error::Pending)?;
            let payment_hash = validate_refund_invoice(&record.order.quote, &invoice.pr)?;
            if let Some(verify) = invoice.verify.as_deref() {
                same_origin(&pay_url, verify)?;
            }
            let request = protocol::melt_request(
                &record
                    .order
                    .quote
                    .issuer
                    .as_ref()
                    .ok_or(Error::Unavailable)?
                    .callback,
                &rotation.new_secret,
                &invoice.pr,
            )
            .map_err(|_| Error::Pending)?;
            let journal = RefundJournal {
                destination,
                invoice: invoice.pr,
                payment_hash,
                receiver_verify: invoice.verify,
                request_url: request.url,
                issuer_verify: None,
                refunded_at: None,
            };
            self.ledger.start_refund(id, &journal)?;
            record = self.ledger.get(id)?.ok_or(Error::Internal)?;
            prepared_now = true;
        }
        let mut refund = record.refund.ok_or(Error::Internal)?;
        if !prepared_now && self.refund_settled(&refund).await? {
            refund.refunded_at = Some(now()?);
            self.ledger.complete_refund(id, &refund)?;
            return Ok(self.ledger.get(id)?.ok_or(Error::Internal)?.order);
        }
        let body = self.fetch(&refund.request_url).await?;
        let response = protocol::parse_mutation(&body, MutationKind::Melt, &[], policy())
            .map_err(|_| Error::Pending)?;
        if response
            .pr
            .as_ref()
            .is_some_and(|invoice| !same_invoice(invoice, &refund.invoice))
        {
            return Err(Error::Pending);
        }
        if let Some(verify) = response.verify {
            let issuer = record
                .order
                .quote
                .issuer
                .as_ref()
                .ok_or(Error::Unavailable)?;
            same_origin(&issuer.callback, &verify)?;
            refund.issuer_verify = Some(verify);
            self.ledger.update_refund(id, &refund)?;
        }
        if !self.refund_settled(&refund).await? {
            return Err(Error::Pending);
        }
        refund.refunded_at = Some(now()?);
        self.ledger.complete_refund(id, &refund)?;
        Ok(self.ledger.get(id)?.ok_or(Error::Internal)?.order)
    }
    async fn refund_settled(&self, refund: &RefundJournal) -> Result<bool, Error> {
        for verify in [
            refund.issuer_verify.as_ref(),
            refund.receiver_verify.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            let Ok(body) = self.refund_fetch(verify).await else {
                continue;
            };
            let Ok(result) = protocol::parse_verify(&body) else {
                continue;
            };
            if !same_invoice(&result.pr, &refund.invoice) {
                return Err(Error::Pending);
            }
            if result.settled {
                if let Some(preimage) = result.preimage {
                    let bytes = hex::decode(preimage).map_err(|_| Error::Pending)?;
                    if bytes.len() != 32 || digest(&bytes) != refund.payment_hash {
                        return Err(Error::Pending);
                    }
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// A user action performs one bounded settlement/recovery attempt. GET status
    /// never calls this method, and constructing Checkout starts no background job.
    pub async fn check(&self, p: &Principal, id: &str, commitment: &str) -> Result<Order, Error> {
        let _guard = self.receiving.try_lock().map_err(|_| Error::Busy)?;
        let record = self.consent(p, id, commitment)?;
        match record.order.state {
            State::AwaitingPayment => {
                let hash = record.payment_hash.as_ref().ok_or(Error::Internal)?;
                let backend = self.lightning.as_ref().ok_or(Error::Unavailable)?;
                let status =
                    tokio::time::timeout(Duration::from_secs(15), backend.check_invoice(hash))
                        .await
                        .map_err(|_| Error::Unavailable)?
                        .map_err(|_| Error::Unavailable)?;
                if !status.paid {
                    return Ok(record.order);
                }
                let preimage = status
                    .preimage
                    .as_ref()
                    .filter(|s| s.len() == 64)
                    .and_then(|s| hex::decode(s).ok())
                    .filter(|v| v.len() == 32)
                    .ok_or(Error::Pending)?;
                if digest(&preimage) != *hash {
                    return Err(Error::Pending);
                }
                self.ledger.settle(
                    id,
                    State::AwaitingPayment,
                    &format!("lightning:{hash}"),
                    None,
                )?;
            }
            State::LnurlPending => {
                let rotation = record.rotation.as_ref().ok_or(Error::Internal)?;
                if !self
                    .recover_rotation(id, &record.order.quote, rotation)
                    .await?
                {
                    self.rotate(id, &record.order.quote, rotation).await?;
                }
            }
            State::Settled => {}
            State::InvoicePending => return Err(Error::Pending),
            State::Reserving => return self.reserve(record),
            _ => return Ok(record.order),
        }
        self.fulfil(id)?;
        self.order(p, id)
    }
    fn fulfil(&self, id: &str) -> Result<(), Error> {
        // Always ask Shelter first: a prior activation may have succeeded before
        // the checkout commit was interrupted, even if the hold is now expired.
        match self.store.activate_paid_sale(id) {
            Ok(a) => self.ledger.activate(
                id,
                &Receipt {
                    allowance_id: a.allowance_id,
                    capacity_bytes: a.capacity_bytes,
                    starts_at: a.starts_at,
                    writes_until: a.writes_until,
                    retains_until: a.retains_until,
                },
            ),
            Err(StoreError::PaidAllowanceUnavailable) => {
                self.ledger.state(id, State::Settled, State::RefundRequired)
            }
            Err(_) => Err(Error::Internal),
        }
    }
}
fn policy() -> Policy {
    Policy {
        require_signatures: true,
        require_mint_pubkey: true,
    }
}
fn same_origin(left: &str, right: &str) -> Result<(), Error> {
    let left = url::Url::parse(left).map_err(|_| Error::Invalid)?;
    let right = url::Url::parse(right).map_err(|_| Error::Invalid)?;
    if left.origin() != right.origin()
        || !right.username().is_empty()
        || right.password().is_some()
        || right.fragment().is_some()
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn same_invoice(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}
fn validate_refund_invoice(quote: &Quote, invoice: &str) -> Result<String, Error> {
    if invoice.len() > 8192 {
        return Err(Error::Pending);
    }
    let parsed: Bolt11Invoice = invoice.parse().map_err(|_| Error::Pending)?;
    let currency = match quote.network {
        Network::Bitcoin => Currency::Bitcoin,
        Network::Testnet => Currency::BitcoinTestnet,
        Network::Regtest => Currency::Regtest,
    };
    if parsed.currency() != currency
        || parsed.amount_milli_satoshis() != Some(quote.offer.price_msat)
        || parsed
            .expires_at()
            .is_none_or(|expiry| expiry.as_secs() <= now().unwrap_or(u64::MAX))
    {
        return Err(Error::Pending);
    }
    Ok(parsed.payment_hash().to_string())
}
fn validate_invoice(quote: &Quote, invoice: &Invoice, allow_expired: bool) -> Result<(), Error> {
    if invoice.bolt11.len() > 8192 || invoice.payment_hash.len() != 64 {
        return Err(Error::Pending);
    }
    let parsed: Bolt11Invoice = invoice.bolt11.parse().map_err(|_| Error::Pending)?;
    let currency = match quote.network {
        Network::Bitcoin => Currency::Bitcoin,
        Network::Testnet => Currency::BitcoinTestnet,
        Network::Regtest => Currency::Regtest,
    };
    let expiry = parsed.expires_at().ok_or(Error::Pending)?.as_secs();
    if (!allow_expired && expiry <= now()?)
        || parsed.currency() != currency
        || parsed.amount_milli_satoshis() != Some(quote.offer.price_msat)
        || parsed.payment_hash().to_string() != invoice.payment_hash
        || expiry > quote.expires_at
        || expiry <= quote.created_at
        || parsed.duration_since_epoch().as_secs() > quote.expires_at
    {
        return Err(Error::Pending);
    }
    Ok(())
}

#[cfg(test)]
impl SensitiveUrl {
    pub(crate) fn for_test(url: String) -> Self {
        Self(url)
    }
}
