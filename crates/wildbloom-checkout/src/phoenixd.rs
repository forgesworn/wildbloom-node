//! Receive-only Phoenixd adapter for the pinned toll-booth backend interface.
use crate::transport::{PinnedClient, bounded};
use crate::{Destination, Error, Ledger, Rail, State, TransportFailure, now};
use serde::Deserialize;
use toll_booth::{
    backends::LightningBackend,
    types::{BackendError, Invoice, InvoiceStatus},
};

/// Supply Phoenixd's limited-access password, never its spending password.
/// Construction performs no I/O. No Debug implementation exposes the credential.
pub struct Phoenixd {
    http: PinnedClient,
    password: String,
    ledger: Ledger,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Created {
    serialized: String,
    payment_hash: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Incoming {
    payment_hash: String,
    preimage: Option<String>,
    external_id: Option<String>,
    invoice: Option<String>,
    is_paid: bool,
}
fn failure(_: impl Sized) -> BackendError {
    BackendError::Request("receiving request unavailable".into())
}
impl Phoenixd {
    pub fn new(
        destination: Destination,
        limited_password: String,
        ledger: Ledger,
    ) -> Result<Self, Error> {
        if limited_password.is_empty()
            || limited_password.len() > 1024
            || limited_password.chars().any(char::is_control)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            http: PinnedClient::new(destination)?,
            password: limited_password,
            ledger,
        })
    }
    async fn get(&self, url: url::Url) -> Result<Vec<u8>, TransportFailure> {
        bounded(
            self.http
                .client
                .get(url)
                .basic_auth("", Some(&self.password))
                .send()
                .await
                .map_err(|_| TransportFailure)?,
        )
        .await
    }
    /// Find exactly one original invoice. Zero/multiple results remain uncertain;
    /// this never creates a replacement or marks an order paid.
    pub async fn original_invoice(&self, order_id: &str) -> Result<Invoice, Error> {
        let record = self.ledger.get(order_id)?.ok_or(Error::NotFound)?;
        if record.order.state != State::InvoicePending || record.order.quote.rail != Rail::Lightning
        {
            return Err(Error::Conflict);
        }
        let mut url = self
            .http
            .path("payments/incoming")
            .map_err(|_| Error::Unavailable)?;
        url.query_pairs_mut()
            .append_pair("externalId", order_id)
            .append_pair("all", "true")
            .append_pair("limit", "2");
        let rows: Vec<Incoming> =
            serde_json::from_slice(&self.get(url).await.map_err(|_| Error::Unavailable)?)
                .map_err(|_| Error::Pending)?;
        if rows.len() != 1 {
            return Err(Error::Pending);
        }
        let row = rows.into_iter().next().ok_or(Error::Pending)?;
        if row.external_id.as_deref() != Some(order_id) {
            return Err(Error::Pending);
        }
        Ok(Invoice {
            bolt11: row.invoice.ok_or(Error::Pending)?,
            payment_hash: row.payment_hash,
        })
    }
}
#[async_trait::async_trait]
impl LightningBackend for Phoenixd {
    async fn create_invoice(
        &self,
        amount_sats: u64,
        memo: Option<&str>,
    ) -> Result<Invoice, BackendError> {
        let order_id = memo.filter(|s| crate::id(s)).ok_or_else(|| failure(()))?;
        let record = self
            .ledger
            .get(order_id)
            .map_err(failure)?
            .ok_or_else(|| failure(()))?;
        if record.order.state != State::InvoicePending
            || record.order.quote.rail != Rail::Lightning
            || record.order.quote.offer.price_msat
                != amount_sats.checked_mul(1000).ok_or_else(|| failure(()))?
        {
            return Err(failure(()));
        }
        // Leave room for request transit/server clock skew. Checkout validates
        // the signed invoice deadline again before returning it to the buyer.
        let expiry = record
            .order
            .quote
            .expires_at
            .checked_sub(now().map_err(failure)? + 15)
            .filter(|n| *n > 0)
            .ok_or_else(|| failure(()))?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("amountSat", &amount_sats.to_string())
            .append_pair("description", order_id)
            .append_pair("externalId", order_id)
            .append_pair("expirySeconds", &expiry.to_string())
            .finish();
        let response = self
            .http
            .client
            .post(self.http.path("createinvoice").map_err(failure)?)
            .basic_auth("", Some(&self.password))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .map_err(failure)?;
        let created: Created =
            serde_json::from_slice(&bounded(response).await.map_err(failure)?).map_err(failure)?;
        Ok(Invoice {
            bolt11: created.serialized,
            payment_hash: created.payment_hash,
        })
    }
    async fn check_invoice(&self, hash: &str) -> Result<InvoiceStatus, BackendError> {
        if hash.len() != 64 || hex::decode(hash).is_err() {
            return Err(failure(()));
        }
        let url = self
            .http
            .path(&format!("payments/incoming/{hash}"))
            .map_err(failure)?;
        let incoming: Incoming =
            serde_json::from_slice(&self.get(url).await.map_err(failure)?).map_err(failure)?;
        if incoming.payment_hash != hash {
            return Err(failure(()));
        }
        Ok(InvoiceStatus {
            paid: incoming.is_paid,
            preimage: if incoming.is_paid {
                incoming.preimage
            } else {
                None
            },
        })
    }
}
