use crate::{Error, Order, Quote, RefundReceipt, RefundStatus, State, digest};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
    sync::{Arc, Mutex},
};

/// Private operator state. Never use a public directory or include this in diagnostics.
#[derive(Clone)]
pub struct Ledger(Arc<Inner>);
struct Inner {
    db: Mutex<Connection>,
    _lock: File,
}

// Deliberately no Debug: this journal contains spendable bearer assets.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Rotation {
    pub request_url: String,
    pub new_secret: String,
    pub outputs: Vec<String>,
    pub issuer: String,
    pub mint_pubkey: String,
    pub endpoint: String,
    pub certificate: Option<String>,
}
#[derive(Clone)]
pub(crate) struct Record {
    pub order: Order,
    pub request: String,
    pub payment_hash: Option<String>,
    pub rotation: Option<Rotation>,
    pub refund: Option<RefundJournal>,
}
// Deliberately no Debug: this journal contains a spendable note and invoice.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RefundJournal {
    pub destination: String,
    pub invoice: String,
    pub payment_hash: String,
    pub receiver_verify: Option<String>,
    pub request_url: String,
    pub issuer_verify: Option<String>,
    pub refunded_at: Option<u64>,
}
impl RefundJournal {
    fn public(&self, amount_msat: u64) -> RefundReceipt {
        RefundReceipt {
            status: if self.refunded_at.is_some() {
                RefundStatus::Completed
            } else {
                RefundStatus::Pending
            },
            amount_msat,
            payment_hash: self.payment_hash.clone(),
            refunded_at: self.refunded_at,
        }
    }
}
fn validate_existing_file(metadata: &fs::Metadata) -> Result<(), Error> {
    if !metadata.is_file() {
        return Err(Error::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

impl Ledger {
    pub fn open(directory: &Path) -> Result<Self, Error> {
        wildbloom_private_state::private_directory(directory)?;
        // Reject a symlink at the state directory boundary. The parent must be
        // operator-controlled; protection from a hostile local owner is out of scope.
        if fs::symlink_metadata(directory)?.file_type().is_symlink() {
            return Err(Error::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let open_private = |name: &str| -> Result<File, Error> {
            let path = directory.join(name);
            if let Ok(metadata) = fs::symlink_metadata(&path) {
                validate_existing_file(&metadata)?;
            }
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true).truncate(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = options.open(path)?;
            wildbloom_private_state::check_file(&file)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            Ok(file)
        };
        let lock = open_private("checkout.lock")?;
        lock.try_lock_exclusive().map_err(|_| Error::Conflict)?;
        drop(open_private("checkout.sqlite3")?);
        // SQLite opens these companions itself. Refuse pre-existing symlinks.
        for name in [
            "checkout.sqlite3-wal",
            "checkout.sqlite3-shm",
            "checkout.sqlite3-journal",
        ] {
            let path = directory.join(name);
            if let Ok(metadata) = fs::symlink_metadata(&path) {
                validate_existing_file(&metadata)?;
            }
        }
        let db = Connection::open(directory.join("checkout.sqlite3"))?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > 2 {
            return Err(Error::Invalid);
        }
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        if version == 0 {
            db.execute_batch(
                "BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS orders (
                    id TEXT PRIMARY KEY NOT NULL, signer TEXT NOT NULL, request TEXT NOT NULL,
                    quote TEXT NOT NULL, digest TEXT NOT NULL, state TEXT NOT NULL,
                    invoice TEXT, payment_hash TEXT UNIQUE, rotation TEXT, note_id TEXT UNIQUE,
                    settlement TEXT UNIQUE, receipt TEXT, refund TEXT
                );
                PRAGMA user_version=2; COMMIT;",
            )?;
        } else if version == 1 {
            db.execute_batch(
                "BEGIN IMMEDIATE; ALTER TABLE orders ADD COLUMN refund TEXT;
                PRAGMA user_version=2; COMMIT;",
            )?;
        }
        for name in [
            "checkout.sqlite3",
            "checkout.sqlite3-wal",
            "checkout.sqlite3-shm",
        ] {
            let path = directory.join(name);
            if path.exists() {
                wildbloom_private_state::check_file(&File::open(path)?)?;
            }
        }
        Ok(Self(Arc::new(Inner {
            db: Mutex::new(db),
            _lock: lock,
        })))
    }
    fn db(&self) -> Result<std::sync::MutexGuard<'_, Connection>, Error> {
        self.0.db.lock().map_err(|_| Error::Internal)
    }
    /// Local operator inspection only. Keyset pagination is bounded and never
    /// exports invoice/preimage/bearer assets or mutation URLs.
    pub fn inspect(&self, after: &str, limit: u16) -> Result<Vec<crate::OrderSummary>, Error> {
        if limit == 0 || limit > 100 || (!after.is_empty() && !crate::id(after)) {
            return Err(Error::Invalid);
        }
        let db = self.db()?;
        let mut query =
            db.prepare("SELECT id,state,quote FROM orders WHERE id>?1 ORDER BY id LIMIT ?2")?;
        query
            .query_map(params![after, limit], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .map(|row| {
                let (order_id, state, quote) = row?;
                let quote: crate::Quote = serde_json::from_str(&quote)?;
                Ok(crate::OrderSummary {
                    order_id,
                    state: serde_json::from_value(serde_json::Value::String(state))?,
                    rail: quote.rail,
                    expires_at: quote.expires_at,
                })
            })
            .collect()
    }
    pub(crate) fn get(&self, id: &str) -> Result<Option<Record>, Error> {
        let row=self.db()?.query_row("SELECT request,quote,digest,state,invoice,payment_hash,rotation,receipt,refund FROM orders WHERE id=?1",[id],|r| {
            Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,Option<String>>(6)?,r.get::<_,Option<String>>(7)?,r.get::<_,Option<String>>(8)?))
        }).optional()?;
        row.map(
            |(
                request,
                quote,
                quote_digest,
                state,
                invoice,
                payment_hash,
                rotation,
                receipt,
                refund,
            )| {
                let quote: Quote = serde_json::from_str(&quote)?;
                let refund: Option<RefundJournal> =
                    refund.map(|s| serde_json::from_str(&s)).transpose()?;
                Ok(Record {
                    request,
                    payment_hash,
                    rotation: rotation.map(|s| serde_json::from_str(&s)).transpose()?,
                    refund: refund.clone(),
                    order: Order {
                        refund: refund.map(|r| r.public(quote.offer.price_msat)),
                        quote,
                        quote_digest,
                        state: serde_json::from_value(serde_json::Value::String(state))?,
                        invoice,
                        receipt: receipt.map(|s| serde_json::from_str(&s)).transpose()?,
                    },
                })
            },
        )
        .transpose()
    }
    pub(crate) fn insert(&self, quote: &Quote, request: &str) -> Result<(), Error> {
        let json = serde_json::to_string(quote)?;
        let count = self.db()?.execute("INSERT INTO orders(id,signer,request,quote,digest,state) SELECT ?1,?2,?3,?4,?5,'reserving' WHERE (SELECT COUNT(*) FROM orders)<10000 ON CONFLICT(id) DO NOTHING",params![quote.order_id,quote.signer_pubkey,request,json,digest(json.as_bytes())])?;
        if count == 0 && self.get(&quote.order_id)?.is_none() {
            return Err(Error::Busy);
        }
        Ok(())
    }
    pub(crate) fn state(&self, id: &str, from: State, to: State) -> Result<(), Error> {
        if self.db()?.execute(
            "UPDATE orders SET state=?1 WHERE id=?2 AND state=?3",
            params![to.key(), id, from.key()],
        )? != 1
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn invoice(&self, id: &str, invoice: &str, hash: &str) -> Result<(), Error> {
        let db = self.db()?;
        let owner: Option<String> = db
            .query_row("SELECT id FROM orders WHERE payment_hash=?1", [hash], |r| {
                r.get(0)
            })
            .optional()?;
        if owner.is_some_and(|v| v != id) {
            return Err(Error::Conflict);
        }
        if db.execute("UPDATE orders SET state='awaiting_payment',invoice=?1,payment_hash=?2 WHERE id=?3 AND state='invoice_pending'",params![invoice,hash,id])?!=1 {return Err(Error::Conflict);}
        Ok(())
    }
    pub(crate) fn rotate(&self, id: &str, note_id: &str, rotation: &Rotation) -> Result<(), Error> {
        let db = self.db()?;
        if db
            .query_row("SELECT 1 FROM orders WHERE note_id=?1", [note_id], |_| {
                Ok(())
            })
            .optional()?
            .is_some()
        {
            return Err(Error::Conflict);
        }
        if db.execute("UPDATE orders SET state='lnurl_pending',note_id=?1,rotation=?2 WHERE id=?3 AND state='quoted'",params![note_id,serde_json::to_string(rotation)?,id])?!=1 {return Err(Error::Conflict);}
        Ok(())
    }
    pub(crate) fn settle(
        &self,
        id: &str,
        from: State,
        reference: &str,
        rotation: Option<&Rotation>,
    ) -> Result<(), Error> {
        let db = self.db()?;
        let owner: Option<String> = db
            .query_row(
                "SELECT id FROM orders WHERE settlement=?1",
                [reference],
                |r| r.get(0),
            )
            .optional()?;
        if owner.is_some_and(|v| v != id) {
            return Err(Error::Conflict);
        }
        if db.execute("UPDATE orders SET state='settled',settlement=?1,rotation=COALESCE(?4,rotation) WHERE id=?2 AND state=?3",params![reference,id,from.key(),rotation.map(serde_json::to_string).transpose()?])?!=1 {return Err(Error::Conflict);}
        Ok(())
    }
    pub(crate) fn activate(&self, id: &str, receipt: &crate::Receipt) -> Result<(), Error> {
        if self.db()?.execute(
            "UPDATE orders SET state='active',receipt=?1 WHERE id=?2 AND state='settled'",
            params![serde_json::to_string(receipt)?, id],
        )? != 1
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn start_refund(&self, id: &str, refund: &RefundJournal) -> Result<(), Error> {
        if self.db()?.execute(
            "UPDATE orders SET refund=?1 WHERE id=?2 AND state='refund_required' AND refund IS NULL",
            params![serde_json::to_string(refund)?, id],
        )? != 1
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn update_refund(&self, id: &str, refund: &RefundJournal) -> Result<(), Error> {
        let current = self
            .get(id)?
            .and_then(|record| record.refund)
            .ok_or(Error::Conflict)?;
        if current.payment_hash != refund.payment_hash || current.request_url != refund.request_url
        {
            return Err(Error::Conflict);
        }
        if self.db()?.execute(
            "UPDATE orders SET refund=?1 WHERE id=?2 AND state='refund_required'",
            params![serde_json::to_string(refund)?, id],
        )? != 1
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn complete_refund(&self, id: &str, refund: &RefundJournal) -> Result<(), Error> {
        if refund.refunded_at.is_none() {
            return Err(Error::Invalid);
        }
        if self.db()?.execute(
            "UPDATE orders SET state='refunded',refund=?1 WHERE id=?2 AND state='refund_required'",
            params![serde_json::to_string(refund)?, id],
        )? != 1
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
