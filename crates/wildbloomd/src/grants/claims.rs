//! Blocking store work for the delegated claim lifecycle: move to the owner,
//! hand back on a later grant, and re-adopt after a rollback demoted claims.
//!
//! Every walk is paginated through the core's public listing API; nothing is
//! capped or silently truncated.  Hash sets hold 32-byte digests only.
use super::db::{self, Member, MovedClaim};
use rusqlite::Connection;
use std::{collections::HashSet, sync::Mutex};
use wildbloom_core::{
    ClaimMetadata, ClaimSpec, RetentionTier, Store, StoreError, store::UploadStart,
};

const PAGE: usize = 100;
const MOVED_PAGE: usize = 500;
const ADOPT_BATCH: usize = 10_000;
/// Grant ids are never empty, so the grant-scoped listing with this id
/// returns exactly the signer's live `paid` claims.
const PAID_ONLY: &str = "";

type Digest = [u8; 32];

fn digest(hash: &str) -> Digest {
    let mut out = [0_u8; 32];
    // Listing only returns canonical hashes; a failure leaves zeros, which no
    // real claim has, so it can only make a set lookup miss.
    let _ = hex::decode_to_slice(hash, &mut out);
    out
}

fn declared_type(value: &str) -> String {
    if value.is_empty() || value.len() > 255 {
        "application/octet-stream".to_owned()
    } else {
        value.to_owned()
    }
}

fn friend_spec(
    key: &str,
    grant_id: &str,
    member: &Member,
    declared: String,
    class: Option<String>,
) -> ClaimSpec {
    ClaimSpec {
        signer_pubkey: key.to_owned(),
        retention_tier: RetentionTier::Friend,
        declared_type: declared,
        grant_id: Some(grant_id.to_owned()),
        claim_expires_at: Some(super::CORE_GRANT_SENTINEL),
        byte_limit: Some(member.byte_limit),
        class,
    }
}

/// Read-only walk over every claim in one listing view.
fn each_claim(
    store: &Store,
    key: &str,
    grant_id: Option<&str>,
    mut visit: impl FnMut(ClaimMetadata),
) -> Result<(), StoreError> {
    let mut cursor: Option<String> = None;
    loop {
        let page = match grant_id {
            Some(grant_id) => {
                store.list_claims_for_grant(key, grant_id, cursor.as_deref(), PAGE)?
            }
            None => store.list_claims(key, cursor.as_deref(), PAGE)?,
        };
        let full = page.len() == PAGE;
        cursor = page.last().map(|claim| claim.sha256.clone());
        page.into_iter().for_each(&mut visit);
        if !full {
            return Ok(());
        }
    }
}

fn hash_set(
    store: &Store,
    key: &str,
    grant_id: Option<&str>,
) -> Result<HashSet<Digest>, StoreError> {
    let mut set = HashSet::new();
    each_claim(store, key, grant_id, |claim| {
        set.insert(digest(&claim.sha256));
    })?;
    Ok(set)
}

/// Whether `owner` holds an active claim on `hash`.  The listing cursor must
/// be one of the signer's active claims, so this is an exact point lookup.
fn owner_claims(store: &Store, owner: &str, hash: &str) -> Result<bool, String> {
    match store.list_claims(owner, Some(hash), 1) {
        Ok(_) => Ok(true),
        Err(StoreError::InvalidCursor) => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

fn lock(db: &Mutex<Connection>) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
    db.lock()
        .map_err(|_| "device grant database lock".to_owned())
}

/// Move every friend claim `key` holds under its delegated grant to an
/// owner-tier claim for `owner`, recording each move.  Paid claims are left
/// alone: they belong to a separate allowance with its own retention.
pub(super) fn transfer(
    store: &Store,
    db: &Mutex<Connection>,
    key: &str,
    owner: &str,
    grant_id: &str,
) -> Result<u64, String> {
    let paid = hash_set(store, key, Some(PAID_ONLY)).map_err(|e| e.to_string())?;
    let mut attempted = HashSet::new();
    let mut cursor: Option<String> = None;
    let mut moved = 0_u64;
    loop {
        // Moved claims disappear from this view, so the cursor only advances
        // over claims that stay (paid, or already attempted and refused).
        let page = store
            .list_claims_for_grant(key, grant_id, cursor.as_deref(), PAGE)
            .map_err(|e| e.to_string())?;
        let full = page.len() == PAGE;
        for claim in page {
            let id = digest(&claim.sha256);
            if paid.contains(&id) || !attempted.insert(id) {
                cursor = Some(claim.sha256);
                continue;
            }
            let declared = declared_type(&claim.content_type);
            let spec = ClaimSpec {
                signer_pubkey: owner.to_owned(),
                retention_tier: RetentionTier::Owner,
                declared_type: declared.clone(),
                grant_id: None,
                claim_expires_at: None,
                byte_limit: None,
                class: claim.class.clone(),
            };
            // A mirror-style claim never lifts an operator tombstone.
            match store.begin_claimed_mirror(&claim.sha256, claim.size, spec) {
                Ok(UploadStart::Existing(_)) => {}
                // The blob is gone or refused; the reservation cancels on drop.
                Ok(UploadStart::Reserved(_))
                | Err(
                    StoreError::MissingBlob | StoreError::Tombstoned | StoreError::LengthMismatch,
                ) => {
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            }
            // The owner claim now protects the blob, so this cannot orphan it.
            match store.delete_claim(&claim.sha256, key) {
                Ok(_) | Err(StoreError::NotClaimant | StoreError::MissingBlob) => {}
                Err(error) => return Err(error.to_string()),
            }
            db::record_move(
                &*lock(db)?,
                key,
                &MovedClaim {
                    hash: claim.sha256,
                    owner: owner.to_owned(),
                    size: claim.size,
                    declared_type: declared,
                    class: claim.class,
                },
            )
            .map_err(|_| "device grant database".to_owned())?;
            moved += 1;
        }
        if !full {
            return Ok(moved);
        }
    }
}

/// Give an active key back the claims an earlier sweep moved to the same
/// owner.  The owner keeps its own claim; the key's claim is added beside it.
/// A moved claim the owner has since deleted is not handed back.  Claims over
/// the key's current ceiling stay recorded and are retried on later sweeps.
pub(super) fn restore(
    store: &Store,
    db: &Mutex<Connection>,
    key: &str,
    member: &Member,
    grant_id: &str,
) -> Result<(u64, u64), String> {
    let (mut restored, mut kept) = (0_u64, 0_u64);
    let mut after = String::new();
    loop {
        let page = db::moved_page(&*lock(db)?, key, &after, MOVED_PAGE)
            .map_err(|_| "device grant database".to_owned())?;
        let Some(last) = page.last() else {
            return Ok((restored, kept));
        };
        after = last.hash.clone();
        for record in page {
            // Claims moved to a different owner stay with that owner.
            if record.owner != member.issuer {
                kept += 1;
                continue;
            }
            let forget = |db: &Mutex<Connection>| {
                db::forget_move(&*lock(db)?, key, &record.hash)
                    .map_err(|_| "device grant database".to_owned())
            };
            if !owner_claims(store, &member.issuer, &record.hash)? {
                // The owner deleted it while holding it: that decision wins.
                forget(db)?;
                continue;
            }
            let spec = friend_spec(
                key,
                grant_id,
                member,
                record.declared_type.clone(),
                record.class.clone(),
            );
            match store.begin_claimed_mirror(&record.hash, record.size, spec) {
                Ok(UploadStart::Existing(_)) => {
                    forget(db)?;
                    restored += 1;
                }
                Ok(UploadStart::Reserved(_))
                | Err(
                    StoreError::MissingBlob | StoreError::Tombstoned | StoreError::LengthMismatch,
                ) => {
                    forget(db)?;
                }
                Err(StoreError::FriendLimitExceeded) => kept += 1,
                Err(error) => return Err(error.to_string()),
            }
        }
    }
}

/// Re-adopt claims of a delegated key that a binary without device grant
/// support demoted to `guest` (its reconcile clears the grant id).  Runs in
/// batches until every such claim is adopted or refused by the ceiling.
pub(super) fn adopt(
    store: &Store,
    key: &str,
    member: &Member,
    grant_id: &str,
) -> Result<(u64, u64), String> {
    let (mut adopted, mut refused) = (0_u64, 0_u64);
    let mut refused_set = HashSet::new();
    loop {
        // Friend claims under this grant and paid claims are already placed.
        let placed = hash_set(store, key, Some(grant_id)).map_err(|e| e.to_string())?;
        let mut batch = Vec::new();
        each_claim(store, key, None, |claim| {
            let id = digest(&claim.sha256);
            if batch.len() < ADOPT_BATCH && !placed.contains(&id) && !refused_set.contains(&id) {
                batch.push(claim);
            }
        })
        .map_err(|e| e.to_string())?;
        if batch.is_empty() {
            return Ok((adopted, refused));
        }
        for claim in batch {
            let spec = friend_spec(
                key,
                grant_id,
                member,
                declared_type(&claim.content_type),
                claim.class.clone(),
            );
            match store.begin_claimed_mirror(&claim.sha256, claim.size, spec) {
                Ok(UploadStart::Existing(_)) => adopted += 1,
                Ok(UploadStart::Reserved(_))
                | Err(
                    StoreError::FriendLimitExceeded
                    | StoreError::MissingBlob
                    | StoreError::Tombstoned
                    | StoreError::LengthMismatch,
                ) => {
                    refused += 1;
                    refused_set.insert(digest(&claim.sha256));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
    }
}
