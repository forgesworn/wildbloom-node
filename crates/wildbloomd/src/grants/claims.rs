//! Blocking store work for the delegated claim lifecycle: move to the owner,
//! hand back on a later grant, release on a key's delete, and re-adopt after a
//! rollback demoted claims.
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

/// Whether `signer` holds an active claim on `hash`.  The listing cursor must
/// be one of the signer's active claims, so this is an exact point lookup.
pub(super) fn holds_claim(store: &Store, signer: &str, hash: &str) -> Result<bool, String> {
    match store.list_claims(signer, Some(hash), 1) {
        Ok(_) => Ok(true),
        Err(StoreError::InvalidCursor) => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

fn lock(db: &Mutex<Connection>) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
    db.lock()
        .map_err(|_| "device grant database lock".to_owned())
}

fn database<E>(_: E) -> String {
    "device grant database".to_owned()
}

/// Drop the owner claim a move created, unless the owner held the blob
/// before the move or has written it since.  Runs under the database lock,
/// which owner writes also take to record themselves before they reach the
/// core, so an owner upload is either seen here or lands after this delete.
fn drop_owner_claim_if_ours(
    store: &Store,
    connection: &Connection,
    key: &str,
    hash: &str,
) -> Result<(), String> {
    let Some(record) = db::moved_row(connection, key, hash).map_err(database)? else {
        return Ok(());
    };
    if record.owner_claim_is_ours() {
        match store.delete_claim(hash, &record.owner) {
            Ok(_) | Err(StoreError::NotClaimant | StoreError::MissingBlob) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    db::forget_move(connection, key, hash).map_err(database)
}

/// Move every friend claim `key` holds under its delegated grant to an
/// owner-tier claim for `owner`, recording each move first.  Paid claims are
/// left alone: they belong to a separate allowance with its own retention.
pub(super) fn transfer(
    store: &Store,
    db: &Mutex<Connection>,
    key: &str,
    owner: &str,
    grant_id: &str,
    now: u64,
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
            {
                // Record intent before the owner claim exists, under the lock
                // owner writes take, so `independent` is exact and a
                // concurrent owner upload is never mistaken for the move's.
                // A record left by an interrupted earlier pass keeps its flags.
                let connection = lock(db)?;
                if db::moved_row(&connection, key, &claim.sha256)
                    .map_err(database)?
                    .is_none()
                {
                    let record = MovedClaim {
                        hash: claim.sha256.clone(),
                        owner: owner.to_owned(),
                        size: claim.size,
                        declared_type: declared.clone(),
                        class: claim.class.clone(),
                        independent: holds_claim(store, owner, &claim.sha256)?,
                        adopted: db::recent_owner_write(
                            &connection,
                            owner,
                            &claim.sha256,
                            now.saturating_sub(super::OWNER_WRITE_WINDOW),
                        )
                        .map_err(database)?,
                        moved_at: now,
                    };
                    db::insert_move(&connection, key, &record).map_err(database)?;
                }
            }
            let spec = ClaimSpec {
                signer_pubkey: owner.to_owned(),
                retention_tier: RetentionTier::Owner,
                declared_type: declared,
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
                    db::forget_move(&*lock(db)?, key, &claim.sha256).map_err(database)?;
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            }
            // The owner claim now protects the blob, so this cannot orphan it.
            match store.delete_claim(&claim.sha256, key) {
                Ok(_) | Err(StoreError::NotClaimant | StoreError::MissingBlob) => {}
                Err(error) => return Err(error.to_string()),
            }
            moved += 1;
        }
        if !full {
            return Ok(moved);
        }
    }
}

/// Give an active key back the claims an earlier sweep moved to the same
/// owner, then drop the owner claim the move created (see
/// [`drop_owner_claim_if_ours`]).  A moved claim the owner deleted and has not
/// written again is not handed back.  Claims over the key's current ceiling
/// stay recorded and are retried when the key frees space or its ceiling
/// changes.  Moves to another owner are never read.
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
        let page = db::moved_page(&*lock(db)?, key, &member.issuer, &after, MOVED_PAGE)
            .map_err(database)?;
        let Some(last) = page.last() else {
            return Ok((restored, kept));
        };
        after = last.hash.clone();
        for record in page {
            if !holds_claim(store, &member.issuer, &record.hash)? {
                // The owner deleted it while holding it: that decision wins.
                db::forget_move(&*lock(db)?, key, &record.hash).map_err(database)?;
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
                    let connection = lock(db)?;
                    drop_owner_claim_if_ours(store, &connection, key, &record.hash)?;
                    restored += 1;
                }
                Ok(UploadStart::Reserved(_))
                | Err(
                    StoreError::MissingBlob | StoreError::Tombstoned | StoreError::LengthMismatch,
                ) => {
                    db::forget_move(&*lock(db)?, key, &record.hash).map_err(database)?;
                }
                Err(StoreError::FriendLimitExceeded) => kept += 1,
                Err(error) => return Err(error.to_string()),
            }
        }
    }
}

/// An active key deletes a blob whose claim was moved to `owner` and not yet
/// handed back: drop the owner claim the move created and forget the record.
/// Returns `None` when there is no such record for this owner.
pub(super) fn release(
    store: &Store,
    db: &Mutex<Connection>,
    key: &str,
    owner: &str,
    hash: &str,
) -> Result<Option<()>, String> {
    let connection = lock(db)?;
    match db::moved_row(&connection, key, hash).map_err(database)? {
        Some(record) if record.owner == owner => {
            drop_owner_claim_if_ours(store, &connection, key, hash)?;
            Ok(Some(()))
        }
        _ => Ok(None),
    }
}

/// Re-adopt claims of a delegated key that a binary without device grant
/// support demoted to `guest` (its reconcile clears the grant id).  Only
/// claims made since the key joined the trusted set are adopted, so guest
/// claims the key made before it was granted stay guest.  Runs in batches
/// until every such claim is adopted or refused by the ceiling.
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
            if batch.len() < ADOPT_BATCH
                && claim.uploaded >= member.since
                && !placed.contains(&id)
                && !refused_set.contains(&id)
            {
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
