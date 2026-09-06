use base64::Engine as _;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use super::{
    Error,
    policy::{self, Blob, Retention, Target, VerifiedPolicy},
    signer::Signer,
    state::{Observation, Pending, StateDirectory, read_bounded},
    transport::Transport,
};

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> u64 {
        nostr::prelude::Timestamp::now().as_secs()
    }
}

pub fn load_policy(path: &Path, owner: &str, now: u64) -> Result<VerifiedPolicy, Error> {
    Ok(policy::verify_policy(
        &read_bounded(path, policy::MAX_POLICY_BYTES)?,
        owner,
        now,
    )?)
}

pub struct Guard<'a> {
    pub path: &'a Path,
    pub expected: &'a VerifiedPolicy,
    pub clock: &'a dyn Clock,
}

impl Guard<'_> {
    pub fn check(&self) -> Result<(), Error> {
        let current = load_policy(self.path, &self.expected.owner, self.clock.now())?;
        if current.event_id != self.expected.event_id {
            return Err(Error::Changed);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct BlobReport {
    pub sha256: String,
    pub verified_configured_groups: usize,
    pub desired_groups: u8,
    pub observations: BTreeMap<String, Observation>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub policy_id: String,
    pub revision: u64,
    pub observed_at: u64,
    pub stopped: bool,
    pub verification_bytes_reserved: u64,
    pub mirror_attempts: usize,
    pub repair_attempts: usize,
    pub blobs: Vec<BlobReport>,
    pub pending_event_ids: Vec<String>,
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub verification_bytes: u64,
    pub mirrors: usize,
}

impl Limits {
    pub fn validate(self, policy: &VerifiedPolicy) -> Result<(), Error> {
        if !(1..=16).contains(&self.mirrors)
            || self.verification_bytes == 0
            || self.verification_bytes > 256 * policy::MAX_BLOB_BYTES
        {
            return Err(Error::Configuration("invalid replica work limits"));
        }
        // One complete blob scan plus every permitted read-back must fit.
        // This guarantees the rotating cursor cannot starve a large blob.
        if policy.policy.desired_groups > 0
            && policy.policy.blobs.iter().any(|blob| {
                blob.size * (policy.policy.targets.len() + self.mirrors) as u64
                    > self.verification_bytes
            })
        {
            return Err(Error::Configuration(
                "verification budget cannot fit one complete blob scan and repair read-backs",
            ));
        }
        Ok(())
    }
}

enum Authorisation {
    Ready(String),
    Awaiting,
    Unavailable,
}

async fn authorise(
    guard: &Guard<'_>,
    state: &mut StateDirectory,
    signer: Option<&dyn Signer>,
    blob: &Blob,
    target: &Target,
) -> Result<Authorisation, Error> {
    guard.check()?;
    let key = format!("{}:{}", blob.sha256, target.id);
    let now = guard.clock.now();
    let previous = state
        .snapshot
        .as_ref()
        .ok_or(Error::Internal)?
        .pending
        .get(&key)
        .cloned();
    let requested_at = match previous {
        Some(pending)
            if pending.requested_at <= now && pending.requested_at.saturating_add(120) > now =>
        {
            pending.requested_at
        }
        Some(pending) => {
            state.remove_request(&pending.event_id)?;
            state
                .snapshot
                .as_mut()
                .ok_or(Error::Internal)?
                .pending
                .remove(&key);
            now
        }
        None => now,
    };
    let request = policy::repair_template(guard.expected, blob, target, requested_at)?;
    let id = request.compute_id().to_hex();
    if let Some(old) = state
        .snapshot
        .as_ref()
        .ok_or(Error::Internal)?
        .pending
        .get(&key)
        && old.event_id != id
    {
        return Err(Error::Internal);
    }
    let bytes = if let Some(signer) = signer {
        guard.check()?;
        let result = signer.sign(&request).await;
        guard.check()?;
        result.ok()
    } else {
        state
            .snapshot
            .as_mut()
            .ok_or(Error::Internal)?
            .pending
            .insert(
                key.clone(),
                Pending {
                    requested_at,
                    event_id: id.clone(),
                },
            );
        state.save()?;
        state.write_request(&id, &serde_json::to_vec_pretty(&request)?)?;
        let signed_path = state.pending_path(&id, true);
        match std::fs::symlink_metadata(&signed_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Authorisation::Awaiting);
            }
            Err(_) => return Err(super::state::StateError::Io.into()),
            Ok(_) => read_bounded(&signed_path, policy::MAX_EVENT_BYTES).ok(),
        }
    };
    guard.check()?;
    let event =
        bytes.and_then(|bytes| policy::verify_return(&bytes, &request, guard.clock.now()).ok());
    // Consume before sending. An interrupted write needs another explicit
    // authorisation; signed bearer events never enter persistent observations.
    state
        .snapshot
        .as_mut()
        .ok_or(Error::Internal)?
        .pending
        .remove(&key);
    state.save()?;
    state.remove_request(&id)?;
    Ok(match event {
        Some(event) => Authorisation::Ready(format!(
            "Nostr {}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(event.as_json())
        )),
        None => Authorisation::Unavailable,
    })
}

fn groups(
    policy: &VerifiedPolicy,
    observations: &BTreeMap<String, Observation>,
) -> BTreeSet<String> {
    policy
        .policy
        .targets
        .iter()
        .filter(|target| {
            target.retention == Retention::Owner
                && matches!(
                    observations.get(&target.id),
                    Some(Observation::Verified { .. })
                )
        })
        .map(|target| target.failure_group.clone())
        .collect()
}

fn prune_pending(guard: &Guard<'_>, state: &mut StateDirectory) -> Result<(), Error> {
    let snapshot = state.snapshot.as_mut().ok_or(Error::Internal)?;
    let now = guard.clock.now();
    let completed = snapshot
        .observations
        .iter()
        .filter(|(_, observations)| {
            groups(guard.expected, observations).len()
                >= usize::from(guard.expected.policy.desired_groups)
        })
        .map(|(hash, _)| hash.clone())
        .collect::<BTreeSet<_>>();
    snapshot.pending.retain(|key, pending| {
        let Some((hash, id)) = key.split_once(':') else {
            return false;
        };
        let Some(blob) = guard
            .expected
            .policy
            .blobs
            .iter()
            .find(|blob| blob.sha256 == hash)
        else {
            return false;
        };
        let Some(target) = guard
            .expected
            .policy
            .targets
            .iter()
            .find(|target| target.id == id && target.retention == Retention::Owner)
        else {
            return false;
        };
        !completed.contains(hash)
            && pending.requested_at <= now
            && pending.requested_at.saturating_add(120) > now
            && !matches!(
                snapshot
                    .observations
                    .get(hash)
                    .and_then(|targets| targets.get(id)),
                Some(Observation::Verified { .. })
            )
            && policy::repair_template(guard.expected, blob, target, pending.requested_at)
                .is_ok_and(|request| request.compute_id().to_hex() == pending.event_id)
    });
    let keep = snapshot
        .pending
        .values()
        .map(|pending| pending.event_id.clone())
        .collect::<Vec<_>>();
    state.save()?;
    state.reconcile_pending_files(&keep)?;
    Ok(())
}

pub async fn run_pass(
    guard: &Guard<'_>,
    state: &mut StateDirectory,
    transport: &dyn Transport,
    signer: Option<&dyn Signer>,
    limits: Limits,
) -> Result<Report, Error> {
    let result = pass_inner(guard, state, transport, signer, limits).await;
    if result.is_err() {
        state.invalidate()?;
    }
    result
}

async fn pass_inner(
    guard: &Guard<'_>,
    state: &mut StateDirectory,
    transport: &dyn Transport,
    signer: Option<&dyn Signer>,
    limits: Limits,
) -> Result<Report, Error> {
    guard.check()?;
    limits.validate(guard.expected)?;
    state.accept(guard.expected)?;
    let policy = &guard.expected.policy;
    let stopped = policy.desired_groups == 0;
    if stopped {
        state.invalidate()?;
    }
    let snapshot = state.snapshot.as_mut().ok_or(Error::Internal)?;
    let start = snapshot.cursor;
    // Previous passes are history, never evidence for the current floor.
    snapshot.observations = policy
        .blobs
        .iter()
        .map(|blob| {
            (
                blob.sha256.clone(),
                policy
                    .targets
                    .iter()
                    .map(|target| (target.id.clone(), Observation::Deferred))
                    .collect(),
            )
        })
        .collect();
    snapshot.observed_at = None;
    state.save()?;
    prune_pending(guard, state)?;
    let mut used = 0;
    let mut attempts = 0;
    let mut writes = 0;
    if !stopped {
        for offset in 0..policy.blobs.len() {
            let index = (start + offset) % policy.blobs.len();
            let blob = &policy.blobs[index];
            let reserve = blob.size * (policy.targets.len() + limits.mirrors - attempts) as u64;
            if used + reserve > limits.verification_bytes {
                break;
            }
            let mut observations = BTreeMap::new();
            let mut sources = Vec::new();
            for target in &policy.targets {
                guard.check()?;
                let result = transport.verify(target, blob).await;
                guard.check()?;
                used += blob.size;
                let observation = match result {
                    Ok(()) => {
                        sources.push(target);
                        Observation::Verified {
                            at: guard.clock.now(),
                        }
                    }
                    Err(reason) => Observation::Failed { reason },
                };
                observations.insert(target.id.clone(), observation);
            }
            let mut pairs = Vec::new();
            for source in &sources {
                for target in &policy.targets {
                    if target.retention == Retention::Owner && source.origin != target.origin {
                        pairs.push((target, *source));
                    }
                }
            }
            let repair_start = *state
                .snapshot
                .as_ref()
                .ok_or(Error::Internal)?
                .repair_cursors
                .get(&blob.sha256)
                .unwrap_or(&0);
            let mut waiting = BTreeSet::new();
            for offset in 0..pairs.len() {
                let pair_index = (repair_start + offset) % pairs.len();
                let (target, source) = pairs[pair_index];
                if groups(guard.expected, &observations).len() >= usize::from(policy.desired_groups)
                    || attempts >= limits.mirrors
                {
                    break;
                }
                if target.retention != Retention::Owner
                    || groups(guard.expected, &observations).contains(&target.failure_group)
                    || waiting.contains(&target.id)
                {
                    continue;
                }
                // All sources passed a complete read in this pass. A disappearing
                // source can fail the mirror; another configured source may work.
                {
                    state
                        .snapshot
                        .as_mut()
                        .ok_or(Error::Internal)?
                        .repair_cursors
                        .insert(blob.sha256.clone(), (pair_index + 1) % pairs.len());
                    state.save()?;
                    attempts += 1;
                    let authorisation = authorise(guard, state, signer, blob, target).await?;
                    let header = match authorisation {
                        Authorisation::Ready(header) => header,
                        Authorisation::Awaiting => {
                            observations
                                .insert(target.id.clone(), Observation::AwaitingAuthorisation);
                            waiting.insert(target.id.clone());
                            continue;
                        }
                        Authorisation::Unavailable => {
                            observations.insert(target.id.clone(), Observation::SignerUnavailable);
                            waiting.insert(target.id.clone());
                            continue;
                        }
                    };
                    guard.check()?;
                    let host = url::Url::parse(&target.origin)
                        .map_err(|_| Error::Internal)?
                        .host_str()
                        .ok_or(Error::Internal)?
                        .to_owned();
                    if wildbloom_core::auth::AuthPolicy::new([host])
                        .with_allowed_pubkeys([guard.expected.owner.clone()])
                        .verify_upload(Some(&header), &blob.sha256, guard.clock.now())
                        .is_err()
                    {
                        observations.insert(target.id.clone(), Observation::SignerUnavailable);
                        continue;
                    }
                    writes += 1;
                    let result = transport.mirror(target, source, blob, &header).await;
                    drop(header);
                    guard.check()?;
                    match result {
                        Ok(()) => {
                            observations.insert(target.id.clone(), Observation::Acknowledged);
                            state
                                .snapshot
                                .as_mut()
                                .ok_or(Error::Internal)?
                                .observations
                                .insert(blob.sha256.clone(), observations.clone());
                            state.save()?;
                            guard.check()?;
                            let result = transport.verify(target, blob).await;
                            guard.check()?;
                            used += blob.size;
                            match result {
                                Ok(()) => {
                                    observations.insert(
                                        target.id.clone(),
                                        Observation::Verified {
                                            at: guard.clock.now(),
                                        },
                                    );
                                }
                                Err(reason) => {
                                    observations
                                        .insert(target.id.clone(), Observation::Failed { reason });
                                }
                            }
                        }
                        Err(reason) => {
                            observations.insert(target.id.clone(), Observation::Failed { reason });
                        }
                    }
                }
            }
            let snapshot = state.snapshot.as_mut().ok_or(Error::Internal)?;
            snapshot
                .observations
                .insert(blob.sha256.clone(), observations);
            snapshot.cursor = (index + 1) % policy.blobs.len();
            state.save()?;
        }
    }
    guard.check()?;
    prune_pending(guard, state)?;
    let snapshot = state.snapshot.as_mut().ok_or(Error::Internal)?;
    let now = guard.clock.now();
    snapshot.observed_at = Some(now);
    let report = Report {
        policy_id: policy.id.clone(),
        revision: policy.revision,
        observed_at: now,
        stopped,
        verification_bytes_reserved: used,
        mirror_attempts: writes,
        repair_attempts: attempts,
        blobs: policy
            .blobs
            .iter()
            .map(|blob| {
                let observations = snapshot
                    .observations
                    .get(&blob.sha256)
                    .cloned()
                    .unwrap_or_default();
                BlobReport {
                    sha256: blob.sha256.clone(),
                    verified_configured_groups: groups(guard.expected, &observations).len(),
                    desired_groups: policy.desired_groups,
                    observations,
                }
            })
            .collect(),
        pending_event_ids: snapshot
            .pending
            .values()
            .map(|pending| pending.event_id.clone())
            .collect(),
    };
    state.save()?;
    Ok(report)
}
