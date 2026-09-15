//! Enrolment: turn a source inventory into signed replica policies.
//!
//! One run reads an inventory of exact blobs (hash and size) that one
//! source currently holds, appends newly seen blobs to an append-only ledger,
//! reads the intake coordinator's last observations, and derives two kinds of
//! policy from the ledger rather than from the source:
//!
//! - `<prefix>-intake` lists the source as a guest target plus every archive
//!   as an owner target, and holds a blob only until the archives verify it.
//! - `<prefix>-archive-<hex>` lists the archives only and holds a blob for
//!   good, chunked by leading hash hex so no policy exceeds 128 blobs.
//!
//! The source appears only in intake because every coordinator pass reads
//! every blob from every target in full. A source whose retention counts from
//! the last read would otherwise keep every blob forever. The ledger, not the
//! source, decides archive membership, so a blob the source later forgets
//! stays archived.
//!
//! Only policies whose content changed, or whose expiry is near, are signed.
//! Every signed return is verified as this owner's policy for exactly the
//! content requested before it is written. Nothing here deletes a file.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use super::{
    Error,
    engine::Clock,
    policy::{self, Blob, Policy, Retention, Target},
    signer::Signer,
    state::{self, Observation, Snapshot},
    transport::Profile,
};

type Observations = BTreeMap<String, BTreeMap<String, Observation>>;

pub const MAX_POLICY_BLOBS: usize = 128;
const DAY: u64 = 86_400;
const MAX_LEDGER_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_INVENTORY_BYTES: usize = 64 * 1024 * 1024;

fn default_profile() -> Profile {
    Profile::TorOnly
}
fn default_ttl_days() -> u64 {
    30
}
fn default_renew_below_days() -> u64 {
    7
}
fn default_grace_days() -> u64 {
    7
}
fn default_signer_timeout() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSpec {
    pub id: String,
    pub origin: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Holds `state/`, `policies/` and, unless overridden, `coordinators/`.
    pub root: PathBuf,
    /// Coordinator state directories, one per policy id.
    #[serde(default)]
    pub state_root: Option<PathBuf>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub owner_file: Option<PathBuf>,
    pub signer: PathBuf,
    #[serde(default)]
    pub signer_args: Vec<String>,
    #[serde(default = "default_signer_timeout")]
    pub signer_timeout_secs: u64,
    /// Policy ids are `<prefix>-intake` and `<prefix>-archive-<hex>`.
    pub policy_prefix: String,
    #[serde(default = "default_profile")]
    pub profile: Profile,
    /// The one source intake reads from. Never counted, never repaired.
    pub source: TargetSpec,
    pub archives: Vec<TargetSpec>,
    /// Inventory rows of any other declared type are counted, not enrolled.
    #[serde(default)]
    pub accept_types: Option<Vec<String>>,
    #[serde(default = "default_ttl_days")]
    pub policy_ttl_days: u64,
    #[serde(default = "default_renew_below_days")]
    pub renew_below_days: u64,
    #[serde(default = "default_grace_days")]
    pub intake_grace_days: u64,
}

impl Config {
    pub fn state_root(&self) -> PathBuf {
        self.state_root
            .clone()
            .unwrap_or_else(|| self.root.join("coordinators"))
    }

    pub fn owner(&self) -> Result<String, Error> {
        let owner = match (&self.owner, &self.owner_file) {
            (Some(owner), None) => owner.trim().to_owned(),
            (None, Some(path)) => String::from_utf8(state::read_bounded(path, 256)?)
                .map_err(|_| Error::Configuration("owner file is not text"))?
                .trim()
                .to_owned(),
            _ => {
                return Err(Error::Configuration(
                    "configure exactly one of owner or owner_file",
                ));
            }
        };
        if !policy::canonical_hex(&owner, 32) {
            return Err(Error::Configuration(
                "owner must be a lowercase hexadecimal public key",
            ));
        }
        Ok(owner)
    }

    fn intake_id(&self) -> String {
        format!("{}-intake", self.policy_prefix)
    }

    fn archive_prefix(&self) -> String {
        format!("{}-archive-", self.policy_prefix)
    }

    fn validate(&self) -> Result<(), Error> {
        if !self.root.is_absolute()
            || !self.signer.is_absolute()
            || !self.state_root().is_absolute()
        {
            return Err(Error::Configuration(
                "root, state_root and signer must be absolute paths",
            ));
        }
        if !policy::identifier(&self.policy_prefix) || self.policy_prefix.len() > 40 {
            return Err(Error::Configuration(
                "policy_prefix must be a short lowercase identifier",
            ));
        }
        if self.archives.is_empty() || self.archives.len() > 15 {
            return Err(Error::Configuration(
                "configure between one and fifteen archives",
            ));
        }
        let mut ids = BTreeSet::new();
        for spec in std::iter::once(&self.source).chain(&self.archives) {
            if !policy::identifier(&spec.id) || !ids.insert(spec.id.as_str()) {
                return Err(Error::Configuration(
                    "target ids must be unique lowercase identifiers",
                ));
            }
        }
        if self.policy_ttl_days == 0 || self.policy_ttl_days > 365 {
            return Err(Error::Configuration(
                "policy_ttl_days must be between 1 and 365",
            ));
        }
        Ok(())
    }

    fn source_target(&self) -> Target {
        Target {
            id: self.source.id.clone(),
            origin: self.source.origin.clone(),
            failure_group: self.source.id.clone(),
            retention: Retention::Guest,
        }
    }

    fn archive_targets(&self) -> Vec<Target> {
        self.archives
            .iter()
            .map(|spec| Target {
                id: spec.id.clone(),
                origin: spec.origin.clone(),
                failure_group: spec.id.clone(),
                retention: Retention::Owner,
            })
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct InventoryRow {
    pub sha256: String,
    pub size: u64,
    #[serde(default, rename = "type")]
    pub content_type: Option<String>,
    #[serde(default)]
    pub uploaded: Option<u64>,
}

/// Parse an inventory: a JSON array of rows. Empty input is refused, never
/// read as an empty source, because an empty source marks every blob still
/// in intake as lost.
pub fn parse_inventory(bytes: &[u8]) -> Result<Vec<InventoryRow>, Error> {
    if bytes.len() > MAX_INVENTORY_BYTES {
        return Err(Error::Configuration("inventory exceeds its size limit"));
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::Configuration(
            "inventory is empty; an empty source must be the JSON array []",
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| Error::Configuration("inventory is not a JSON array of rows"))
}

#[derive(Debug, Default, Serialize)]
pub struct LedgerCounts {
    pub intake: usize,
    pub archived: usize,
    pub lost: usize,
}

#[derive(Debug, Serialize)]
pub struct ArchivedBlob {
    pub hash: String,
    pub verified_on: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SignedPolicy {
    pub id: String,
    pub revision: u64,
    pub why: &'static str,
    pub blobs: usize,
    pub desired_groups: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub at: u64,
    pub dry_run: bool,
    pub ledger: LedgerCounts,
    pub long_term_copies: String,
    pub intake_state_trusted: bool,
    pub source_blobs: usize,
    pub foreign_types: usize,
    pub new: Vec<String>,
    pub archived: Vec<ArchivedBlob>,
    pub lost: Vec<String>,
    pub signed: Vec<SignedPolicy>,
    pub unchanged: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistoryRecord {
    at: u64,
    id: String,
    revision: u64,
    event: String,
    expires_at: u64,
    content_fp: String,
    targets_fp: String,
    desired_groups: u8,
    blobs: usize,
}

struct LedgerBlob {
    size: u64,
    first_seen: u64,
    uploaded: Option<u64>,
    archived: bool,
    lost: bool,
}

struct Desired {
    targets: Vec<Target>,
    desired_groups: u8,
    blobs: Vec<Blob>,
}

/// JSON with object keys sorted at every level and no whitespace. Stable
/// across implementations, so a history written by another enrolment tool
/// for the same root still matches.
fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical(&map[key])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => other.to_string(),
    }
}

#[cfg(test)]
pub fn canonical_for_tests(value: &Value) -> String {
    canonical(value)
}

fn fingerprint(value: &Value) -> String {
    hex::encode(Sha256::digest(canonical(value).as_bytes()))
}

fn content_fingerprint(desired: &Desired) -> Result<String, Error> {
    Ok(fingerprint(&json!({
        "targets": serde_json::to_value(&desired.targets)?,
        "desired_groups": desired.desired_groups,
        "blobs": serde_json::to_value(&desired.blobs)?,
    })))
}

fn targets_fingerprint(targets: &[Target]) -> Result<String, Error> {
    Ok(fingerprint(&serde_json::to_value(targets)?))
}

fn read_json_lines(path: &Path) -> Result<Vec<Value>, Error> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(state::StateError::Io.into()),
        Ok(_) => {}
    }
    let bytes = state::read_bounded(path, MAX_LEDGER_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| state::StateError::Schema)?;
    text.lines()
        .filter(|line| !line.is_empty())
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|_| {
                Error::Enrol(format!(
                    "{} line {} is not JSON; refusing to guess",
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    index + 1
                ))
            })
        })
        .collect()
}

fn append_line(path: &Path, value: &impl Serialize) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| state::StateError::Io)?;
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    file.write_all(&line).map_err(|_| state::StateError::Io)?;
    file.sync_all().map_err(|_| state::StateError::Io)?;
    Ok(())
}

fn partition(hashes: &[String], prefix: &str) -> Vec<(String, Vec<String>)> {
    if hashes.len() <= MAX_POLICY_BLOBS && !prefix.is_empty() {
        return vec![(prefix.to_owned(), hashes.to_vec())];
    }
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for hash in hashes {
        groups
            .entry(hash[..prefix.len() + 1].to_owned())
            .or_default()
            .push(hash.clone());
    }
    groups
        .into_iter()
        .flat_map(|(next, members)| partition(&members, &next))
        .collect()
}

/// Read a coordinator's observations, trusting them only when its accepted
/// policy event is one this enrolment signed, for this owner, with exactly
/// the given targets. The coordinator discards observations whenever it
/// accepts a new revision, so observations always describe that event.
fn trusted_observations(
    state_root: &Path,
    id: &str,
    targets: &[Target],
    history: &BTreeMap<String, Vec<HistoryRecord>>,
    owner: &str,
) -> Result<Option<Observations>, Error> {
    let path = state_root.join(id).join("state.json");
    let Ok(bytes) = state::read_bounded(&path, state::MAX_STATE_BYTES) else {
        return Ok(None);
    };
    let Ok(snapshot) = serde_json::from_slice::<Snapshot>(&bytes) else {
        return Ok(None);
    };
    let expected_targets = targets_fingerprint(targets)?;
    let trusted = snapshot.owner == owner
        && snapshot.policy_id == id
        && history.get(id).is_some_and(|records| {
            records.iter().any(|record| {
                record.event == snapshot.event_id && record.targets_fp == expected_targets
            })
        });
    Ok(trusted.then_some(snapshot.observations))
}

struct Paths {
    ledger: PathBuf,
    history: PathBuf,
    lock: PathBuf,
    policies: PathBuf,
    state_root: PathBuf,
}

/// One enrolment run. `signer` may be absent only for a dry run.
pub async fn run(
    config: &Config,
    inventory: &[InventoryRow],
    signer: Option<&dyn Signer>,
    clock: &dyn Clock,
    dry_run: bool,
) -> Result<Report, Error> {
    config.validate()?;
    let owner = config.owner()?;
    if signer.is_none() && !dry_run {
        return Err(Error::Configuration(
            "enrolment needs a signer unless it is a dry run",
        ));
    }
    let now = clock.now();
    let state_dir = config.root.join("state");
    let paths = Paths {
        ledger: state_dir.join("ledger.jsonl"),
        history: state_dir.join("policy-history.jsonl"),
        lock: state_dir.join("enrol.lock"),
        policies: config.root.join("policies"),
        state_root: config.state_root(),
    };
    for dir in [&state_dir, &paths.policies, &paths.state_root] {
        state::private_directory(dir)?;
    }
    // Held for the whole run and released on exit. The file itself is never
    // removed.
    let _lock = if dry_run {
        None
    } else {
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&paths.lock)
            .map_err(|_| state::StateError::Io)?;
        fs2::FileExt::try_lock_exclusive(&file)
            .map_err(|_| Error::Enrol("another enrolment run holds the lock".into()))?;
        Some(file)
    };
    let append = |path: &Path, value: &Value| -> Result<(), Error> {
        if dry_run {
            Ok(())
        } else {
            append_line(path, value)
        }
    };

    // ---- inventory -------------------------------------------------------
    let mut on_source: BTreeMap<String, (u64, Option<u64>)> = BTreeMap::new();
    let mut foreign_types = 0;
    for row in inventory {
        if let (Some(accepted), Some(declared)) = (&config.accept_types, &row.content_type)
            && !accepted.contains(declared)
        {
            foreign_types += 1;
            continue;
        }
        if config.accept_types.is_some() && row.content_type.is_none() {
            foreign_types += 1;
            continue;
        }
        if !policy::canonical_hex(&row.sha256, 32)
            || row.size == 0
            || row.size > policy::MAX_BLOB_BYTES
        {
            return Err(Error::Enrol(
                "inventory row is not an exact sha256 and size".into(),
            ));
        }
        on_source.insert(row.sha256.clone(), (row.size, row.uploaded));
    }

    // ---- ledger ----------------------------------------------------------
    let mut blobs: BTreeMap<String, LedgerBlob> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for event in read_json_lines(&paths.ledger)? {
        let hash = event["hash"].as_str().unwrap_or_default().to_owned();
        match event["event"].as_str() {
            Some("seen") => {
                if !blobs.contains_key(&hash) {
                    order.push(hash.clone());
                }
                blobs.insert(
                    hash,
                    LedgerBlob {
                        size: event["size"].as_u64().unwrap_or(0),
                        first_seen: event["at"].as_u64().unwrap_or(0),
                        uploaded: event["uploaded"].as_u64(),
                        archived: false,
                        lost: false,
                    },
                );
            }
            Some("archived") => {
                if let Some(blob) = blobs.get_mut(&hash) {
                    blob.archived = true;
                }
            }
            Some("lost") => {
                if let Some(blob) = blobs.get_mut(&hash) {
                    blob.lost = true;
                }
            }
            _ => {}
        }
    }

    let mut report = Report {
        at: now,
        dry_run,
        ledger: LedgerCounts::default(),
        long_term_copies: if config.archives.len() == 1 {
            "one long-term copy".into()
        } else {
            format!("{} long-term copies", config.archives.len())
        },
        intake_state_trusted: false,
        source_blobs: on_source.len(),
        foreign_types,
        new: Vec::new(),
        archived: Vec::new(),
        lost: Vec::new(),
        signed: Vec::new(),
        unchanged: Vec::new(),
    };

    let mut arrivals: Vec<(&String, &(u64, Option<u64>))> = on_source.iter().collect();
    arrivals.sort_by(
        |(a_hash, (_, a_up)), (b_hash, (_, b_up))| match (a_up, b_up) {
            (Some(a), Some(b)) if a != b => a.cmp(b),
            _ => a_hash.cmp(b_hash),
        },
    );
    for (hash, (size, uploaded)) in arrivals {
        if let Some(known) = blobs.get(hash) {
            if known.size != *size {
                return Err(Error::Enrol(format!(
                    "blob {} changed size; content addressing is broken, refusing",
                    &hash[..16]
                )));
            }
            continue;
        }
        blobs.insert(
            hash.clone(),
            LedgerBlob {
                size: *size,
                first_seen: now,
                uploaded: *uploaded,
                archived: false,
                lost: false,
            },
        );
        order.push(hash.clone());
        let mut seen = json!({ "at": now, "event": "seen", "hash": hash, "size": size });
        if let Some(uploaded) = uploaded {
            seen["uploaded"] = json!(uploaded);
        }
        append(&paths.ledger, &seen)?;
        report.new.push(hash.clone());
    }

    // ---- history ---------------------------------------------------------
    let mut history: BTreeMap<String, Vec<HistoryRecord>> = BTreeMap::new();
    for value in read_json_lines(&paths.history)? {
        let record: HistoryRecord = serde_json::from_value(value)
            .map_err(|_| Error::Enrol("policy history record has an unexpected shape".into()))?;
        history.entry(record.id.clone()).or_default().push(record);
    }

    let source_target = config.source_target();
    let archive_targets = config.archive_targets();
    let archive_ids: Vec<&str> = archive_targets.iter().map(|t| t.id.as_str()).collect();
    let intake_id = config.intake_id();
    let archive_prefix = config.archive_prefix();
    let intake_targets: Vec<Target> = std::iter::once(source_target)
        .chain(archive_targets.iter().cloned())
        .collect();
    let groups_wanted = u8::try_from(archive_targets.len())
        .map_err(|_| Error::Configuration("too many archives"))?;

    // ---- intake verdicts -------------------------------------------------
    if let Some(observations) = trusted_observations(
        &paths.state_root,
        &intake_id,
        &intake_targets,
        &history,
        &owner,
    )? {
        report.intake_state_trusted = true;
        for hash in &order {
            let blob = blobs.get_mut(hash).ok_or(Error::Internal)?;
            if blob.archived {
                continue;
            }
            let verified_on: Vec<String> = archive_ids
                .iter()
                .filter(|id| {
                    observations
                        .get(hash)
                        .and_then(|targets| targets.get(**id))
                        .is_some_and(|observation| {
                            matches!(observation, Observation::Verified { .. })
                        })
                })
                .map(|id| (*id).to_owned())
                .collect();
            let all = verified_on.len() == archive_ids.len();
            let grace_over = !verified_on.is_empty()
                && now.saturating_sub(blob.first_seen) >= config.intake_grace_days * DAY;
            if all || grace_over {
                blob.archived = true;
                let reason = if all {
                    "all archives verified".to_owned()
                } else {
                    format!("grace {}d, partial", config.intake_grace_days)
                };
                append(
                    &paths.ledger,
                    &json!({
                        "at": now, "event": "archived", "hash": hash,
                        "verified_on": verified_on, "reason": reason,
                    }),
                )?;
                report.archived.push(ArchivedBlob {
                    hash: hash.clone(),
                    verified_on,
                });
            }
        }
    }

    for hash in &order {
        let blob = blobs.get_mut(hash).ok_or(Error::Internal)?;
        if !blob.archived && !blob.lost && !on_source.contains_key(hash) {
            blob.lost = true;
            append(
                &paths.ledger,
                &json!({
                    "at": now, "event": "lost", "hash": hash,
                    "note": "gone from the source before any archive verified it",
                }),
            )?;
            report.lost.push(hash.clone());
        }
    }

    // ---- desired policies ------------------------------------------------
    let mut desired: BTreeMap<String, Desired> = BTreeMap::new();
    let mut waiting: Vec<&String> = order.iter().filter(|hash| !blobs[*hash].archived).collect();
    waiting.sort_by(|a, b| {
        let (x, y) = (&blobs[*a], &blobs[*b]);
        x.first_seen
            .cmp(&y.first_seen)
            .then(x.uploaded.unwrap_or(0).cmp(&y.uploaded.unwrap_or(0)))
            .then(a.cmp(b))
    });
    let intake_blobs: Vec<Blob> = waiting
        .into_iter()
        .take(MAX_POLICY_BLOBS)
        .map(|hash| Blob {
            sha256: hash.clone(),
            size: blobs[hash].size,
        })
        .collect();
    if !intake_blobs.is_empty() || history.contains_key(&intake_id) {
        desired.insert(
            intake_id.clone(),
            Desired {
                targets: intake_targets.clone(),
                desired_groups: if intake_blobs.is_empty() {
                    0
                } else {
                    groups_wanted
                },
                blobs: intake_blobs,
            },
        );
    }

    let mut archived: Vec<String> = blobs
        .iter()
        .filter(|(_, blob)| blob.archived)
        .map(|(hash, _)| hash.clone())
        .collect();
    archived.sort();
    for (prefix, members) in partition(&archived, "") {
        desired.insert(
            format!("{archive_prefix}{prefix}"),
            Desired {
                targets: archive_targets.clone(),
                desired_groups: groups_wanted,
                blobs: members
                    .iter()
                    .map(|hash| Blob {
                        sha256: hash.clone(),
                        size: blobs[hash].size,
                    })
                    .collect(),
            },
        );
    }
    for (id, records) in &history {
        if id.starts_with(&archive_prefix)
            && !desired.contains_key(id)
            && records
                .last()
                .is_some_and(|record| record.desired_groups != 0)
        {
            desired.insert(
                id.clone(),
                Desired {
                    targets: archive_targets.clone(),
                    desired_groups: 0,
                    blobs: Vec::new(),
                },
            );
        }
    }

    // ---- sign what changed -----------------------------------------------
    for (id, spec) in &desired {
        let fp = content_fingerprint(spec)?;
        let last = history.get(id).and_then(|records| records.last()).cloned();
        let expiring = last
            .as_ref()
            .is_some_and(|record| record.expires_at < now + config.renew_below_days * DAY);
        if let Some(record) = &last
            && record.content_fp == fp
            && !expiring
        {
            report.unchanged.push(id.clone());
            continue;
        }
        let why = match &last {
            None => "new",
            Some(record) if record.content_fp != fp => "changed",
            Some(_) => "renewing expiry",
        };
        let revision = last.as_ref().map_or(0, |record| record.revision) + 1;
        if dry_run {
            report.signed.push(SignedPolicy {
                id: id.clone(),
                revision,
                why,
                blobs: spec.blobs.len(),
                desired_groups: spec.desired_groups,
                event: None,
                dry_run: true,
            });
            continue;
        }
        let expires_at = now + config.policy_ttl_days * DAY;
        let content = Policy {
            policy_type: "wildbloom.replica-policy".into(),
            version: 1,
            id: id.clone(),
            revision,
            expires_at,
            profile: config.profile,
            desired_groups: spec.desired_groups,
            targets: spec.targets.clone(),
            blobs: spec.blobs.clone(),
        };
        let request = policy::policy_template(content.clone(), &owner, now)?;
        let signer = signer.ok_or(Error::Internal)?;
        let bytes = signer
            .sign(&request)
            .await
            .map_err(|_| Error::Enrol(format!("signer refused or failed the {id} policy")))?;
        let verified = policy::verify_policy(&bytes, &owner, clock.now())?;
        if serde_json::to_value(&verified.policy)? != serde_json::to_value(&content)? {
            return Err(Error::Enrol(format!(
                "signer returned a different policy than {id} requested"
            )));
        }
        // File first, history second: a crash between them costs one revision
        // number, never a coordinator left on a policy this run replaced.
        state::write_private(&paths.policies, &format!("signed-{id}.json"), &bytes)?;
        state::private_directory(&paths.state_root.join(id))?;
        let record = HistoryRecord {
            at: now,
            id: id.clone(),
            revision,
            event: verified.event_id.clone(),
            expires_at,
            content_fp: fp,
            targets_fp: targets_fingerprint(&spec.targets)?,
            desired_groups: spec.desired_groups,
            blobs: spec.blobs.len(),
        };
        append_line(&paths.history, &record)?;
        history.entry(id.clone()).or_default().push(record);
        report.signed.push(SignedPolicy {
            id: id.clone(),
            revision,
            why,
            blobs: spec.blobs.len(),
            desired_groups: spec.desired_groups,
            event: Some(verified.event_id),
            dry_run: false,
        });
    }

    for blob in blobs.values() {
        if blob.archived {
            report.ledger.archived += 1;
        } else {
            report.ledger.intake += 1;
        }
        if blob.lost {
            report.ledger.lost += 1;
        }
    }
    Ok(report)
}
