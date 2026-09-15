//! Maintain every signed policy in one directory from one process.
//!
//! A single-policy coordinator exits when its policy stops or fails. That
//! suits one operator-managed policy, but enrolment creates new policy ids
//! over time (a new leading hash character, a chunk split) and stops others.
//! This runner rescans a directory for `signed-<id>.json`, keeps one state
//! directory (and its lock) per id under a state root, runs each policy on
//! its own interval, and isolates failures: an invalid, expired or locked
//! policy is reported and retried with backoff while every other policy keeps
//! running. A stopped policy is not re-run until its signed event changes.
//!
//! Each pass is the same bounded, sequential pass the single-policy
//! coordinator runs; nothing about authorisation, verification or repair
//! differs.

use serde::Serialize;
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use super::{
    Error,
    engine::{self, Clock, Guard, Limits},
    policy::{self, VerifiedPolicy},
    signer::Signer,
    state::{StateDirectory, StateError},
    transport::{DisabledTransport, Transport},
};

pub const RESCAN_SECS: u64 = 30;
const ERROR_BACKOFF_BASE_SECS: u64 = 60;
const ERROR_BACKOFF_MAX_SECS: u64 = 1800;

pub type TransportFactory<'a> =
    dyn Fn(&VerifiedPolicy) -> Result<Box<dyn Transport>, &'static str> + Send + Sync + 'a;

pub struct Settings<'a> {
    pub policy_dir: PathBuf,
    pub state_root: PathBuf,
    pub owner: String,
    pub limits: Limits,
    pub default_interval: u64,
    /// Longest matching policy-id prefix wins.
    pub intervals: Vec<(String, u64)>,
    pub transport: &'a TransportFactory<'a>,
}

impl Settings<'_> {
    fn interval_for(&self, id: &str) -> u64 {
        self.intervals
            .iter()
            .filter(|(prefix, _)| id.starts_with(prefix.as_str()))
            .max_by_key(|(prefix, _)| prefix.len())
            .map_or(self.default_interval, |(_, secs)| *secs)
    }
}

/// Parse `PREFIX=SECONDS`.
pub fn parse_interval(value: &str) -> Result<(String, u64), String> {
    let (prefix, secs) = value
        .split_once('=')
        .ok_or_else(|| "expected PREFIX=SECONDS".to_owned())?;
    if prefix.is_empty()
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err("prefix must be lowercase letters, digits, - or _".into());
    }
    let secs: u64 = secs
        .parse()
        .map_err(|_| "seconds must be a whole number".to_owned())?;
    if !(5..=86400).contains(&secs) {
        return Err("seconds must be between 5 and 86400".into());
    }
    Ok((prefix.to_owned(), secs))
}

struct Entry {
    state: StateDirectory,
    next_due: u64,
    stopped_event: Option<String>,
    failures: u32,
}

#[derive(Serialize)]
struct ErrorLine<'a> {
    policy_id: &'a str,
    error: String,
}

#[derive(Default)]
pub struct Cycle {
    pub passes: usize,
    pub failures: usize,
}

pub struct Runner<'a> {
    settings: Settings<'a>,
    entries: BTreeMap<String, Entry>,
    blocked: BTreeMap<String, (u64, u32)>,
}

fn policy_files(dir: &Path) -> Result<BTreeMap<String, PathBuf>, Error> {
    let mut files = BTreeMap::new();
    for entry in std::fs::read_dir(dir).map_err(|_| StateError::Io)? {
        let entry = entry.map_err(|_| StateError::Io)?;
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|name| name.strip_prefix("signed-"))
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        if policy::identifier(id) {
            files.insert(id.to_owned(), entry.path());
        }
    }
    Ok(files)
}

fn backoff(failures: u32) -> u64 {
    ERROR_BACKOFF_BASE_SECS
        .saturating_mul(2_u64.saturating_pow(failures.saturating_sub(1)))
        .min(ERROR_BACKOFF_MAX_SECS)
}

impl<'a> Runner<'a> {
    pub fn new(settings: Settings<'a>) -> Result<Self, Error> {
        super::state::private_directory(&settings.state_root)?;
        Ok(Self {
            settings,
            entries: BTreeMap::new(),
            blocked: BTreeMap::new(),
        })
    }

    fn report_error(
        out: &mut dyn Write,
        id: &str,
        error: &dyn std::fmt::Display,
    ) -> Result<(), Error> {
        let line = serde_json::to_string(&ErrorLine {
            policy_id: id,
            error: error.to_string(),
        })?;
        writeln!(out, "{line}").map_err(|_| StateError::Io)?;
        Ok(())
    }

    /// Run every policy that is due at `clock.now()`. With `all`, run every
    /// policy present regardless of its schedule (for `--once`).
    pub async fn cycle(
        &mut self,
        clock: &dyn Clock,
        signer: Option<&dyn Signer>,
        out: &mut dyn Write,
        all: bool,
    ) -> Result<Cycle, Error> {
        let mut cycle = Cycle::default();
        let files = policy_files(&self.settings.policy_dir)?;
        let now = clock.now();
        for id in files.keys() {
            if self.entries.contains_key(id) {
                continue;
            }
            if let Some((retry_at, _)) = self.blocked.get(id)
                && *retry_at > now
                && !all
            {
                continue;
            }
            match StateDirectory::open(&self.settings.state_root.join(id)) {
                Ok(state) => {
                    self.blocked.remove(id);
                    self.entries.insert(
                        id.clone(),
                        Entry {
                            state,
                            next_due: now,
                            stopped_event: None,
                            failures: 0,
                        },
                    );
                }
                Err(error) => {
                    let failures = self.blocked.get(id).map_or(0, |(_, f)| *f) + 1;
                    self.blocked
                        .insert(id.clone(), (now + backoff(failures), failures));
                    Self::report_error(out, id, &error)?;
                    cycle.failures += 1;
                }
            }
        }

        let ids: Vec<String> = self.entries.keys().cloned().collect();
        for id in ids {
            let Some(path) = files.get(&id) else {
                // The file is gone. Keep the lock and state; do nothing.
                continue;
            };
            let now = clock.now();
            let entry = self.entries.get_mut(&id).ok_or(Error::Internal)?;
            if !all && entry.next_due > now {
                continue;
            }
            let interval = self.settings.interval_for(&id);
            let loaded = engine::load_policy(path, &self.settings.owner, now).and_then(|policy| {
                if policy.policy.id == id {
                    Ok(policy)
                } else {
                    Err(Error::Configuration(
                        "policy id does not match its file name",
                    ))
                }
            });
            let policy = match loaded {
                Ok(policy) => policy,
                Err(error) => {
                    entry.failures += 1;
                    entry.next_due = now + backoff(entry.failures);
                    entry.stopped_event = None;
                    let _ = entry.state.invalidate();
                    Self::report_error(out, &id, &error)?;
                    cycle.failures += 1;
                    continue;
                }
            };
            if entry.stopped_event.as_deref() == Some(policy.event_id.as_str()) && !all {
                entry.next_due = now + interval;
                continue;
            }
            let transport: Box<dyn Transport> = if policy.policy.desired_groups == 0 {
                Box::new(DisabledTransport)
            } else {
                match (self.settings.transport)(&policy) {
                    Ok(transport) => transport,
                    Err(message) => {
                        entry.failures += 1;
                        entry.next_due = now + backoff(entry.failures);
                        Self::report_error(out, &id, &message)?;
                        cycle.failures += 1;
                        continue;
                    }
                }
            };
            let guard = Guard {
                path,
                expected: &policy,
                clock,
            };
            let limits = self.settings.limits;
            let result = async {
                limits.validate(&policy)?;
                engine::run_pass(&guard, &mut entry.state, transport.as_ref(), signer, limits).await
            }
            .await;
            match result {
                Ok(report) => {
                    entry.failures = 0;
                    entry.stopped_event = report.stopped.then(|| policy.event_id.clone());
                    entry.next_due = clock.now() + interval;
                    let line = serde_json::to_string(&report)?;
                    writeln!(out, "{line}").map_err(|_| StateError::Io)?;
                    cycle.passes += 1;
                }
                Err(error) => {
                    entry.failures += 1;
                    entry.next_due = clock.now() + backoff(entry.failures);
                    entry.stopped_event = None;
                    Self::report_error(out, &id, &error)?;
                    cycle.failures += 1;
                }
            }
        }
        Ok(cycle)
    }

    /// Seconds until the next policy is due, bounded by the rescan period, or
    /// zero when a returned authorisation or an expired request is waiting.
    pub fn sleep_for(&self, clock: &dyn Clock) -> u64 {
        let now = clock.now();
        let mut wait = RESCAN_SECS;
        for entry in self.entries.values() {
            wait = wait.min(entry.next_due.saturating_sub(now));
            if let Some(snapshot) = &entry.state.snapshot
                && snapshot.pending.values().any(|pending| {
                    pending.requested_at.saturating_add(120) <= now
                        || std::fs::symlink_metadata(
                            entry.state.pending_path(&pending.event_id, true),
                        )
                        .is_ok()
                })
            {
                return 0;
            }
        }
        wait
    }

    pub fn wake_pending(&mut self, clock: &dyn Clock) {
        let now = clock.now();
        for entry in self.entries.values_mut() {
            if let Some(snapshot) = &entry.state.snapshot
                && snapshot.pending.values().any(|pending| {
                    pending.requested_at.saturating_add(120) <= now
                        || std::fs::symlink_metadata(
                            entry.state.pending_path(&pending.event_id, true),
                        )
                        .is_ok()
                })
            {
                entry.next_due = now;
            }
        }
    }
}

pub async fn run(
    settings: Settings<'_>,
    clock: &dyn Clock,
    signer: Option<&dyn Signer>,
    once: bool,
) -> Result<(), Error> {
    let mut runner = Runner::new(settings)?;
    let mut stdout = std::io::stdout();
    if once {
        let cycle = runner.cycle(clock, signer, &mut stdout, true).await?;
        stdout.flush().map_err(|_| StateError::Io)?;
        if cycle.failures > 0 {
            return Err(Error::Enrol(format!(
                "{} of {} policies failed",
                cycle.failures,
                cycle.failures + cycle.passes
            )));
        }
        return Ok(());
    }
    loop {
        runner.cycle(clock, signer, &mut stdout, false).await?;
        stdout.flush().map_err(|_| StateError::Io)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(runner.sleep_for(clock));
        loop {
            if tokio::time::Instant::now() >= deadline || runner.sleep_for(clock) == 0 {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                _ = tokio::signal::ctrl_c() => return Ok(()),
            }
        }
        runner.wake_pending(clock);
    }
}
