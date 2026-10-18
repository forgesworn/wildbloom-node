//! Online copies: the device key uploads each envelope to the online node
//! (BUD-11), with progress, back-off retries (1 min, 5 min, 30 min, then every
//! 30 min or when the node comes back), reachability checks, 6-hourly HEAD
//! checks of every copy on both nodes and the queued BUD-12 deletions.

use super::client::{self, NodeError};
use super::engine::{Engine, kv, now};
use super::index::{local, online};
use std::sync::Arc;
use std::time::Duration;

/// Back-off after the n-th failure.
pub fn backoff(attempts: u32) -> u64 {
    match attempts {
        0 => 0,
        1 => 60,
        2 => 5 * 60,
        _ => 30 * 60,
    }
}

const CHECK_EVERY: u64 = 6 * 60 * 60;
const HEALTH_EVERY: Duration = Duration::from_secs(120);

impl Engine {
    pub(crate) fn spawn_workers(self: &Arc<Self>) {
        let engine = self.clone();
        self.rt.spawn(async move { engine.mirror_loop().await });
        let engine = self.clone();
        self.rt.spawn(async move { engine.health_loop().await });
        let engine = self.clone();
        self.rt.spawn(async move { engine.keysync_loop().await });
        let engine = self.clone();
        self.rt.spawn(async move { engine.watch_loop().await });
        let engine = self.clone();
        self.rt.spawn(async move { engine.deletes_loop().await });
    }

    /// Queued deletions and the 24-hour share deletions run on their own
    /// timer, so a long upload never holds them up.
    async fn deletes_loop(self: Arc<Self>) {
        loop {
            self.run_pending_deletes().await;
            self.sweep_shares().await;
            tokio::select! {
                _ = self.deletes_wake.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            }
        }
    }

    async fn mirror_loop(self: Arc<Self>) {
        // Start-up: settle the approval and copies before the first pass.
        self.refresh_grant().await;
        self.recover_open_shares().await;
        loop {
            self.mirror_pass().await;
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        }
    }

    async fn health_loop(self: Arc<Self>) {
        loop {
            self.check_online().await;
            tokio::time::sleep(HEALTH_EVERY).await;
        }
    }

    /// Publishes this computer's changes when woken, and pulls the other
    /// computers' changes on a timer and when woken.  A pull never seals or
    /// uploads unless this computer holds something the online copies lack.
    async fn keysync_loop(self: Arc<Self>) {
        let mut pull_timer =
            tokio::time::interval(self.cfg.pull_interval.max(Duration::from_millis(100)));
        pull_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = self.keysync_wake.notified() => {
                    // Let a burst of drops settle into one seal.
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if self.index.get_bool(kv::FIRST_RUN_DONE).unwrap_or(false)
                        || self.index.get_bool(kv::RESTORE_PENDING).unwrap_or(false)
                    {
                        self.sync_key_list_reporting().await;
                    } else if self.identity().is_ok() {
                        // Not yet set up: seal what there is, locally at least.
                        self.sync_key_list_reporting().await;
                    }
                }
                _ = self.pull_wake.notified() => self.pull_key_list_reporting().await,
                _ = pull_timer.tick() => self.pull_key_list_reporting().await,
            }
        }
    }

    /// One reachability check of the online node.
    pub(crate) async fn check_online(&self) {
        let Some(node) = self.online_endpoint() else {
            return;
        };
        let result = client::health(&self.http, &node).await;
        let recovered = {
            let Ok(mut rt) = self.online_rt.lock() else {
                return;
            };
            match result {
                Ok(health) => {
                    let recovered = rt.failed_checks > 0 || !rt.reachable;
                    rt.reachable = true;
                    rt.failed_checks = 0;
                    rt.quota = Some(health.quota_bytes);
                    recovered
                }
                Err(_) => {
                    rt.reachable = false;
                    rt.failed_checks = rt.failed_checks.saturating_add(1);
                    false
                }
            }
        };
        if recovered {
            if self.index.get_bool(kv::KEY_LIST_PENDING).unwrap_or(false) {
                self.keysync_wake.notify_one();
            }
            self.pull_wake.notify_one();
            // "then on network change": a node that comes back is retried now.
            if let Ok(files) = self.index.files() {
                for file in files {
                    if matches!(file.online.as_str(), online::WAITING | online::FAILED) {
                        let _ = self.index.set_online(&file.id, online::QUEUED);
                        let _ = self.index.set_backoff(&file.id, 0, 0);
                    }
                }
            }
            self.wake.notify_one();
        }
        self.emit_status();
    }

    async fn mirror_pass(self: &Arc<Self>) {
        let Ok(files) = self.index.files() else {
            return;
        };
        // Envelopes waiting for the local node.
        for file in files.iter().filter(|f| f.local == local::PENDING) {
            self.upload_local(&file.id).await;
        }
        let now = now();
        let writable = self.writable_online();
        for file in self.index.files().unwrap_or_default() {
            if file.local == local::UNREADABLE
                || file.local == local::ENCRYPTING
                || file.sha256.is_none()
            {
                continue;
            }
            let due = match file.online.as_str() {
                online::QUEUED | online::WAITING => true,
                online::FAILED => file.next_attempt <= now,
                _ => false,
            };
            if !due {
                continue;
            }
            if writable.is_none() {
                if file.online != online::WAITING && self.online_endpoint().is_some() {
                    let _ = self.index.set_online(&file.id, online::WAITING);
                    self.emit_row(&file.id);
                }
                continue;
            }
            self.upload_online(&file.id).await;
        }
        self.deletes_wake.notify_one();
        let reachable = self
            .online_rt
            .lock()
            .map(|rt| rt.reachable)
            .unwrap_or(false);
        if self.index.get_bool(kv::KEY_LIST_PENDING).unwrap_or(false)
            && self.local_endpoint().is_some()
            && (reachable || self.online_endpoint().is_none())
        {
            self.keysync_wake.notify_one();
        }
        let last = self
            .index
            .get_u64(kv::LAST_CHECK)
            .ok()
            .flatten()
            .unwrap_or(0);
        if now.saturating_sub(last) >= CHECK_EVERY {
            let _ = self.index.set_u64(kv::LAST_CHECK, now);
            self.refresh_grant().await;
            self.check_copies().await;
        }
        self.emit_status();
    }

    /// Uploads one envelope to the online node with the device key, then
    /// confirms the stored size with a HEAD.
    pub(crate) async fn upload_online(self: &Arc<Self>, id: &str) {
        let Ok(Some(file)) = self.index.file(id) else {
            return;
        };
        let (Some(sha), Some(size)) = (file.sha256.clone(), file.size) else {
            return;
        };
        let (Some(node), Ok(identity)) = (self.writable_online(), self.identity()) else {
            return;
        };
        let _ = self.index.set_online(id, online::COPYING);
        self.set_progress(id, 0);
        let engine = self.clone();
        let progress_id = id.to_owned();
        let progress = move |sent: u64| {
            let percent = 99u64.min(sent.saturating_mul(100) / size.max(1)) as u8;
            engine.set_progress(&progress_id, percent);
        };
        let body = if file.local == local::OK
            && let Some(local_node) = self.local_endpoint()
        {
            client::relay_body(&self.http, &local_node, &sha, size, progress).await
        } else {
            client::file_body(&self.outbox_path(id), progress).await
        };
        let result = match body {
            Ok(body) => {
                client::upload(&self.http, &node, identity.device.keys(), &sha, size, body).await
            }
            Err(error) => Err(error),
        };
        let result = match result {
            Ok(()) => match client::head(&self.http, &node, &sha).await {
                Ok(Some(stored)) if stored == size => Ok(()),
                Ok(_) => Err(NodeError::Mismatch),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        self.clear_progress(id);
        match result {
            Ok(()) => {
                let _ = self.index.set_online(id, online::OK);
                let _ = self.index.add_online_copy(id, node.origin());
                let _ = self.index.set_backoff(id, 0, 0);
                if let Ok(mut rt) = self.online_rt.lock() {
                    rt.full = false;
                }
            }
            Err(NodeError::Full) => {
                let _ = self.index.set_online(id, online::FULL);
                if let Ok(mut rt) = self.online_rt.lock() {
                    rt.full = true;
                }
            }
            Err(NodeError::Unreachable) => {
                let _ = self.index.set_online(id, online::WAITING);
                if let Ok(mut rt) = self.online_rt.lock() {
                    rt.reachable = false;
                }
            }
            Err(NodeError::Unauthorised) => {
                // The grant may have ended; re-read it before trying again.
                let _ = self.index.set_online(id, online::WAITING);
                self.refresh_grant().await;
            }
            Err(_) => {
                let attempts = file.attempts.saturating_add(1);
                let _ = self.index.set_online(id, online::FAILED);
                let _ = self
                    .index
                    .set_backoff(id, attempts, now() + backoff(attempts));
            }
        }
        self.emit_row(id);
        self.emit_status();
    }

    /// HEAD every copy on both nodes: a 404 or wrong size marks it missing.
    pub(crate) async fn check_copies(self: &Arc<Self>) {
        let local_node = self.local_endpoint();
        let online_node = self.online_endpoint();
        for file in self.index.files().unwrap_or_default() {
            let (Some(sha), Some(size)) = (file.sha256.clone(), file.size) else {
                continue;
            };
            if file.online == online::OK
                && let Some(node) = &online_node
            {
                match client::head(&self.http, node, &sha).await {
                    Ok(Some(stored)) if stored == size => {}
                    Ok(_) => {
                        let _ = self.index.set_online(&file.id, online::MISSING);
                        self.emit_row(&file.id);
                    }
                    Err(_) => {}
                }
            }
            if file.local == local::OK
                && let Some(node) = &local_node
            {
                match client::head(&self.http, node, &sha).await {
                    Ok(Some(stored)) if stored == size => {}
                    Ok(_) => {
                        let _ = self.index.set_local(&file.id, local::MISSING);
                        self.emit_row(&file.id);
                    }
                    Err(_) => {}
                }
            }
        }
    }

    /// Runs the checks now (tests and "Try now").
    pub async fn check_copies_now(self: &Arc<Self>) {
        self.check_copies().await;
        self.emit_status();
    }
}

#[cfg(test)]
mod tests {
    use super::backoff;

    #[test]
    fn backoff_follows_the_spec() {
        assert_eq!([1, 2, 3, 9].map(backoff), [60, 300, 1800, 1800]);
    }
}
