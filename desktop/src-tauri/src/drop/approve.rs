//! Device approval (design question Q1, Q3): one NIP-46 session asks the
//! owner's signer for its public key and one signature over the kind 27540
//! grant event, then disconnects.  The desktop posts the signed event to the
//! online node itself.
//!
//! The bunker link is a connection secret: it is parsed here, handed to
//! nostr-connect and never stored, logged or echoed.

use super::client::{self, GrantError};
use super::engine::{APPROVAL_SECONDS, DEFAULT_GRANT_BYTES, Engine, internal, kv, now, npub};
use super::types::{ApprovalStatus, CommandError, CommandResult};
use nostr::prelude::{
    EventBuilder, FinalizeUnsignedEvent as _, Kind, PublicKey, Tag, Timestamp, UnsignedEvent,
};
use nostr_connect::prelude::{NostrConnect, NostrConnectUri};
use std::sync::Arc;
use std::time::Duration;

/// The grant event kind (an experimental Wildbloom profile, not a NIP).
pub const DEVICE_GRANT_KIND: u16 = 27_540;
/// The node accepts the event for at most ten minutes after `created_at`.
const GRANT_EVENT_LIFETIME: u64 = 600;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Phase {
    #[default]
    Idle,
    Waiting,
    Approved {
        by: String,
    },
    Failed {
        code: &'static str,
        detail: Option<String>,
        owner: Option<String>,
    },
    RestoreFailed {
        code: &'static str,
    },
}

#[derive(Default)]
pub(crate) struct ApprovalRuntime {
    pub phase: Phase,
    pub task: Option<tokio::task::JoinHandle<()>>,
    /// Bumped on every start and cancel, so a stale task cannot report.
    pub generation: u64,
    /// The terms the next grant will carry.
    pub planned: Option<(u64, u64)>,
}

/// The unsigned grant the owner is asked to sign.
pub fn grant_event(
    owner: PublicKey,
    device: &str,
    recovery: &str,
    bytes: u64,
    until: u64,
    server: &str,
    created_at: u64,
) -> UnsignedEvent {
    let tag = |parts: [&str; 2]| Tag::parse(parts).expect("static tag shapes are valid");
    let bytes = bytes.to_string();
    let until = until.to_string();
    let expiration = (created_at + GRANT_EVENT_LIFETIME).to_string();
    EventBuilder::new(
        Kind::Custom(DEVICE_GRANT_KIND),
        "Approve this computer to keep Wildbloom Drop copies on your online node.",
    )
    .tags([
        tag(["t", "grant"]),
        tag(["device", device]),
        tag(["recovery", recovery]),
        tag(["bytes", &bytes]),
        tag(["until", &until]),
        tag(["server", server]),
        tag(["expiration", &expiration]),
    ])
    .custom_created_at(Timestamp::from(created_at))
    .finalize_unsigned(owner)
}

/// Whether nostr-connect reported a timeout (rather than a refusal).
fn is_timeout(error: &nostr_connect::error::Error) -> bool {
    error.to_string().to_ascii_lowercase().contains("timeout")
}

impl Engine {
    fn planned_terms(&self) -> (u64, u64) {
        let quota = self.online_rt.lock().ok().and_then(|rt| rt.quota);
        (
            quota.unwrap_or(DEFAULT_GRANT_BYTES),
            now() + APPROVAL_SECONDS,
        )
    }

    pub fn approval_status(&self) -> CommandResult<ApprovalStatus> {
        let identity = self.identity()?;
        let runtime = self.approval.lock().map_err(|_| internal("lock"))?;
        let (limit, until) = runtime.planned.unwrap_or_else(|| self.planned_terms());
        let mut status = ApprovalStatus {
            state: "idle",
            code: None,
            detail: None,
            owner_npub: None,
            by_npub: None,
            device_npub: npub(&identity.device.public_key_hex()),
            limit_bytes: limit,
            until,
        };
        match &runtime.phase {
            Phase::Idle => {}
            Phase::Waiting => status.state = "waiting",
            Phase::Approved { by } => {
                status.state = "approved";
                status.by_npub = Some(npub(by));
            }
            Phase::Failed {
                code,
                detail,
                owner,
            } => {
                status.state = "failed";
                status.code = Some(code);
                status.detail = detail.clone();
                status.owner_npub = owner.as_deref().map(npub);
            }
            Phase::RestoreFailed { code } => {
                status.state = "restore_failed";
                status.code = Some(code);
            }
        }
        Ok(status)
    }

    /// Starts one approval.  `browser` (the NIP-07 page) does not exist yet.
    pub fn approve_device(
        self: &Arc<Self>,
        bunker_url: Option<&str>,
        browser: bool,
    ) -> CommandResult<()> {
        if browser {
            return Err(CommandError::with_message(
                "unavailable",
                "Approving in the browser isn't available yet.",
            ));
        }
        let link = bunker_url.unwrap_or_default().trim();
        if !link.to_ascii_lowercase().starts_with("bunker://") {
            return Err(CommandError::code("bad_link"));
        }
        let uri = NostrConnectUri::parse(link).map_err(|_| CommandError::code("bad_link"))?;
        if !matches!(uri, NostrConnectUri::Bunker { .. }) {
            return Err(CommandError::code("bad_link"));
        }
        let node = self.online_endpoint().ok_or(CommandError::with_message(
            "refused",
            "No online node is set up.",
        ))?;
        let identity = self.identity()?;
        let terms = self.planned_terms();
        let mut runtime = self.approval.lock().map_err(|_| internal("lock"))?;
        if let Some(task) = runtime.task.take() {
            task.abort();
        }
        runtime.generation += 1;
        runtime.phase = Phase::Waiting;
        runtime.planned = Some(terms);
        let generation = runtime.generation;
        let engine = self.clone();
        let device = identity.device.public_key_hex();
        let recovery = identity.recovery.identity().public_key_hex();
        runtime.task = Some(self.rt.spawn(async move {
            let phase = engine
                .run_approval(uri, &node, &device, &recovery, terms)
                .await;
            engine.finish_approval(generation, phase).await;
        }));
        Ok(())
    }

    pub fn cancel_approval(&self) -> CommandResult<()> {
        let mut runtime = self.approval.lock().map_err(|_| internal("lock"))?;
        runtime.generation += 1;
        if let Some(task) = runtime.task.take() {
            // Dropping the task drops the NIP-46 client and its relay pool.
            task.abort();
        }
        runtime.phase = Phase::Idle;
        Ok(())
    }

    async fn run_approval(
        &self,
        uri: NostrConnectUri,
        node: &client::NodeEndpoint,
        device: &str,
        recovery: &str,
        (bytes, until): (u64, u64),
    ) -> Phase {
        use nostr::prelude::{AsyncGetPublicKey as _, AsyncSignEvent as _, Keys};
        let failed = |code: &'static str| Phase::Failed {
            code,
            detail: None,
            owner: None,
        };
        // A fresh client key per session: nothing about this connection is kept.
        let connect = match NostrConnect::new(uri, Keys::generate(), self.cfg.signer_timeout, None)
        {
            Ok(connect) => connect,
            Err(_) => return failed("refused"),
        };
        let signed = async {
            let owner = connect.get_public_key_async().await?;
            let unsigned = grant_event(owner, device, recovery, bytes, until, node.server(), now());
            let expected = unsigned.clone();
            let signed = connect.sign_event_async(unsigned).await?;
            Ok::<_, nostr_connect::error::Error>((owner, expected, signed))
        };
        // The whole exchange is bounded, even if a relay never answers.
        let outcome =
            tokio::time::timeout(self.cfg.signer_timeout + Duration::from_secs(10), signed).await;
        connect.shutdown().await;
        let (owner, expected, signed) = match outcome {
            Err(_) => return failed("timeout"),
            Ok(Err(error)) if is_timeout(&error) => return failed("timeout"),
            Ok(Err(_)) => return failed("declined"),
            Ok(Ok(result)) => result,
        };
        // The signer must have signed exactly what was asked, as the owner.
        if signed.verify().is_err()
            || signed.pubkey != owner
            || signed.kind != expected.kind
            || signed.tags != expected.tags
            || signed.content != expected.content
            || signed.created_at != expected.created_at
        {
            return failed("declined");
        }
        let owner_hex = owner.to_hex();
        match client::post_grant(&self.http, node, &signed.as_json()).await {
            Ok(status) if status.state == "active" && status.device == device => {
                let _ = self.index.set(kv::APPROVAL_BY, &owner_hex);
                let _ = self
                    .index
                    .set_u64(kv::APPROVAL_UNTIL, status.until.unwrap_or(until));
                let _ = self
                    .index
                    .set_u64(kv::APPROVAL_LIMIT, status.bytes.unwrap_or(bytes));
                let _ = self.index.set_bool(kv::APPROVAL_REVOKED, false);
                Phase::Approved { by: owner_hex }
            }
            Ok(_) => Phase::Failed {
                code: "refused",
                detail: Some("the approval is not active".into()),
                owner: None,
            },
            Err(GrantError::Unreachable) => failed("offline"),
            Err(GrantError::NotOwner { .. }) => Phase::Failed {
                code: "wrong_owner",
                detail: None,
                owner: Some(owner_hex),
            },
            Err(GrantError::Refused { reason, status }) => Phase::Failed {
                code: "refused",
                detail: Some(reason.unwrap_or_else(|| format!("HTTP {status}"))),
                owner: None,
            },
            Err(GrantError::Invalid) => Phase::Failed {
                code: "refused",
                detail: Some("an unexpected answer".into()),
                owner: None,
            },
        }
    }

    async fn finish_approval(self: &Arc<Self>, generation: u64, phase: Phase) {
        let approved = matches!(phase, Phase::Approved { .. });
        let restoring = approved && self.index.get_bool(kv::RESTORE_PENDING).unwrap_or(false);
        // A restore keeps the UI waiting until the key list has been read.
        let shown = if restoring {
            Phase::Waiting
        } else {
            phase.clone()
        };
        if !self.set_phase(generation, shown) {
            return;
        }
        if !approved {
            return;
        }
        let first = !self.index.get_bool(kv::FIRST_RUN_DONE).unwrap_or(false);
        if restoring {
            let outcome = self.restore_after_approval().await;
            let next = match outcome {
                Ok(()) => phase,
                Err(code) => Phase::RestoreFailed { code },
            };
            self.set_phase(generation, next);
        } else if first {
            let _ = self.index.set(kv::FIRST_RUN_STEP, "recovery");
        }
        self.emit_status();
        self.wake.notify_one();
        self.keysync_wake.notify_one();
    }

    fn set_phase(&self, generation: u64, phase: Phase) -> bool {
        let Ok(mut runtime) = self.approval.lock() else {
            return false;
        };
        if runtime.generation != generation {
            return false;
        }
        runtime.phase = phase;
        true
    }

    /// Refreshes the approval from the node (start-up and the 6-hourly check).
    pub(crate) async fn refresh_grant(&self) {
        let (Some(node), Ok(identity)) = (self.online_endpoint(), self.identity()) else {
            return;
        };
        if self.index.get(kv::APPROVAL_BY).ok().flatten().is_none() {
            return;
        }
        match client::grant_status(&self.http, &node, identity.device.keys()).await {
            Ok(Some(status)) => {
                if let Some(until) = status.until {
                    let _ = self.index.set_u64(kv::APPROVAL_UNTIL, until);
                }
                let _ = self
                    .index
                    .set_bool(kv::APPROVAL_REVOKED, status.state != "active");
            }
            Ok(None) => {
                let _ = self.index.set_bool(kv::APPROVAL_REVOKED, true);
            }
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::{FinalizeEvent as _, Keys};

    #[test]
    fn the_grant_event_matches_the_node_profile() {
        let owner = Keys::generate();
        let event = grant_event(
            owner.public_key(),
            &"aa".repeat(32),
            &"bb".repeat(32),
            5_000_000_000,
            1_900_000_000,
            "storage.example",
            1_800_000_000,
        )
        .finalize(&owner)
        .unwrap();
        assert_eq!(event.kind, Kind::Custom(27_540));
        let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
        let names: Vec<&str> = tags.iter().map(|t| t[0].as_str()).collect();
        assert_eq!(
            names,
            [
                "t",
                "device",
                "recovery",
                "bytes",
                "until",
                "server",
                "expiration"
            ]
        );
        assert!(tags.iter().all(|t| t.len() == 2));
        assert!(tags.contains(&vec!["expiration".into(), "1800000600".into()]));
        assert!(tags.contains(&vec!["bytes".into(), "5000000000".into()]));
        assert!(event.content.len() <= 512);
    }
}
