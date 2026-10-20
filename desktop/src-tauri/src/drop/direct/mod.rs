//! Direct send, Drop's receiving end ("Receive a file"; `docs/PROTOCOL.md`,
//! "Direct send (experimental)", profile `wildbloom-direct/1`).  A person's
//! browser sends one file straight to Drop over a WebRTC data channel that is
//! set up inside a word-verified Foregather live channel.  Nothing about the
//! file rests on any server.
//!
//! Rust owns the transfer: the pairing, the check words, the exchange
//! messages, the TURN credentials, the envelope key, the sink and the disk.
//! A hidden webview window, created and destroyed by Rust per transfer, runs
//! `RTCPeerConnection` and the frame logic with the web project's TypeScript;
//! it receives SDP and ICE servers and hands the envelope bytes back.  The
//! visible sheet in the Drop window only shows states and sends the owner's
//! choices, so closing the Drop window never ends a transfer.  The contract
//! is in `desktop/ui/DROP-IPC.md`, "Receiving".
//!
//! - [`messages`]: the strict canonical message codec.
//! - [`frames`]: the data-channel frames, as the webview reads them.
//! - [`session`]: the session itself, independent of Tauri.
//! - [`sink`]: the private temp file, verification at END and keeping.
//! - [`received`]: the Received folder and "Add to Wildbloom".
//! - [`receive`]: the engine's commands around them.
//! - [`awake`]: no idle sleep during a transfer.
//!
//! Secrets: the link and words go only to the Drop window; the page's TURN
//! credential (`peer`) goes only into `invite`; Drop's own (`own`) only to the
//! hidden window's `create`; the envelope key never leaves Rust.  None of
//! them is logged.

pub mod awake;
pub mod frames;
pub mod messages;
pub mod receive;
pub mod received;
pub mod session;
pub mod sink;

use messages::IceServer;
use serde::{Deserialize, Serialize};

/// The live session's purpose; the namespace is Drop's `wildbloom.drop`.
pub const PURPOSE: &str = "send";
/// The hidden window's label and page.
pub const PEER_WINDOW: &str = "direct";
pub const PEER_PAGE: &str = "direct.html";

/// The receive sheet's state: the `receive://state` payload and what the
/// receive commands return.  `link` and `words` go only to the Drop window;
/// `Debug` hides them.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiveState {
    /// `idle`, `preparing`, `waiting`, `opened`, `check`, `waiting_file`,
    /// `consent`, `connecting`, `receiving`, `verifying`, `kept`,
    /// `declined`, `cancelled` or `failed`.
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub words: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_words: Option<Vec<String>>,
    /// The file's name as the sender gave it (`kept`: the name it was kept
    /// under, which may carry a number).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// `connecting`, `receiving`: Drop's address is hidden behind the relay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    /// `receiving`: envelope bytes acknowledged to the sender, and E.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// `connecting`, `receiving`: the connection dropped and Drop is getting
    /// it back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconnecting: Option<bool>,
    /// `kept`: the handle for `receive_add_to_wildbloom` and `receive_reveal`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `kept`: where the file is, for display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `kept`: the Received folder, for display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// `kept`: whether "Add to Wildbloom" can run now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_add: Option<bool>,
    /// `cancelled`: `you` or `them`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<&'static str>,
    /// `failed`: why, as a code the UI phrases.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

impl ReceiveState {
    pub fn new(state: &'static str) -> Self {
        Self {
            state,
            link: None,
            words: None,
            expires_at: None,
            check_words: None,
            name: None,
            size: None,
            media_type: None,
            hidden: None,
            acknowledged: None,
            total: None,
            reconnecting: None,
            id: None,
            path: None,
            folder: None,
            can_add: None,
            by: None,
            reason: None,
        }
    }

    pub fn failed(reason: &'static str) -> Self {
        let mut failed = Self::new("failed");
        failed.reason = Some(reason);
        failed
    }

    /// Whether this state ends the sheet's transfer.
    pub fn is_final(&self) -> bool {
        matches!(
            self.state,
            "kept" | "declined" | "cancelled" | "failed" | "idle"
        )
    }
}

impl std::fmt::Debug for ReceiveState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiveState")
            .field("state", &self.state)
            .field("size", &self.size)
            .field("acknowledged", &self.acknowledged)
            .field("total", &self.total)
            .field("reconnecting", &self.reconnecting)
            .field("by", &self.by)
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl Drop for ReceiveState {
    fn drop(&mut self) {
        if let Some(link) = self.link.as_mut() {
            zeroize::Zeroize::zeroize(link);
        }
        for word in self.words.iter_mut().flatten() {
            zeroize::Zeroize::zeroize(word);
        }
    }
}

/// A request to the hidden window, sent over the channel it attached with
/// `direct_peer_attach`.  Every request has the transfer's `id` and a `seq`
/// its reply repeats.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerRequest {
    pub transfer: String,
    pub seq: u64,
    #[serde(flatten)]
    pub op: PeerOp,
}

impl std::fmt::Debug for PeerRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let op = match &self.op {
            PeerOp::Create { .. } => "create",
            PeerOp::Offer => "offer",
            PeerOp::Restart => "restart",
            PeerOp::Answer { .. } => "answer",
            PeerOp::Close { .. } => "close",
        };
        f.debug_struct("PeerRequest")
            .field("seq", &self.seq)
            .field("op", &op)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum PeerOp {
    /// Make the one `RTCPeerConnection` and its negotiated data channel from
    /// exactly these servers (Drop's own credential).  `relayOnly` hides
    /// Drop's address: relay candidates only and no STUN.  Reply `done`.
    #[serde(rename_all = "camelCase")]
    Create {
        ice_servers: Vec<IceServer>,
        relay_only: bool,
        /// E, and the file's size: what `receiveEnvelope` needs.
        envelope_bytes: u64,
        size: u64,
    },
    /// Make the offer.  Reply `offer` with the SDP once gathering completes
    /// or three seconds after it starts.
    Offer,
    /// Make an ICE restart offer on the same connection.  Reply `offer`.
    Restart,
    /// Apply the page's answer (or restart answer).  Reply `done`.
    Answer { sdp: String },
    /// End: when `stop` is set and the transfer is still running, send STOP
    /// with that reason first; wait at most a second for the send buffer to
    /// drain; close the connection.  Reply `done`.  Rust then destroys the
    /// window.
    Close { stop: Option<u8> },
}

/// The connection's state, as `RTCPeerConnection.connectionState` gives it.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    New,
    Connecting,
    Connected,
    Disconnected,
    Failed,
    Closed,
}

/// What the hidden window tells Rust, through `direct_peer_report`.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PeerReport {
    /// The page has loaded and attached its request channel.
    Ready,
    /// The request `seq` succeeded.
    Done { transfer: String, seq: u64 },
    /// The offer (or restart offer) for request `seq`.
    Offer {
        transfer: String,
        seq: u64,
        sdp: String,
    },
    /// The request `seq` failed: `no-relay` when hiding left no TURN URL,
    /// anything else for a failure of the connection or the page.
    Error {
        transfer: String,
        seq: u64,
        reason: String,
    },
    /// The connection's state changed.
    State { transfer: String, state: PeerState },
    /// The data channel opened.
    Channel { transfer: String },
    /// The frame logic ended: `kept` once KEPT has been sent, otherwise the
    /// `TransferError` kind (`cancelled`, `peer-cancelled`, `peer-failed`,
    /// `peer-storage`, `protocol`, `closed`, `verification`, `storage`).
    Ended { transfer: String, outcome: String },
}

impl PeerReport {
    /// The transfer it is about; `None` for `ready`.
    pub fn transfer(&self) -> Option<&str> {
        match self {
            Self::Ready => None,
            Self::Done { transfer, .. }
            | Self::Offer { transfer, .. }
            | Self::Error { transfer, .. }
            | Self::State { transfer, .. }
            | Self::Channel { transfer }
            | Self::Ended { transfer, .. } => Some(transfer),
        }
    }
}

impl std::fmt::Debug for PeerReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready => f.write_str("Ready"),
            Self::Done { seq, .. } => write!(f, "Done({seq})"),
            Self::Offer { seq, .. } => write!(f, "Offer({seq})"),
            Self::Error { seq, .. } => write!(f, "Error({seq})"),
            Self::State { state, .. } => write!(f, "State({state:?})"),
            Self::Channel { .. } => f.write_str("Channel"),
            Self::Ended { outcome, .. } => write!(f, "Ended({outcome})"),
        }
    }
}

/// What the sink tells the session.
#[derive(Debug)]
pub enum SinkEvent {
    /// The webview's ACK rule just acknowledged this many envelope bytes.
    Progress { acked: u64 },
    /// END arrived and the checks are running.
    Verifying,
    /// Verified and kept.
    Kept(sink::Kept),
    /// Refused; the webview sends STOP with the error's code.
    Failed(sink::SinkError),
}

/// `receive_add_to_wildbloom`'s answer: the name the file took in the
/// Wildbloom folder, and the folder for display.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AddedToWildbloom {
    pub name: String,
    pub folder: String,
}

/// The receiving settings (`receive_hide_address`).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceivingSettings {
    /// Relay-only ICE for Drop's own connection (the default).
    pub hide_address: bool,
    /// The Received folder, for display.
    pub folder: String,
    /// The largest file Drop accepts.
    pub max_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_serialise_as_the_contract_says() {
        let ice = IceServer {
            credential: "c".into(),
            urls: vec!["turn:turn.example.net:3478".into()],
            username: "u".into(),
        };
        let create = PeerRequest {
            transfer: "AAECAwQFBgcICQoLDA0ODw".into(),
            seq: 1,
            op: PeerOp::Create {
                ice_servers: vec![ice],
                relay_only: true,
                envelope_bytes: 65_608,
                size: 43,
            },
        };
        assert_eq!(
            serde_json::to_value(&create).unwrap(),
            serde_json::json!({
                "transfer": "AAECAwQFBgcICQoLDA0ODw", "seq": 1, "op": "create",
                "iceServers": [{ "credential": "c", "urls": ["turn:turn.example.net:3478"], "username": "u" }],
                "relayOnly": true, "envelopeBytes": 65_608, "size": 43
            })
        );
        assert!(!format!("{create:?}").contains("\"c\""));
        for (op, json) in [
            (PeerOp::Offer, serde_json::json!({ "op": "offer" })),
            (PeerOp::Restart, serde_json::json!({ "op": "restart" })),
            (
                PeerOp::Answer { sdp: "v=0".into() },
                serde_json::json!({ "op": "answer", "sdp": "v=0" }),
            ),
            (
                PeerOp::Close { stop: Some(1) },
                serde_json::json!({ "op": "close", "stop": 1 }),
            ),
            (
                PeerOp::Close { stop: None },
                serde_json::json!({ "op": "close", "stop": null }),
            ),
        ] {
            let mut expected = json;
            expected["transfer"] = "t".into();
            expected["seq"] = 2.into();
            let request = PeerRequest {
                transfer: "t".into(),
                seq: 2,
                op,
            };
            assert_eq!(serde_json::to_value(&request).unwrap(), expected);
        }
    }

    #[test]
    fn reports_read_as_the_contract_says() {
        let read = |json: serde_json::Value| serde_json::from_value::<PeerReport>(json);
        assert_eq!(
            read(serde_json::json!({ "kind": "ready" })).unwrap(),
            PeerReport::Ready
        );
        assert_eq!(
            read(serde_json::json!({ "kind": "offer", "transfer": "t", "seq": 3, "sdp": "v=0" }))
                .unwrap(),
            PeerReport::Offer {
                transfer: "t".into(),
                seq: 3,
                sdp: "v=0".into()
            }
        );
        assert_eq!(
            read(serde_json::json!({ "kind": "state", "transfer": "t", "state": "disconnected" }))
                .unwrap(),
            PeerReport::State {
                transfer: "t".into(),
                state: PeerState::Disconnected
            }
        );
        assert_eq!(
            read(serde_json::json!({ "kind": "ended", "transfer": "t", "outcome": "kept" }))
                .unwrap()
                .transfer(),
            Some("t")
        );
        assert!(
            read(serde_json::json!({ "kind": "state", "transfer": "t", "state": "odd" })).is_err()
        );
        assert!(read(serde_json::json!({ "kind": "nope" })).is_err());
    }

    #[test]
    fn states_hide_the_link_and_words_from_debug() {
        let mut state = ReceiveState::new("waiting");
        state.link = Some("https://example.invalid/send/#secret".into());
        state.words = Some(vec!["alpha".into()]);
        let shown = format!("{state:?}");
        assert!(!shown.contains("secret") && !shown.contains("alpha"));
        assert_eq!(
            serde_json::to_value(ReceiveState::failed("lost")).unwrap(),
            serde_json::json!({ "state": "failed", "reason": "lost" })
        );
    }
}
