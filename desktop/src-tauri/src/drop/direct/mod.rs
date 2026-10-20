//! Direct send, Drop's receiving end ("Receive a file"; `docs/PROTOCOL.md`,
//! "Direct send (experimental)", profile `wildbloom-direct/1`).  A person's
//! browser sends one file straight to Drop over a WebRTC data channel that is
//! set up inside a word-verified Foregather live channel.  Nothing about the
//! file rests on any server.
//!
//! - [`messages`]: the strict canonical message codec.
//! - [`frames`]: the data-channel frames, as the webview reads them.
//! - [`sink`]: the private temp file, verification at END and keeping.
//! - [`received`]: the Received folder and "Add to Wildbloom".
//! - [`awake`]: no idle sleep during a transfer.

pub mod awake;
pub mod frames;
pub mod messages;
pub mod received;
pub mod sink;

/// The live session's purpose; the namespace is Drop's `wildbloom.drop`.
pub const PURPOSE: &str = "send";
