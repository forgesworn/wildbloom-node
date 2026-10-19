//! The IPC payloads in `desktop/ui/DROP-IPC.md`, field for field.  Every
//! struct serialises camelCase.  None of them carries a secret, except
//! [`RecoveryKeyDisplay`] (shown once) and the link and words in
//! [`ShareState`], which only the sheet that asked for them receives.

use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlatformInfo {
    pub os: &'static str,
    pub desktop: String,
    pub computer_name: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FirstRun {
    pub step: &'static str,
    pub node_settings_exist: bool,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OnlineStatus {
    pub configured: bool,
    pub url: String,
    pub host: String,
    pub reachable: bool,
    pub failed_checks: u32,
    pub used_bytes: u64,
    pub limit_bytes: u64,
    pub full: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalSummary {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_npub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_npub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStatus {
    /// `"ok"`, or `"failed"` when the key list could not be opened or sealed
    /// (files are kept; the recovery key cannot restore new ones until it is
    /// sealed again).
    pub key_list: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_at: Option<u64>,
    pub confirmed: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WatchFolderStatus {
    pub enabled: bool,
    pub path: String,
    /// `off`, `on`, `unavailable` (the folder or its marker can't be found)
    /// or `too_many` (a scan hit the item limit).
    pub state: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LimitsStatus {
    pub drop_max_bytes: u64,
    pub share_max_bytes: u64,
}

/// What happens to a shared copy once its recipient confirms the download,
/// and how long a sent copy stays otherwise.  Read when a file is sent.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharingSettings {
    /// `delete` (the default) or `keep`.
    pub after_download: &'static str,
    /// 3600, 86400 (the default) or 604800.
    pub expiry_seconds: u64,
}

/// `DropStatus` without `files`: the `drop://status` payload.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DropStatus {
    pub first_run: Option<FirstRun>,
    pub node: &'static str,
    pub keychain: &'static str,
    pub online: OnlineStatus,
    pub approval: ApprovalSummary,
    pub recovery: RecoveryStatus,
    pub watch_folder: WatchFolderStatus,
    pub limits: LimitsStatus,
    pub sharing: SharingSettings,
    pub browser_approval: bool,
}

/// `drop_status`'s answer: the status plus every row.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DropSnapshot {
    #[serde(flatten)]
    pub status: DropStatus,
    pub files: Vec<FileRow>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FileRow {
    pub id: String,
    pub name: String,
    pub bytes: u64,
    pub added: u64,
    pub state: &'static str,
    pub progress: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sharing_ended: Option<u64>,
    /// When the recipient confirmed the download: on `shared` (the copy is
    /// kept), `sharing_ended` (deleted) and `stop_pending` (being deleted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downloaded_at: Option<u64>,
    /// Why a `not_kept` row is not kept: `too_big`, `name`, `too_long` or
    /// `too_deep`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_kept: Option<&'static str>,
    /// The parent path relative to the Wildbloom folder, if not the root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// Linked to a file in the Wildbloom folder.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub in_watch_folder: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RemovedRow {
    pub id: String,
    pub removed: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Refused {
    pub name: String,
    pub reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Duplicate {
    pub name: String,
    pub id: String,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AddResult {
    pub added: Vec<String>,
    pub refused: Vec<Refused>,
    pub duplicates: Vec<Duplicate>,
}

/// `resolve_held_removals`'s answer: how many held rows it acted on.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HeldResolved {
    pub count: u32,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SavedCopy {
    pub folder: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NodeCheck {
    pub ok: bool,
    pub host: String,
    pub used_bytes: u64,
    pub limit_bytes: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalStatus {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_npub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_npub: Option<String>,
    pub device_npub: String,
    pub limit_bytes: u64,
    pub until: u64,
}

/// The recovery key, ungrouped, for display once.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKeyDisplay {
    pub key: String,
}

impl Drop for RecoveryKeyDisplay {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SavedRecoveryFile {
    pub filename: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RestoreResult {
    pub next: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// One share sheet state.  `link` and `words` are what the owner sends and
/// reads out; they never go anywhere but the sheet.  `Debug` hides them.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ShareState {
    pub id: String,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub words: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_words: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tries_left: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_at: Option<u64>,
    /// `sent`: whether a download confirmation can still arrive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub awaiting_download: Option<bool>,
    /// `sent`: `delete` or `keep`, the policy this share was sent with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_download: Option<&'static str>,
    /// `downloaded`: when the recipient confirmed it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downloaded_at: Option<u64>,
    /// `downloaded`: `deleted`, `deleting` (queued until the online node
    /// answers) or `kept` (until `delete_at`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copy: Option<&'static str>,
}

impl ShareState {
    pub fn new(id: &str, state: &'static str) -> Self {
        Self {
            id: id.to_owned(),
            state,
            progress: None,
            link: None,
            words: None,
            check_words: None,
            expires_at: None,
            tries_left: None,
            delete_at: None,
            awaiting_download: None,
            after_download: None,
            downloaded_at: None,
            copy: None,
        }
    }
}

impl std::fmt::Debug for ShareState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareState")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("progress", &self.progress)
            .field("expires_at", &self.expires_at)
            .field("awaiting_download", &self.awaiting_download)
            .field("copy", &self.copy)
            .finish_non_exhaustive()
    }
}

impl Drop for ShareState {
    fn drop(&mut self) {
        if let Some(link) = self.link.as_mut() {
            zeroize::Zeroize::zeroize(link);
        }
        for word in self.words.iter_mut().flatten() {
            zeroize::Zeroize::zeroize(word);
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Notice {
    pub kind: &'static str,
}

/// `drop://open-flow`: the node window asked the Drop window to open a flow.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenFlow {
    pub flow: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DragInfo {
    pub files: u32,
    pub folders: u32,
    pub too_big: u32,
}

/// A command rejection: `{ code, message?, host?, detail?, ownerNpub? }`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_npub: Option<String>,
}

impl CommandError {
    pub fn code(code: &'static str) -> Self {
        Self {
            code,
            message: None,
            host: None,
            detail: None,
            owner_npub: None,
        }
    }

    pub fn with_message(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
            ..Self::code(code)
        }
    }

    pub fn with_host(code: &'static str, host: impl Into<String>) -> Self {
        Self {
            host: Some(host.into()),
            ..Self::code(code)
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)?;
        if let Some(message) = &self.message {
            write!(f, ": {message}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CommandError {}

pub type CommandResult<T> = Result<T, CommandError>;
