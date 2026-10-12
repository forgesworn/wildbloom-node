//! Serial, bounded publication. Persist the exact signed watermark before relay I/O.
use super::{
    Announcement, Error, Services,
    contract::{self, Description},
    now, relay,
};
use crate::replicas::{
    signer::{CommandSigner, Signer},
    state,
};
use nostr::prelude::Event;
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::oneshot;
use url::Url;

pub struct Journal {
    root: PathBuf,
    _lock: File,
    pub last: Option<Event>,
}
impl Journal {
    pub fn open(root: &Path, services: &Services) -> Result<Self, Error> {
        state::private_directory(root).map_err(|_| Error)?;
        let resolved = std::fs::canonicalize(root).map_err(|_| Error)?;
        let store_root = std::fs::canonicalize(services.store.config().root).map_err(|_| Error)?;
        if resolved.starts_with(store_root) {
            return Err(Error);
        }
        let lock_path = root.join("publisher.lock");
        if let Ok(metadata) = std::fs::symlink_metadata(&lock_path)
            && !metadata.is_file()
        {
            return Err(Error);
        }
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path).map_err(|_| Error)?;
        wildbloom_private_state::check_file(&lock).map_err(|_| Error)?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| Error)?;
        let path = root.join("last-event.json");
        let last = match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let bytes = wildbloom_checkout::read_private_file(&path).map_err(|_| Error)?;
                let raw: Event = serde_json::from_slice(&bytes).map_err(|_| Error)?;
                // Validate the signature/contract even if the clock rolled backwards.
                let (event, d) = contract::parse_event(&bytes, raw.created_at.as_secs())?;
                if d.service_pubkey != services.profile.service_pubkey
                    || d.identifier != services.profile.identifier
                {
                    return Err(Error);
                }
                Some(event)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(Error),
        };
        Ok(Self {
            root: root.to_owned(),
            _lock: lock,
            last,
        })
    }
    pub fn save(&mut self, event: Event) -> Result<(), Error> {
        if self
            .last
            .as_ref()
            .is_some_and(|e| event.created_at <= e.created_at)
        {
            return Err(Error);
        }
        state::write_private(
            &self.root,
            "last-event.json",
            &serde_json::to_vec(&event).map_err(|_| Error)?,
        )
        .map_err(|_| Error)?;
        self.last = Some(event);
        Ok(())
    }
}
fn fingerprint(mut description: Description) -> Result<String, Error> {
    // Timestamps alone do not cause a capacity-change announcement.
    description.observed_at = 0;
    description.expires_at = 1;
    serde_json::to_string(&description).map_err(|_| Error)
}
fn due(last_attempt: Option<u64>, changed: bool, failed: bool, now: u64, heartbeat: u64) -> bool {
    match last_attempt {
        None => true,
        Some(last) => now >= last && now - last >= if changed || failed { 300 } else { heartbeat },
    }
}
async fn signed(
    services: &Services,
    journal: &mut Journal,
    signer: &dyn Signer,
    withdraw: bool,
) -> Result<Event, Error> {
    let at = now()?;
    if journal
        .last
        .as_ref()
        .is_some_and(|e| e.created_at.as_secs() >= at)
    {
        return Err(Error);
    }
    let services = services.clone();
    let description = tokio::task::spawn_blocking(move || services.snapshot(at, withdraw))
        .await
        .map_err(|_| Error)??;
    let template = description.template(at)?;
    let bytes = signer.sign(&template).await.map_err(|_| Error)?;
    let event = contract::accept_signature(&bytes, &template, now()?)?;
    journal.save(event.clone())?;
    Ok(event)
}
async fn deliver(a: &Announcement, proxy: Option<&Url>, event: &Event) -> Result<usize, Error> {
    let results = futures_util::future::join_all(
        a.relays
            .iter()
            .map(|d| relay::publish(d, a.transport, proxy, event)),
    )
    .await;
    let acknowledgements = results.iter().filter(|result| result.is_ok()).count();
    tracing::info!(
        acknowledgements,
        configured_relays = a.relays.len(),
        "public service publication completed"
    );
    if acknowledgements == 0 {
        Err(Error)
    } else {
        Ok(acknowledgements)
    }
}
pub struct Publisher {
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}
impl Publisher {
    pub fn start(services: Services, a: Announcement, proxy: Option<Url>) -> Result<Self, Error> {
        let signer = std::sync::Arc::new(CommandSigner {
            executable: a.signer.clone(),
            arguments: a.signer_args.clone(),
            timeout: Duration::from_secs(10),
        });
        Self::start_with_signer(services, a, proxy, signer)
    }
    fn start_with_signer(
        services: Services,
        a: Announcement,
        proxy: Option<Url>,
        signer: std::sync::Arc<dyn Signer>,
    ) -> Result<Self, Error> {
        let mut journal = Journal::open(&a.state_dir, &services)?;
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            // Restarting must not bypass the five-minute publication limit.
            let mut last_attempt = journal.last.as_ref().map(|e| e.created_at.as_secs());
            let mut last_fingerprint = None;
            let mut failed = false;
            loop {
                let work = async {
                    let at = now()?;
                    let s = services.clone();
                    let description = tokio::task::spawn_blocking(move || s.snapshot(at, false))
                        .await
                        .map_err(|_| Error)??;
                    let current = fingerprint(description)?;
                    let changed = last_fingerprint.as_ref() != Some(&current);
                    if due(last_attempt, changed, failed, at, a.heartbeat_seconds) {
                        last_attempt = Some(at);
                        let event = signed(&services, &mut journal, signer.as_ref(), false).await?;
                        last_fingerprint = Some(current);
                        deliver(&a, proxy.as_ref(), &event).await?;
                        failed = false;
                    }
                    Ok::<_, Error>(())
                };
                tokio::select! {
                    _ = &mut stopped => break,
                    result = work => if result.is_err() { failed = true; tracing::warn!("public service publication failed; existing announcements expire at their signed deadline"); },
                }
                tokio::select! {
                    _ = &mut stopped => break,
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {},
                }
            }
            // Withdraw with a strictly newer timestamp. If signing or a relay fails,
            // the previous bounded expiration remains the final fallback.
            if journal
                .last
                .as_ref()
                .is_some_and(|e| e.created_at.as_secs() == now().unwrap_or(0))
            {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            let result = async {
                let event = signed(&services, &mut journal, signer.as_ref(), true).await?;
                deliver(&a, proxy.as_ref(), &event).await?;
                Ok::<_, Error>(())
            }
            .await;
            if result.is_err() {
                tracing::warn!(
                    "public service withdrawal failed; previous announcement will expire"
                );
            }
        });
        Ok(Self { stop, task })
    }
    pub async fn stop(self) {
        let _ = self.stop.send(());
        // Signer 10s + relays 15s + clock boundary 1s. A hard bound also catches
        // unexpected worker delays without holding Tor shutdown indefinitely.
        let mut task = self.task;
        if tokio::time::timeout(Duration::from_secs(30), &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt, future::BoxFuture};
    use nostr::prelude::{FinalizeEvent, Keys, UnsignedEvent};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct TestSigner;
    impl Signer for TestSigner {
        fn sign<'a>(
            &'a self,
            request: &'a UnsignedEvent,
        ) -> BoxFuture<'a, Result<Vec<u8>, crate::replicas::signer::SignerError>> {
            Box::pin(async move {
                Ok(serde_json::to_vec(
                    &request
                        .clone()
                        .finalize(&Keys::parse(&hex::encode([1; 32])).unwrap())
                        .unwrap(),
                )
                .unwrap())
            })
        }
    }

    #[tokio::test]
    async fn publisher_persists_before_delivery_and_withdraws_on_shutdown() {
        let root = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Url::parse(&format!("socks5h://{}", listener.local_addr().unwrap())).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/storage-v1/free-onion.json"
        ))
        .unwrap();
        let host = Url::parse(fixture["description"]["origins"][0].as_str().unwrap())
            .unwrap()
            .host_str()
            .unwrap()
            .to_owned();
        let a = Announcement {
            signer: root.path().join("test-signer"),
            signer_args: vec![],
            state_dir: root.path().join("publisher"),
            transport: relay::Transport::TorOnly,
            relays: vec![relay::Destination {
                url: format!("ws://{host}/"),
                addresses: vec![],
            }],
            heartbeat_seconds: 1800,
            ttl_seconds: 7200,
        };
        let persisted = a.state_dir.join("last-event.json");
        let (seen, mut events) = tokio::sync::mpsc::channel(2);
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut header = [0; 5];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(&header[..4], &[5, 1, 0, 3]);
                let mut domain = vec![0; header[4] as usize];
                stream.read_exact(&mut domain).await.unwrap();
                assert_eq!(domain, host.as_bytes());
                assert_eq!(stream.read_u16().await.unwrap(), 80);
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                    .await
                    .unwrap();
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                let value: serde_json::Value =
                    serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap())
                        .unwrap();
                let event: Event = serde_json::from_value(value[1].clone()).unwrap();
                event.verify().unwrap();
                let disk: Event =
                    serde_json::from_slice(&std::fs::read(&persisted).unwrap()).unwrap();
                assert_eq!(disk.id, event.id);
                ws.send(tokio_tungstenite::tungstenite::Message::Text(
                    serde_json::json!(["OK", event.id.to_hex(), true, ""])
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
                seen.send(event).await.unwrap();
                let _ = ws.close(None).await;
            }
        });
        let store = wildbloom_core::Store::open(wildbloom_core::StoreConfig {
            root: root.path().join("storage"),
            quota_bytes: 1000,
            max_blob_bytes: 1000,
        })
        .unwrap();
        let services = Services::new(
            super::super::Profile {
                service_pubkey: Keys::parse(&hex::encode([1; 32]))
                    .unwrap()
                    .public_key()
                    .to_hex(),
                identifier: "test-storage".into(),
                name: "Synthetic service".into(),
                about: "Synthetic lifecycle test".into(),
                origins: vec!["https://storage.example/".into()],
                browser_origins: vec!["https://app.example".into()],
                withdrawn: false,
                announcement: Some(a.clone()),
            },
            store,
            None,
            "https://storage.example/",
            true,
            true,
            &[],
            Some(&proxy),
            true,
        )
        .unwrap();
        let publisher =
            Publisher::start_with_signer(services, a, Some(proxy), std::sync::Arc::new(TestSigner))
                .unwrap();
        let initial = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .unwrap();
        publisher.stop().await;
        let withdrawn = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(withdrawn.created_at > initial.created_at);
        let (_, description) =
            contract::parse_event(&serde_json::to_vec(&withdrawn).unwrap(), now().unwrap())
                .unwrap();
        assert_eq!(description.state, contract::ListingState::Withdrawn);
        assert!(
            description
                .services
                .iter()
                .all(|s| s.availability() == contract::Availability::Paused)
        );
        server.await.unwrap();
    }
    #[test]
    fn updates_and_failures_are_rate_limited_and_heartbeats_have_a_deadline() {
        assert!(due(None, false, false, 1000, 1800));
        assert!(!due(Some(1000), true, false, 1299, 1800));
        assert!(due(Some(1000), true, false, 1300, 1800));
        assert!(due(Some(1000), false, true, 1300, 1800));
        assert!(!due(Some(1000), false, false, 2799, 1800));
        assert!(due(Some(1000), false, false, 2800, 1800));
        assert!(!due(Some(1000), true, true, 999, 1800));
    }
}
