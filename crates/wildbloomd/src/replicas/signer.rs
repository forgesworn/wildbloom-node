use futures_util::future::BoxFuture;
use nostr::prelude::UnsignedEvent;
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::policy::MAX_EVENT_BYTES;

#[derive(Debug, thiserror::Error)]
#[error("local signer refused, exceeded its limits or was unavailable")]
pub struct SignerError;

pub trait Signer: Send + Sync {
    fn sign<'a>(
        &'a self,
        request: &'a UnsignedEvent,
    ) -> BoxFuture<'a, Result<Vec<u8>, SignerError>>;
}

pub struct CommandSigner {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub timeout: Duration,
}

impl Signer for CommandSigner {
    fn sign<'a>(
        &'a self,
        request: &'a UnsignedEvent,
    ) -> BoxFuture<'a, Result<Vec<u8>, SignerError>> {
        Box::pin(async move {
            if !self.executable.is_absolute() {
                return Err(SignerError);
            }
            let input = serde_json::to_vec(request).map_err(|_| SignerError)?;
            if input.len() > MAX_EVENT_BYTES {
                return Err(SignerError);
            }
            let mut child = tokio::process::Command::new(&self.executable)
                .args(&self.arguments)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| SignerError)?;
            let mut stdin = child.stdin.take().ok_or(SignerError)?;
            let stdout = child.stdout.take().ok_or(SignerError)?;
            // Concurrent bounded input/output also handles a helper which writes
            // before reading. One process is live at a time; no shell is involved.
            let exchange = async {
                let write = async {
                    stdin.write_all(&input).await.map_err(|_| SignerError)?;
                    stdin.shutdown().await.map_err(|_| SignerError)?;
                    drop(stdin);
                    Ok::<_, SignerError>(())
                };
                let read = async {
                    let mut bytes = Vec::new();
                    stdout
                        .take(MAX_EVENT_BYTES as u64 + 1)
                        .read_to_end(&mut bytes)
                        .await
                        .map_err(|_| SignerError)?;
                    if bytes.len() > MAX_EVENT_BYTES {
                        return Err(SignerError);
                    }
                    Ok::<_, SignerError>(bytes)
                };
                let (_, bytes) = tokio::try_join!(write, read)?;
                if !child.wait().await.map_err(|_| SignerError)?.success() {
                    return Err(SignerError);
                }
                Ok(bytes)
            };
            match tokio::time::timeout(self.timeout, exchange).await {
                Ok(Ok(bytes)) => Ok(bytes),
                _ => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    Err(SignerError)
                }
            }
        })
    }
}
