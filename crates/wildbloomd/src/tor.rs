use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    fs,
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    sync::oneshot,
    time::timeout,
};

#[derive(Debug, Error)]
pub enum TorError {
    #[error("Tor can expose only a loopback Wildbloom listener")]
    NonLoopbackTarget,
    #[error("failed to prepare private Tor state: {0}")]
    State(#[from] std::io::Error),
    #[error("Tor did not become ready within {0} seconds")]
    Timeout(u64),
    #[error("Tor stopped before the onion service was ready")]
    Exited,
    #[error("Tor produced an invalid onion hostname")]
    InvalidHostname,
    #[error("Tor did not report its private SOCKS listener")]
    MissingSocksListener,
}

pub struct TorService {
    child: Child,
    hostname: String,
    socks_address: SocketAddr,
}

impl TorService {
    pub async fn start(
        binary: &Path,
        state_root: &Path,
        target: SocketAddr,
        readiness_timeout: Duration,
    ) -> Result<Self, TorError> {
        if !target.ip().is_loopback() {
            return Err(TorError::NonLoopbackTarget);
        }
        let state_root = absolute_private_dir(state_root).await?;
        let data_dir = state_root.join("client");
        let service_dir = state_root.join("onion-service");
        create_private_dir(&data_dir).await?;
        create_private_dir(&service_dir).await?;
        let torrc = state_root.join("torrc");
        fs::write(
            &torrc,
            b"# This Tor instance is managed by Wildbloom Node.\n",
        )
        .await?;
        set_private_permissions(&torrc, false).await?;

        let target = match target {
            SocketAddr::V4(address) => address.to_string(),
            SocketAddr::V6(address) => format!("[{}]:{}", address.ip(), address.port()),
        };
        let mut command = Command::new(binary);
        command
            .arg("-f")
            .arg(&torrc)
            .arg("--DataDirectory")
            .arg(&data_dir)
            .arg("--SocksPort")
            .arg("auto")
            .arg("--ORPort")
            .arg("0")
            .arg("--ExitRelay")
            .arg("0")
            .arg("--ExitPolicy")
            .arg("reject *:*")
            .arg("--PublishServerDescriptor")
            .arg("0")
            .arg("--HiddenServiceDir")
            .arg(&service_dir)
            .arg("--HiddenServiceVersion")
            .arg("3")
            .arg("--HiddenServicePort")
            .arg(format!("80 {target}"))
            .arg("--Log")
            .arg("notice stdout")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        configure_no_window(&mut command);

        let mut child = command.spawn()?;
        let stdout = child.stdout.take().ok_or(TorError::Exited)?;
        let stderr = child.stderr.take().ok_or(TorError::Exited)?;
        let (ready_sender, ready_receiver) = oneshot::channel();
        let socks_address = Arc::new(Mutex::new(None));
        tokio::spawn(drain_tor_output(
            stdout,
            Some(ready_sender),
            Arc::clone(&socks_address),
        ));
        tokio::spawn(drain_tor_output(stderr, None, Arc::clone(&socks_address)));

        match timeout(readiness_timeout, ready_receiver).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                let _ = child.kill().await;
                return Err(TorError::Exited);
            }
            Err(_) => {
                let _ = child.kill().await;
                return Err(TorError::Timeout(readiness_timeout.as_secs()));
            }
        }

        let hostname = fs::read_to_string(service_dir.join("hostname")).await?;
        let hostname = hostname.trim().to_ascii_lowercase();
        if !valid_v3_onion(&hostname) {
            let _ = child.kill().await;
            return Err(TorError::InvalidHostname);
        }
        let socks_address = socks_address
            .lock()
            .ok()
            .and_then(|address| *address)
            .ok_or(TorError::MissingSocksListener)?;
        if !socks_address.ip().is_loopback() {
            let _ = child.kill().await;
            return Err(TorError::MissingSocksListener);
        }
        tracing::info!(onion = %hostname, socks = %socks_address, "Tor onion service is ready");
        Ok(Self {
            child,
            hostname,
            socks_address,
        })
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn socks_address(&self) -> SocketAddr {
        self.socks_address
    }

    pub async fn shutdown(mut self) {
        if let Err(error) = self.child.kill().await
            && error.kind() != std::io::ErrorKind::InvalidInput
        {
            tracing::warn!(reason = %error, "failed to stop managed Tor process");
        }
        let _ = self.child.wait().await;
    }
}

async fn drain_tor_output<R>(
    reader: R,
    mut ready: Option<oneshot::Sender<()>>,
    socks_address: Arc<Mutex<Option<SocketAddr>>>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        const SOCKS_MARKER: &str = "Opened Socks listener connection (ready) on ";
        if let Some(address) = line
            .split_once(SOCKS_MARKER)
            .and_then(|(_, address)| address.parse::<SocketAddr>().ok())
            && address.ip().is_loopback()
            && let Ok(mut current) = socks_address.lock()
        {
            *current = Some(address);
        }
        if line.contains("Bootstrapped 100%")
            && let Some(sender) = ready.take()
        {
            let _ = sender.send(());
        }
        tracing::debug!(message = %line, "Tor");
    }
}

fn valid_v3_onion(hostname: &str) -> bool {
    let Some(service_id) = hostname.strip_suffix(".onion") else {
        return false;
    };
    service_id.len() == 56
        && service_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
}

async fn absolute_private_dir(path: &Path) -> Result<PathBuf, TorError> {
    create_private_dir(path).await?;
    Ok(fs::canonicalize(path).await?)
}

async fn create_private_dir(path: &Path) -> Result<(), TorError> {
    fs::create_dir_all(path).await?;
    set_private_permissions(path, true).await?;
    Ok(())
}

async fn set_private_permissions(path: &Path, directory: bool) -> Result<(), TorError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if directory { 0o700 } else { 0o600 };
        fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
    }
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

#[cfg(windows)]
fn configure_no_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn configure_no_window(_command: &mut Command) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_only_v3_onion_hostnames() {
        assert!(valid_v3_onion(&format!("{}.onion", "a".repeat(56))));
        assert!(valid_v3_onion(&format!("{}.onion", "2".repeat(56))));
        assert!(!valid_v3_onion(&format!("{}.onion", "1".repeat(56))));
        assert!(!valid_v3_onion(&format!("{}.onion", "a".repeat(16))));
        assert!(!valid_v3_onion(&format!("{}.example", "a".repeat(56))));
    }
}
