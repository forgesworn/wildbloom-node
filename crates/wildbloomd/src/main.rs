use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, str::FromStr};
use tracing_subscriber::EnvFilter;
use url::Url;
use wildbloom_core::{
    AppState, BlossomConfig, FriendGrant, ServerMetadata, Store, StoreConfig, router,
};

mod tor;

use tor::TorService;

#[derive(Debug, Clone)]
struct FriendGrantArg(FriendGrant);

impl FromStr for FriendGrantArg {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts = value.split(':').collect::<Vec<_>>();
        let [pubkey, byte_limit, expires_at] = parts.as_slice() else {
            return Err("expected PUBKEY:BYTE_LIMIT:EXPIRES_AT".to_owned());
        };
        let byte_limit = byte_limit
            .parse::<u64>()
            .map_err(|_| "friend byte limit must be an unsigned integer".to_owned())?;
        let expires_at = expires_at
            .parse::<u64>()
            .map_err(|_| "friend expiry must be a Unix timestamp".to_owned())?;
        Ok(Self(FriendGrant {
            pubkey: (*pubkey).to_owned(),
            byte_limit,
            expires_at,
            grant_id: format!("local:{pubkey}:{expires_at}"),
        }))
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "wildbloomd",
    version,
    about = "A secure, self-hosted Blossom storage node"
)]
struct Cli {
    /// Address used by the local HTTP service.
    #[arg(long, env = "WILDBLOOM_BIND", default_value = "127.0.0.1:3742")]
    bind: SocketAddr,

    /// Permit binding to a non-loopback interface.
    #[arg(long, env = "WILDBLOOM_ALLOW_PUBLIC_BIND")]
    allow_public_bind: bool,

    /// Persistent data directory.
    #[arg(long, env = "WILDBLOOM_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Total bytes available for stored blobs.
    #[arg(
        long,
        env = "WILDBLOOM_QUOTA_BYTES",
        default_value_t = 10 * 1024 * 1024 * 1024_u64
    )]
    quota_bytes: u64,

    /// Maximum bytes accepted for one blob.
    #[arg(
        long,
        env = "WILDBLOOM_MAX_BLOB_BYTES",
        default_value_t = 1024 * 1024 * 1024_u64
    )]
    max_blob_bytes: u64,

    /// Public origin placed in Blossom blob descriptors.
    #[arg(long, env = "WILDBLOOM_PUBLIC_URL")]
    public_url: Option<Url>,

    /// Exact value accepted in BUD-11 server tags (repeatable).
    #[arg(long = "server-name", env = "WILDBLOOM_SERVER_NAME")]
    server_names: Vec<String>,

    /// Owner Nostr public key allowed to upload, mirror and delete (repeatable).
    #[arg(
        long = "allow-pubkey",
        env = "WILDBLOOM_ALLOW_PUBKEYS",
        value_delimiter = ','
    )]
    allowed_pubkeys: Vec<String>,

    /// Expiring friend grant as PUBKEY:BYTE_LIMIT:EXPIRES_AT (repeatable).
    #[arg(
        long = "friend-grant",
        env = "WILDBLOOM_FRIEND_GRANTS",
        value_delimiter = ','
    )]
    friend_grants: Vec<FriendGrantArg>,

    /// Accept signed BUD-04 mirrors from unknown keys as evictable guest data.
    /// Direct unknown uploads remain denied.
    #[arg(long, env = "WILDBLOOM_OPEN_SHELTER")]
    open_shelter: bool,

    /// Maximum simultaneous upload and mirror streams.
    #[arg(long, env = "WILDBLOOM_MAX_CONCURRENT_WRITES", default_value_t = 4)]
    max_concurrent_writes: usize,

    /// Verify every stored blob and exit without starting the network service.
    #[arg(long, env = "WILDBLOOM_VERIFY_STORAGE")]
    verify_storage: bool,

    /// Run only on the local HTTP listener instead of starting Tor.
    #[arg(long, env = "WILDBLOOM_NO_TOR")]
    no_tor: bool,

    /// Loopback socks5h proxy supplied by a desktop shell when --no-tor is set.
    #[arg(long, env = "WILDBLOOM_MIRROR_PROXY", requires = "no_tor")]
    mirror_proxy: Option<Url>,

    /// Tor executable used for the managed onion service.
    #[arg(long, env = "WILDBLOOM_TOR_BIN", default_value = "tor")]
    tor_bin: PathBuf,

    /// Seconds allowed for Tor to bootstrap.
    #[arg(long, env = "WILDBLOOM_TOR_TIMEOUT", default_value_t = 900)]
    tor_timeout: u64,

    /// Seconds between complete integrity scans and repair attempts. Zero disables repair.
    #[arg(
        long,
        env = "WILDBLOOM_REPAIR_INTERVAL",
        default_value_t = 60 * 60_u64
    )]
    repair_interval: u64,

    /// Desktop parent whose termination must also stop this sidecar.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    parent_pid: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("wildbloom=info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    #[cfg(target_os = "linux")]
    configure_parent_death(cli.parent_pid)?;
    let data_dir = match cli.data_dir {
        Some(path) => path,
        None => default_data_dir()?,
    };
    if !cli.bind.ip().is_loopback() && !cli.allow_public_bind {
        return Err("refusing a non-loopback bind without --allow-public-bind".into());
    }
    let store = Store::open(StoreConfig {
        root: data_dir.clone(),
        quota_bytes: cli.quota_bytes,
        max_blob_bytes: cli.max_blob_bytes,
    })?;
    if cli.verify_storage {
        let report = store.verify_integrity()?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !report.missing.is_empty() || !report.corrupted.is_empty() {
            return Err("storage integrity verification failed".into());
        }
        return Ok(());
    }
    if cli.allowed_pubkeys.is_empty() && cli.friend_grants.is_empty() && !cli.open_shelter {
        tracing::warn!(
            "no owner, friend grant or open-shelter policy is configured; the node is read-only"
        );
    }
    let listener = tokio::net::TcpListener::bind(cli.bind).await?;
    let local_address = listener.local_addr()?;
    let tor = if cli.no_tor {
        None
    } else {
        if !local_address.ip().is_loopback() {
            return Err("managed Tor requires a loopback listener".into());
        }
        Some(
            TorService::start(
                &cli.tor_bin,
                &data_dir.join("tor"),
                local_address,
                std::time::Duration::from_secs(cli.tor_timeout),
            )
            .await?,
        )
    };
    let public_url = match (&tor, cli.public_url) {
        (Some(service), None) => Url::parse(&format!("http://{}/", service.hostname()))?,
        (Some(_), Some(_)) => {
            return Err("--public-url cannot override the managed Tor onion; use --no-tor".into());
        }
        (None, configured) => configured.unwrap_or_else(|| {
            Url::parse(&format!("http://localhost:{}", local_address.port()))
                .expect("local URL is valid")
        }),
    };
    validate_public_url(&public_url)?;
    let server_names = if cli.server_names.is_empty() {
        vec![url_server_name(&public_url)?]
    } else {
        cli.server_names
    };
    let mirror_proxy = tor
        .as_ref()
        .map(|service| {
            Url::parse(&format!("socks5h://{}", service.socks_address()))
                .expect("managed Tor SOCKS URL is valid")
        })
        .or(cli.mirror_proxy);
    let repair_enabled = mirror_proxy.is_some() && cli.repair_interval > 0;

    let state = AppState::new(
        store,
        BlossomConfig {
            server_metadata: ServerMetadata {
                name: "Wildbloom Node".into(),
                software: "https://github.com/forgesworn/wildbloom-node".into(),
            },
            public_base_url: public_url.clone(),
            accepted_server_names: server_names.clone(),
            allowed_pubkeys: cli.allowed_pubkeys,
            friend_grants: cli.friend_grants.into_iter().map(|grant| grant.0).collect(),
            open_shelter: cli.open_shelter,
            max_concurrent_writes: cli.max_concurrent_writes,
            mirror_proxy,
        },
    )?;
    tracing::info!(
        address = %local_address,
        public_url = %public_url,
        server_names = ?server_names,
        "Wildbloom Node is ready"
    );
    if repair_enabled {
        tokio::spawn(repair_loop(
            state.clone(),
            std::time::Duration::from_secs(cli.repair_interval),
        ));
    }
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    if let Some(tor) = tor {
        tor.shutdown().await;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_parent_death(parent_pid: Option<u32>) -> std::io::Result<()> {
    let Some(parent_pid) = parent_pid else {
        return Ok(());
    };

    // SAFETY: PR_SET_PDEATHSIG only updates this process's kernel metadata and
    // SIGTERM is a valid signal number. No pointer is passed to the kernel.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // The parent can exit between exec and prctl. In that case the kernel could
    // not deliver the signal retroactively, so fail closed after installing it.
    // SAFETY: getppid has no preconditions and returns the caller's parent PID.
    if unsafe { libc::getppid() } as u32 != parent_pid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "the requested desktop parent is no longer running",
        ));
    }
    Ok(())
}

async fn repair_loop(state: AppState, interval: std::time::Duration) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        match state.repair_once().await {
            Ok(report) if report.candidates == 0 => {
                tracing::debug!("storage integrity scan found no repair candidates");
            }
            Ok(report) => {
                tracing::info!(
                    candidates = report.candidates,
                    repaired = report.repaired,
                    unrepaired = report.unrepaired.len(),
                    "storage integrity scan completed"
                );
            }
            Err(error) => {
                tracing::error!(reason = %error, "storage integrity scan failed");
            }
        }
    }
}

fn validate_public_url(url: &Url) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("--public-url must be an HTTP(S) origin without credentials or a path".into());
    }
    Ok(())
}

fn url_server_name(url: &Url) -> Result<String, Box<dyn std::error::Error>> {
    Ok(url.host_str().ok_or("public URL has no host")?.to_owned())
}

fn default_data_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    directories::ProjectDirs::from("dev", "ForgeSworn", "Wildbloom Node")
        .map(|directories| directories.data_local_dir().to_owned())
        .ok_or_else(|| "this platform does not expose a per-user application data directory".into())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install terminate handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bud_server_scope_uses_the_hostname_without_the_port() {
        let url = Url::parse("http://localhost:3742/").unwrap();
        assert_eq!(url_server_name(&url).unwrap(), "localhost");
    }

    #[test]
    fn parses_expiring_friend_grants_and_open_shelter() {
        let pubkey = "a".repeat(64);
        let cli = Cli::try_parse_from([
            "wildbloomd",
            "--friend-grant",
            &format!("{pubkey}:1048576:2000000000"),
            "--open-shelter",
        ])
        .unwrap();
        assert!(cli.open_shelter);
        assert_eq!(cli.friend_grants.len(), 1);
        assert_eq!(cli.friend_grants[0].0.pubkey, pubkey);
        assert_eq!(cli.friend_grants[0].0.byte_limit, 1_048_576);
        assert_eq!(cli.friend_grants[0].0.expires_at, 2_000_000_000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_the_hidden_desktop_parent_contract() {
        let cli = Cli::try_parse_from(["wildbloomd", "--parent-pid", "1234"]).unwrap();
        assert_eq!(cli.parent_pid, Some(1234));
    }
}
