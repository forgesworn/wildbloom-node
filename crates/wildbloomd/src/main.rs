use clap::Parser;
use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use tracing_subscriber::EnvFilter;
use url::Url;
use wildbloom_core::{
    AppState, BlossomConfig, DirectHttpsFetcher, FriendGrant, ServerMetadata, Store, StoreConfig,
    router,
};

mod grants;
mod proofs;
mod replicas;
mod services;
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
            // CLI grants are local operator configuration, not delegated
            // grants issued by another identity.
            issuer: None,
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
    #[command(subcommand)]
    command: Option<Command>,
    /// Address used by the local HTTP service.
    #[arg(long, env = "WILDBLOOM_BIND", default_value = "127.0.0.1:3742")]
    bind: SocketAddr,

    /// Permit binding to a non-loopback interface.
    #[arg(long, env = "WILDBLOOM_ALLOW_PUBLIC_BIND")]
    allow_public_bind: bool,

    /// Persistent data directory.
    #[arg(long, env = "WILDBLOOM_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Private operator checkout profile; enables direct-to-operator Lightning/LNURLcash sales.
    #[arg(long, env = "WILDBLOOM_CHECKOUT_PROFILE", requires = "no_tor")]
    checkout_profile: Option<PathBuf>,

    /// Explicit public service listing and optional external-signer Nostr publication.
    #[arg(long, env = "WILDBLOOM_SERVICE_PROFILE")]
    service_profile: Option<PathBuf>,

    /// Enable bounded authenticated full-read storage challenges (not continuous-retention proofs).
    #[arg(long, env = "WILDBLOOM_STORAGE_PROOFS")]
    storage_proofs: bool,

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

    /// Exact value accepted in BUD-11 server tags (repeatable, or comma-separated).
    #[arg(
        long = "server-name",
        env = "WILDBLOOM_SERVER_NAME",
        value_delimiter = ','
    )]
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

    /// Accept owner-signed device grants on /grants/v1 (requires --allow-pubkey).
    #[arg(long, env = "WILDBLOOM_DEVICE_GRANTS")]
    device_grants: bool,

    /// Issue one-use Foregather live creation grants to granted devices.
    /// The operator token comes from --pairing-operator-token-file or the
    /// WILDBLOOM_PAIRING_OPERATOR_TOKEN environment variable, never an argument.
    #[arg(
        long,
        env = "WILDBLOOM_PAIRING_ISSUER",
        requires_all = ["device_grants", "pairing_relay_url"]
    )]
    pairing_issuer: bool,

    /// Foregather resolver API base, for example https://relay.example/ (loopback HTTP allowed).
    #[arg(long, env = "WILDBLOOM_PAIRING_RELAY_URL", requires = "pairing_issuer")]
    pairing_relay_url: Option<Url>,

    /// Private (0600) file holding the Foregather operator creation token.
    #[arg(
        long,
        env = "WILDBLOOM_PAIRING_OPERATOR_TOKEN_FILE",
        requires = "pairing_issuer"
    )]
    pairing_operator_token_file: Option<PathBuf>,

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

    /// Run without a managed Tor service.  The listener remains loopback-only by default.
    #[arg(long, env = "WILDBLOOM_NO_TOR")]
    no_tor: bool,

    /// Fetch public HTTPS mirror and repair sources directly instead of through Tor.
    #[arg(
        long,
        env = "WILDBLOOM_DIRECT_HTTPS_MIRRORS",
        requires = "no_tor",
        conflicts_with = "mirror_proxy"
    )]
    direct_https_mirrors: bool,

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

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Maintain replicas under a signed local policy.
    Replicas(replicas::Cli),
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
    if let Some(Command::Replicas(args)) = cli.command {
        // main's Result termination uses Debug. Preserve the actionable,
        // redacted Display message instead of exposing variants like State(Io).
        return replicas::run(args)
            .await
            .map_err(|error| error.to_string().into());
    }
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
            "no owner, friend grant or open-shelter policy is configured; writes require a previously activated paid allowance"
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
    let repair_enabled =
        (mirror_proxy.is_some() || cli.direct_https_mirrors) && cli.repair_interval > 0;
    if cli.device_grants && cli.allowed_pubkeys.is_empty() {
        return Err("--device-grants requires at least one --allow-pubkey owner".into());
    }
    let cli_friend_grants = cli
        .friend_grants
        .into_iter()
        .map(|grant| grant.0)
        .collect::<Vec<_>>();
    // Persisted grants are always honoured once they exist, even if the routes
    // are later disabled, so turning the flag off never demotes stored claims.
    // Read early so its announcement key can be reserved from delegation.
    let service_profile = cli
        .service_profile
        .as_ref()
        .map(|path| services::Profile::read(path))
        .transpose()?;
    let device_grants = if cli.device_grants || grants::has_database(&data_dir) {
        Some(grants::Grants::open(
            &data_dir,
            grants::GrantsConfig {
                owners: cli.allowed_pubkeys.clone(),
                server_names: server_names.clone(),
                origin: public_url.to_string(),
                cli_friend_grants: cli_friend_grants.clone(),
                reserved_keys: service_profile
                    .iter()
                    .map(|profile| profile.service_pubkey.clone())
                    .collect(),
            },
            grants::system_clock(),
        )?)
    } else {
        None
    };
    let pairing_issuer_token = if cli.pairing_issuer {
        Some(
            match (
                &cli.pairing_operator_token_file,
                std::env::var(grants::issuer::TOKEN_ENV),
            ) {
                (Some(path), Err(_)) => grants::issuer::OperatorToken::from_file(path)?,
                (None, Ok(value)) => grants::issuer::OperatorToken::parse(&value)?,
                _ => {
                    return Err("--pairing-issuer needs exactly one of --pairing-operator-token-file or WILDBLOOM_PAIRING_OPERATOR_TOKEN".into());
                }
            },
        )
    } else {
        None
    };
    let config = BlossomConfig {
        server_metadata: ServerMetadata {
            name: "Wildbloom Node".into(),
            software: "https://github.com/forgesworn/wildbloom-node".into(),
        },
        public_base_url: public_url.clone(),
        accepted_server_names: server_names.clone(),
        allowed_pubkeys: cli.allowed_pubkeys,
        friend_grants: match &device_grants {
            Some(device_grants) => device_grants.core_friend_grants(),
            None => cli_friend_grants,
        },
        open_shelter: cli.open_shelter,
        max_concurrent_writes: cli.max_concurrent_writes,
        mirror_proxy: mirror_proxy.clone(),
    };
    let private_keys = config
        .allowed_pubkeys
        .iter()
        .cloned()
        .chain(
            config
                .friend_grants
                .iter()
                .map(|grant| grant.pubkey.clone()),
        )
        .chain(
            device_grants
                .iter()
                .flat_map(|device_grants| device_grants.known_keys()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let state = if cli.direct_https_mirrors {
        AppState::with_fetcher(store, config, Arc::new(DirectHttpsFetcher::new()?))?
    } else {
        AppState::new(store, config)?
    };
    let transport = if tor.is_some() {
        "tor"
    } else if cli.direct_https_mirrors {
        "direct-https"
    } else {
        "local-only"
    };
    tracing::info!(
        address = %local_address,
        public_url = %public_url,
        server_names = ?server_names,
        transport,
        "Wildbloom Node is ready"
    );
    if repair_enabled {
        tokio::spawn(repair_loop(
            state.clone(),
            std::time::Duration::from_secs(cli.repair_interval),
        ));
    }
    let mut routes = router(state.clone());
    let mut _grant_maintenance = None;
    if let Some(device_grants) = &device_grants {
        device_grants.attach(state.clone());
        if let Err(error) = device_grants.startup().await {
            tracing::warn!(reason = %error, "device grant sweep will retry");
        }
        _grant_maintenance = Some(grants::Maintenance(device_grants.spawn_maintenance()));
        routes = routes.layer(axum::middleware::from_fn_with_state(
            device_grants.clone(),
            grants::gate,
        ));
        if cli.device_grants {
            routes = routes.merge(device_grants.router());
        }
        if let (Some(token), Some(relay_url)) = (pairing_issuer_token, &cli.pairing_relay_url) {
            let issuer = grants::issuer::Issuer::new(device_grants.clone(), relay_url, token)?;
            routes = routes.merge(issuer.router());
        }
    }
    if cli.storage_proofs {
        routes = routes.merge(proofs::router(
            state.store().clone(),
            public_url.to_string(),
        ));
    }
    let mut checkout_service = None;
    if let Some(profile) = cli.checkout_profile {
        let (checkout, service) = wildbloom_checkout::RuntimeProfile::read(&profile)
            .and_then(|profile| {
                profile.open_with_service(state.store().clone(), public_url.as_str())
            })
            .map_err(|error| error.to_string())?;
        routes = routes.merge(checkout);
        checkout_service = Some(service);
    }
    let publisher = if let Some(profile) = service_profile {
        let services = services::Services::new(
            profile,
            state.store().clone(),
            checkout_service,
            public_url.as_str(),
            cli.open_shelter,
            mirror_proxy.is_some() || cli.direct_https_mirrors,
            &private_keys,
            mirror_proxy.as_ref(),
            cli.no_tor,
        )?;
        routes = routes.merge(services.router()?);
        services.start(mirror_proxy)?
    } else {
        None
    };
    let served = axum::serve(listener, routes)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    if let Some(publisher) = publisher {
        publisher.stop().await;
    }
    if let Some(tor) = tor {
        tor.shutdown().await;
    }
    served?;
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
    if url.scheme() == "http"
        && !url
            .host_str()
            .is_some_and(|host| host == "localhost" || host.ends_with(".onion"))
        && !url
            .host()
            .and_then(|host| match host {
                url::Host::Ipv4(address) => Some(address.is_loopback()),
                url::Host::Ipv6(address) => Some(address.is_loopback()),
                url::Host::Domain(_) => None,
            })
            .unwrap_or(false)
    {
        return Err(
            "--public-url requires HTTPS except for localhost, loopback or onion origins".into(),
        );
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

    #[test]
    fn direct_https_mirroring_requires_no_tor_and_conflicts_with_a_proxy() {
        assert!(Cli::try_parse_from(["wildbloomd", "--direct-https-mirrors"]).is_err());
        assert!(
            Cli::try_parse_from([
                "wildbloomd",
                "--no-tor",
                "--direct-https-mirrors",
                "--mirror-proxy",
                "socks5h://127.0.0.1:9050",
            ])
            .is_err()
        );
        let cli =
            Cli::try_parse_from(["wildbloomd", "--no-tor", "--direct-https-mirrors"]).unwrap();
        assert!(cli.no_tor);
        assert!(cli.direct_https_mirrors);
    }

    #[test]
    fn public_url_requires_https_except_for_local_and_onion_origins() {
        for accepted in [
            "https://blossom.example/",
            "http://localhost:3742/",
            "http://127.0.0.1:3742/",
            "http://[::1]:3742/",
            &format!("http://{}.onion/", "a".repeat(56)),
        ] {
            assert!(
                validate_public_url(&Url::parse(accepted).unwrap()).is_ok(),
                "{accepted}"
            );
        }
        for rejected in ["http://blossom.example/", "ftp://blossom.example/"] {
            assert!(
                validate_public_url(&Url::parse(rejected).unwrap()).is_err(),
                "{rejected}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_the_hidden_desktop_parent_contract() {
        let cli = Cli::try_parse_from(["wildbloomd", "--parent-pid", "1234"]).unwrap();
        assert_eq!(cli.parent_pid, Some(1234));
    }

    #[test]
    fn device_grants_and_the_pairing_issuer_are_explicit_opt_ins() {
        let cli = Cli::try_parse_from(["wildbloomd"]).unwrap();
        assert!(!cli.device_grants && !cli.pairing_issuer);
        assert!(Cli::try_parse_from(["wildbloomd", "--pairing-issuer"]).is_err());
        assert!(
            Cli::try_parse_from([
                "wildbloomd",
                "--pairing-issuer",
                "--pairing-relay-url",
                "http://127.0.0.1:8787/",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "wildbloomd",
                "--pairing-relay-url",
                "http://127.0.0.1:8787/",
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "wildbloomd",
            "--device-grants",
            "--pairing-issuer",
            "--pairing-relay-url",
            "http://127.0.0.1:8787/",
            "--pairing-operator-token-file",
            "/var/lib/example/token",
        ])
        .unwrap();
        assert!(cli.device_grants && cli.pairing_issuer);
    }

    #[test]
    fn server_names_accept_a_comma_separated_list() {
        let cli = Cli::try_parse_from([
            "wildbloomd",
            "--server-name",
            "192.0.2.10,archipelago.local",
        ])
        .expect("arguments parse");
        assert_eq!(
            cli.server_names,
            vec!["192.0.2.10".to_owned(), "archipelago.local".to_owned()]
        );
    }
}
