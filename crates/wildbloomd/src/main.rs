use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};
use tracing_subscriber::EnvFilter;
use url::Url;
use wildbloom_core::{AppState, BlossomConfig, Store, StoreConfig, router};

mod tor;

use tor::TorService;

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
    #[arg(long, env = "WILDBLOOM_DATA_DIR", default_value = "./data")]
    data_dir: PathBuf,

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

    /// Run only on the local HTTP listener instead of starting Tor.
    #[arg(long, env = "WILDBLOOM_NO_TOR")]
    no_tor: bool,

    /// Tor executable used for the managed onion service.
    #[arg(long, env = "WILDBLOOM_TOR_BIN", default_value = "tor")]
    tor_bin: PathBuf,

    /// Seconds allowed for Tor to bootstrap.
    #[arg(long, env = "WILDBLOOM_TOR_TIMEOUT", default_value_t = 120)]
    tor_timeout: u64,
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
    if !cli.bind.ip().is_loopback() && !cli.allow_public_bind {
        return Err("refusing a non-loopback bind without --allow-public-bind".into());
    }
    let store = Store::open(StoreConfig {
        root: cli.data_dir.clone(),
        quota_bytes: cli.quota_bytes,
        max_blob_bytes: cli.max_blob_bytes,
    })?;
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
                &cli.data_dir.join("tor"),
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
    let mirror_proxy = tor.as_ref().map(|service| {
        Url::parse(&format!("socks5h://{}", service.socks_address()))
            .expect("managed Tor SOCKS URL is valid")
    });

    let state = AppState::new(
        store,
        BlossomConfig {
            public_base_url: public_url.clone(),
            accepted_server_names: server_names.clone(),
            mirror_proxy,
        },
    )?;
    tracing::info!(
        address = %local_address,
        public_url = %public_url,
        server_names = ?server_names,
        "Wildbloom Node is ready"
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    if let Some(tor) = tor {
        tor.shutdown().await;
    }
    Ok(())
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
}
