mod directory;
mod engine;
mod enrol;
mod policy;
mod signer;
mod state;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_directory;
#[cfg(test)]
mod tests_enrol;
mod transport;

use clap::{Args, Subcommand};
use engine::Clock;
use std::{path::PathBuf, time::Duration};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Policy(#[from] policy::PolicyError),
    #[error(transparent)]
    State(#[from] state::StateError),
    #[error("could not encode replica state")]
    Json(#[from] serde_json::Error),
    #[error("policy changed during the maintenance pass")]
    Changed,
    #[error("replica state does not match the current operation")]
    Internal,
    #[error("{0}")]
    Configuration(&'static str),
    #[error("{0}")]
    Enrol(String),
}

#[derive(Debug, Args)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

// Parsed once per process; boxing the arguments buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    /// Produce an unsigned local policy event; no network or signer contact.
    Template {
        #[arg(long)]
        content: PathBuf,
        #[arg(long)]
        owner: String,
    },
    /// Verify and maintain explicitly configured replicas.
    Run(RunArgs),
    /// Derive and sign intake and archive policies from a source inventory.
    Enrol(EnrolArgs),
}

#[derive(Debug, Args)]
struct EnrolArgs {
    /// Enrolment configuration (JSON). See docs/REPLICA-POLICY.md.
    #[arg(long)]
    config: PathBuf,
    /// JSON array of {sha256, size, type?, uploaded?} rows; `-` reads stdin.
    #[arg(long)]
    inventory_file: PathBuf,
    /// Report what would be enrolled and signed; write and sign nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(
        long,
        required_unless_present = "policy_dir",
        conflicts_with = "policy_dir"
    )]
    policy: Option<PathBuf>,
    /// Expected policy author, as a lowercase hexadecimal public key.
    #[arg(long)]
    owner: String,
    #[arg(
        long,
        required_unless_present = "policy_dir",
        conflicts_with = "state_root"
    )]
    state_dir: Option<PathBuf>,
    /// Maintain every `signed-<id>.json` in this directory from one process.
    #[arg(long, requires = "state_root")]
    policy_dir: Option<PathBuf>,
    /// With --policy-dir: one private state directory per policy id.
    #[arg(long, requires = "policy_dir")]
    state_root: Option<PathBuf>,
    /// With --policy-dir: interval for ids starting PREFIX (repeatable,
    /// longest prefix wins), as PREFIX=SECONDS.
    #[arg(long, requires = "policy_dir", value_parser = directory::parse_interval)]
    interval_for: Vec<(String, u64)>,
    /// Perform one bounded pass (per policy, with --policy-dir) and exit.
    #[arg(long)]
    once: bool,
    /// Seconds between completed passes.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(5..=86400))]
    interval: u64,
    #[arg(long)]
    proxy: Option<Url>,
    /// Explicitly permit the insecure literal-loopback development profile.
    #[arg(long)]
    permit_loopback_development: bool,
    /// Absolute path to a local signer. Omit to use the file handoff.
    #[arg(long)]
    signer: Option<PathBuf>,
    /// Static argument passed to the selected local signer (repeatable).
    #[arg(long, requires = "signer")]
    signer_arg: Vec<String>,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=60))]
    signer_timeout: u64,
    #[arg(long, default_value_t = 8 * 1024 * 1024 * 1024_u64)]
    verification_budget_bytes: u64,
    #[arg(long, default_value_t = 4)]
    max_mirror_attempts: usize,
}

pub async fn run(cli: Cli) -> Result<(), Error> {
    let clock = engine::SystemClock;
    match cli.command {
        Command::Template { content, owner } => {
            let bytes = state::read_bounded(&content, policy::MAX_POLICY_BYTES)?;
            let policy = serde_json::from_slice(&bytes).map_err(|_| policy::PolicyError::Schema)?;
            let event = policy::policy_template(policy, &owner, clock.now())?;
            println!("{}", serde_json::to_string_pretty(&event)?);
            Ok(())
        }
        Command::Enrol(args) => {
            let config: enrol::Config =
                serde_json::from_slice(&state::read_bounded(&args.config, 64 * 1024)?)
                    .map_err(|_| Error::Configuration("enrolment configuration is invalid"))?;
            let inventory = if args.inventory_file.as_os_str() == "-" {
                use std::io::Read as _;
                let mut bytes = Vec::new();
                std::io::stdin()
                    .take(enrol::MAX_INVENTORY_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| state::StateError::Io)?;
                bytes
            } else {
                state::read_bounded(&args.inventory_file, enrol::MAX_INVENTORY_BYTES)?
            };
            let inventory = enrol::parse_inventory(&inventory)?;
            let signer = signer::CommandSigner {
                executable: config.signer.clone(),
                arguments: config.signer_args.clone(),
                timeout: Duration::from_secs(config.signer_timeout_secs.clamp(1, 60)),
            };
            let report = enrol::run(
                &config,
                &inventory,
                Some(&signer as &dyn signer::Signer),
                &clock,
                args.dry_run,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::Run(args) => {
            if args.signer.as_ref().is_some_and(|path| !path.is_absolute()) {
                return Err(Error::Configuration("local signer path must be absolute"));
            }
            let signer = args.signer.map(|executable| signer::CommandSigner {
                executable,
                arguments: args.signer_arg,
                timeout: Duration::from_secs(args.signer_timeout),
            });
            let limits = engine::Limits {
                verification_bytes: args.verification_budget_bytes,
                mirrors: args.max_mirror_attempts,
            };
            if let (Some(policy_dir), Some(state_root)) = (args.policy_dir, args.state_root) {
                if !policy::canonical_hex(&args.owner, 32) {
                    return Err(Error::Configuration(
                        "owner must be a lowercase hexadecimal public key",
                    ));
                }
                let proxy = args.proxy.clone();
                let permit = args.permit_loopback_development;
                let factory = move |policy: &policy::VerifiedPolicy| {
                    transport::HttpTransport::new(policy.policy.profile, proxy.as_ref(), permit)
                        .map(|transport| Box::new(transport) as Box<dyn transport::Transport>)
                };
                let settings = directory::Settings {
                    policy_dir,
                    state_root,
                    owner: args.owner,
                    limits,
                    default_interval: args.interval,
                    intervals: args.interval_for,
                    transport: &factory,
                };
                return directory::run(
                    settings,
                    &clock,
                    signer.as_ref().map(|signer| signer as &dyn signer::Signer),
                    args.once,
                )
                .await;
            }
            let (Some(policy_path), Some(state_dir)) = (args.policy, args.state_dir) else {
                return Err(Error::Configuration(
                    "give --policy and --state-dir, or --policy-dir and --state-root",
                ));
            };
            let mut state = state::StateDirectory::open(&state_dir)?;
            loop {
                let result = async {
                    let policy = engine::load_policy(&policy_path, &args.owner, clock.now())?;
                    limits.validate(&policy)?;
                    let transport: Box<dyn transport::Transport> =
                        if policy.policy.desired_groups == 0 {
                            Box::new(transport::DisabledTransport)
                        } else {
                            Box::new(
                                transport::HttpTransport::new(
                                    policy.policy.profile,
                                    args.proxy.as_ref(),
                                    args.permit_loopback_development,
                                )
                                .map_err(Error::Configuration)?,
                            )
                        };
                    let guard = engine::Guard {
                        path: &policy_path,
                        expected: &policy,
                        clock: &clock,
                    };
                    engine::run_pass(
                        &guard,
                        &mut state,
                        transport.as_ref(),
                        signer.as_ref().map(|signer| signer as &dyn signer::Signer),
                        limits,
                    )
                    .await
                }
                .await;
                match result {
                    Ok(report) => {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                        if args.once || report.stopped {
                            return Ok(());
                        }
                    }
                    Err(error) => {
                        state.invalidate()?;
                        return Err(error);
                    }
                }
                tokio::select! {
                    _ = wait_for_work(&state, Duration::from_secs(args.interval)) => {},
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                }
            }
        }
    }
}

async fn wait_for_work(state: &state::StateDirectory, interval: Duration) {
    let deadline = tokio::time::Instant::now() + interval;
    loop {
        if let Some(snapshot) = &state.snapshot {
            let now = engine::SystemClock.now();
            if snapshot.pending.values().any(|pending| {
                pending.requested_at.saturating_add(120) <= now
                    || std::fs::symlink_metadata(state.pending_path(&pending.event_id, true))
                        .is_ok()
            }) {
                return;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep_until(
            deadline.min(tokio::time::Instant::now() + Duration::from_secs(1)),
        )
        .await;
    }
}
