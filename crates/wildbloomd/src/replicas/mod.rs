mod engine;
mod policy;
mod signer;
mod state;
#[cfg(test)]
mod tests;
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
}

#[derive(Debug, Args)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

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
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(long)]
    policy: PathBuf,
    /// Expected policy author, as a lowercase hexadecimal public key.
    #[arg(long)]
    owner: String,
    #[arg(long)]
    state_dir: PathBuf,
    /// Perform one bounded pass and exit.
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
        Command::Run(args) => {
            if args.signer.as_ref().is_some_and(|path| !path.is_absolute()) {
                return Err(Error::Configuration("local signer path must be absolute"));
            }
            let mut state = state::StateDirectory::open(&args.state_dir)?;
            let signer = args.signer.map(|executable| signer::CommandSigner {
                executable,
                arguments: args.signer_arg,
                timeout: Duration::from_secs(args.signer_timeout),
            });
            let limits = engine::Limits {
                verification_bytes: args.verification_budget_bytes,
                mirrors: args.max_mirror_attempts,
            };
            loop {
                let result = async {
                    let policy = engine::load_policy(&args.policy, &args.owner, clock.now())?;
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
                        path: &args.policy,
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
