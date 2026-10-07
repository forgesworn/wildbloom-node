//! Local, offline-by-default recovery tool. No listening socket or spending API.
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use wildbloom_checkout::{
    Checkout, Config, Destination, Error, HttpNoteTransport, Ledger, Phoenixd,
};
use wildbloom_core::{Store, StoreConfig};

#[derive(Parser)]
struct Args {
    /// Existing private checkout directory; stop its owning process first.
    #[arg(long)]
    state: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Bounded local inventory. No receiving I/O, invoices or bearer assets.
    Inspect {
        #[arg(long, default_value = "")]
        after: String,
        #[arg(long, default_value_t = 50)]
        limit: u16,
    },
    /// One explicit recovery attempt. May replay an already journalled note rotation.
    Reconcile {
        order: String,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Attach exactly one original Phoenixd invoice; does not check settlement.
    RecoverInvoice {
        order: String,
        #[arg(long)]
        profile: PathBuf,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    checkout: Config,
    storage_root: PathBuf,
    quota_bytes: u64,
    max_blob_bytes: u64,
    phoenixd: Option<PhoenixProfile>,
    #[serde(default)]
    notes: Vec<NoteProfile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhoenixProfile {
    destination: Destination,
    password_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoteProfile {
    endpoint: String,
    destination: Destination,
}
fn private_file(path: &Path) -> Result<Vec<u8>, Error> {
    wildbloom_checkout::read_private_file(path)
}

fn open(profile: &Path, ledger: Ledger) -> Result<(Checkout, Option<Arc<Phoenixd>>), Error> {
    let profile: Profile = serde_json::from_slice(&private_file(profile)?)?;
    profile.checkout.validate()?;
    // Refuse to accidentally bootstrap a new store during recovery.
    if !profile.storage_root.join("wildbloom.sqlite3").is_file() {
        return Err(Error::Invalid);
    }
    let phoenix = profile
        .phoenixd
        .map(|p| {
            let password =
                String::from_utf8(private_file(&p.password_file)?).map_err(|_| Error::Invalid)?;
            Phoenixd::new(
                p.destination,
                password.trim_end_matches(['\r', '\n']).into(),
                ledger.clone(),
            )
            .map(Arc::new)
        })
        .transpose()?;
    let notes = if profile.notes.is_empty() {
        None
    } else {
        Some(Arc::new(HttpNoteTransport::new(
            profile
                .notes
                .into_iter()
                .map(|p| (p.endpoint, p.destination))
                .collect(),
        )?) as Arc<dyn wildbloom_checkout::NoteTransport>)
    };
    let store = Store::open(StoreConfig {
        root: profile.storage_root,
        quota_bytes: profile.quota_bytes,
        max_blob_bytes: profile.max_blob_bytes,
    })
    .map_err(|_| Error::Internal)?;
    let checkout = Checkout::new(
        profile.checkout,
        ledger,
        store,
        phoenix
            .clone()
            .map(|p| p as Arc<dyn toll_booth::backends::LightningBackend>),
        notes,
    )?;
    Ok((checkout, phoenix))
}
async fn run(args: Args) -> Result<(), Error> {
    if !args.state.join("checkout.sqlite3").is_file() {
        return Err(Error::Invalid);
    }
    let ledger = Ledger::open(&args.state)?;
    match args.command {
        Command::Inspect { after, limit } => println!(
            "{}",
            serde_json::to_string_pretty(&ledger.inspect(&after, limit)?)?
        ),
        Command::Reconcile { order, profile } => {
            let (checkout, _) = open(&profile, ledger)?;
            let result = checkout.reconcile(&order).await?;
            println!("{}", serde_json::to_string(&result.state)?);
        }
        Command::RecoverInvoice { order, profile } => {
            let (checkout, phoenix) = open(&profile, ledger)?;
            let invoice = phoenix
                .ok_or(Error::Unavailable)?
                .original_invoice(&order)
                .await?;
            checkout.recover_invoice(&order, invoice).await?;
            println!("original invoice attached; settlement check still required");
        }
    }
    Ok(())
}
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run(Args::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operator_files_are_bounded_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        std::fs::write(&path, b"synthetic").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(private_file(&path).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(private_file(&link).is_err());
        }
        assert_eq!(private_file(&path).unwrap(), b"synthetic");
        std::fs::write(&path, vec![0; 65537]).unwrap();
        assert!(private_file(&path).is_err());
    }
}
