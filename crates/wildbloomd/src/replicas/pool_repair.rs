//! Explicit owner-side reconstruction, never started by the storage server.
use super::{
    Error, coding,
    engine::{Clock, SystemClock},
    policy, pool,
    signer::{CommandSigner, Signer},
    state,
    transport::{HttpTransport, Transport},
};
use base64::Engine as _;
use clap::Args;
use nostr::prelude::{Kind, PublicKey, Tag, Timestamp, UnsignedEvent};
use serde::Serialize;
use std::{collections::BTreeSet, path::PathBuf, time::Duration};
use url::Url;

#[derive(Debug, Args)]
pub(super) struct RepairArgs {
    /// Private owner-signed receipt. Replacement requires an explicit restart.
    #[arg(long)]
    receipt: PathBuf,
    /// Exact signed event ID; prevents silent receipt replacement/rollback.
    #[arg(long)]
    receipt_id: String,
    #[arg(long)]
    owner: String,
    /// Private working directory, exclusive to this owner repair process.
    #[arg(long)]
    work_dir: PathBuf,
    /// Explicit consent that THIS machine may reconstruct the ciphertext.
    #[arg(long, required = true)]
    allow_reconstruction: bool,
    /// Unix seconds. No repair authority exists after this deadline.
    #[arg(long)]
    expires_at: u64,
    /// Absolute external signer path. No signing key is held by this process.
    #[arg(long)]
    signer: PathBuf,
    #[arg(long)]
    signer_arg: Vec<String>,
    #[arg(long, default_value_t=30, value_parser=clap::value_parser!(u64).range(1..=60))]
    signer_timeout: u64,
    #[arg(long)]
    proxy: Option<Url>,
    #[arg(long)]
    permit_loopback_development: bool,
    #[arg(long)]
    once: bool,
    #[arg(long, default_value_t=300, value_parser=clap::value_parser!(u64).range(5..=86400))]
    interval: u64,
    /// Aggregate read/write bytes reserved per pass, including failed attempts.
    #[arg(long, default_value_t=8*1024*1024*1024_u64)]
    transfer_budget_bytes: u64,
    /// Conservative temporary disk reservation bound, before any network I/O.
    #[arg(long, default_value_t=5*1024*1024*1024_u64)]
    max_work_bytes: u64,
}

#[derive(Serialize)]
struct Report {
    receipt_id: String,
    observed_at: u64,
    verified_groups: Vec<usize>,
    recoverable: bool,
    protected: bool,
    reconstructed: bool,
    uploads_attempted: usize,
    reserved_transfer_bytes: u64,
}
struct Guard<'a> {
    args: &'a RepairArgs,
    bytes: &'a [u8],
}
impl Guard<'_> {
    fn check(&self) -> Result<(), Error> {
        if SystemClock.now() >= self.args.expires_at {
            return Err(Error::Configuration("owner pool repair authority expired"));
        }
        if state::read_bounded(&self.args.receipt, 128 * 1024)? != self.bytes {
            return Err(Error::Changed);
        }
        Ok(())
    }
}
fn target(node: &pool::Node) -> policy::Target {
    policy::Target {
        id: node.id.clone(),
        origin: node.origin.clone(),
        failure_group: node.failure_group.clone(),
        retention: policy::Retention::Owner,
    }
}
fn blob(part: &pool::Part) -> policy::Blob {
    policy::Blob {
        sha256: part.sha256.clone(),
        size: part.size,
    }
}
fn reserve(left: &mut u64, bytes: u64) -> Result<(), Error> {
    *left = left.checked_sub(bytes).ok_or(Error::Configuration(
        "owner pool repair transfer budget exhausted",
    ))?;
    Ok(())
}
fn upload_template(
    args: &RepairArgs,
    part: &pool::Part,
    node: &pool::Node,
) -> Result<UnsignedEvent, Error> {
    let now = SystemClock.now();
    let origin = Url::parse(&node.origin).map_err(|_| Error::Internal)?;
    let tags = vec![
        vec!["t".into(), "upload".into()],
        vec!["x".into(), part.sha256.clone()],
        vec![
            "server".into(),
            origin.host_str().ok_or(Error::Internal)?.into(),
        ],
        vec![
            "expiration".into(),
            now.saturating_add(120).min(args.expires_at).to_string(),
        ],
    ]
    .into_iter()
    .map(Tag::parse)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| Error::Internal)?;
    Ok(UnsignedEvent::new(
        PublicKey::from_hex(&args.owner).map_err(|_| Error::Internal)?,
        Timestamp::from_secs(now.saturating_sub(1)),
        Kind::from(24242),
        tags,
        format!(
            "Restore one assigned pool part; receipt {}; destination {}",
            args.receipt_id, node.origin
        ),
    ))
}
async fn pass(
    guard: &Guard<'_>,
    manifest: &pool::Manifest,
    transport: &HttpTransport,
    signer: &dyn Signer,
) -> Result<Report, Error> {
    guard.check()?;
    let args = guard.args;
    // At most one retained verified source per part, all regenerated outputs,
    // and a scratch download. Crash leftovers remain bounded by this same gate.
    let required_disk = manifest.parts[0]
        .size
        .checked_mul(2 * manifest.total as u64 + 1)
        .ok_or(Error::Internal)?;
    if required_disk > args.max_work_bytes {
        return Err(Error::Configuration(
            "pool layout exceeds temporary disk budget",
        ));
    }
    let temp = tempfile::Builder::new()
        .prefix("pool-pass-")
        .tempdir_in(&args.work_dir)
        .map_err(|_| state::StateError::Io)?;
    let mut left = args.transfer_budget_bytes;
    let mut groups = vec![BTreeSet::new(); manifest.total];
    let mut sources = Vec::new();
    for part in &manifest.parts {
        let mut stored = false;
        for node in &part.targets {
            if groups[part.index].contains(&node.failure_group) {
                continue;
            }
            guard.check()?;
            reserve(&mut left, part.size)?;
            if stored {
                if transport.verify(&target(node), &blob(part)).await.is_err() {
                    continue;
                }
            } else {
                let file = tempfile::NamedTempFile::new_in(temp.path())
                    .map_err(|_| state::StateError::Io)?;
                if transport
                    .download(&target(node), &blob(part), file.path())
                    .await
                    .is_err()
                {
                    continue;
                }
                let path = temp.path().join(format!("source-{}", part.index));
                file.persist(&path).map_err(|_| state::StateError::Io)?;
                sources.push((part.index, path));
                stored = true;
            }
            guard.check()?;
            groups[part.index].insert(node.failure_group.clone());
            if groups[part.index].len() >= usize::from(manifest.copies) {
                break;
            }
        }
    }
    let mut reconstructed = false;
    let mut uploads_attempted = 0;
    if sources.len() >= manifest.required
        && groups
            .iter()
            .any(|g| g.len() < usize::from(manifest.copies))
    {
        let files = if manifest.mode == "erasure" && sources.len() < manifest.total {
            guard.check()?;
            let files =
                coding::regenerate(manifest, &sources[..manifest.required], temp.path()).await?;
            guard.check()?;
            reconstructed = true;
            files
        } else {
            let mut files = vec![PathBuf::new(); manifest.total];
            for (i, path) in &sources {
                files[*i] = path.clone();
            }
            files
        };
        for part in &manifest.parts {
            for node in &part.targets {
                if groups[part.index].len() >= usize::from(manifest.copies) {
                    break;
                }
                if groups[part.index].contains(&node.failure_group) {
                    continue;
                }
                guard.check()?;
                // Reserve upload plus mandatory read-back BEFORE requesting a signature.
                reserve(&mut left, part.size * 2)?;
                let request = upload_template(args, part, node)?;
                let returned = signer.sign(&request).await;
                guard.check()?;
                let Ok(bytes) = returned else {
                    continue;
                };
                let Ok(event) = policy::verify_return(&bytes, &request, SystemClock.now()) else {
                    continue;
                };
                let header = format!(
                    "Nostr {}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(event.as_json())
                );
                guard.check()?;
                uploads_attempted += 1;
                if transport
                    .upload(&target(node), &blob(part), &files[part.index], &header)
                    .await
                    .is_err()
                {
                    continue;
                }
                guard.check()?;
                if transport.verify(&target(node), &blob(part)).await.is_ok() {
                    guard.check()?;
                    groups[part.index].insert(node.failure_group.clone());
                }
            }
        }
    }
    guard.check()?;
    Ok(Report {
        receipt_id: args.receipt_id.clone(),
        observed_at: SystemClock.now(),
        protected: groups
            .iter()
            .all(|g| g.len() >= usize::from(manifest.copies)),
        recoverable: groups.iter().filter(|g| !g.is_empty()).count() >= manifest.required,
        verified_groups: groups.iter().map(BTreeSet::len).collect(),
        reconstructed,
        uploads_attempted,
        reserved_transfer_bytes: args.transfer_budget_bytes - left,
    })
}
async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
pub(super) async fn run(args: RepairArgs) -> Result<(), Error> {
    let now = SystemClock.now();
    if !args.allow_reconstruction
        || !args.signer.is_absolute()
        || args.expires_at <= now
        || args.expires_at - now > 365 * 86400
        || !policy::canonical_hex(&args.receipt_id, 32)
    {
        return Err(Error::Configuration(
            "explicit bounded owner repair authority and absolute signer are required",
        ));
    }
    let bytes = state::read_bounded(&args.receipt, 128 * 1024)?;
    let (manifest, profile) = pool::receipt(
        &bytes,
        &args.owner,
        &args.receipt_id,
        now,
        args.permit_loopback_development,
    )?;
    let transport = HttpTransport::new(
        profile,
        args.proxy.as_ref(),
        args.permit_loopback_development,
    )
    .map_err(Error::Configuration)?;
    // Reuse the private directory/exclusive OS lock boundary. No bearer event or
    // ciphertext enters persistent state. Graceful shutdown removes pass files.
    let _lock = state::StateDirectory::open(&args.work_dir)?;
    // Do not silently delete leftovers from a killed process or unrelated files.
    if std::fs::read_dir(&args.work_dir)
        .map_err(|_| state::StateError::Io)?
        .any(|e| e.is_ok_and(|e| e.file_name().to_string_lossy().starts_with("pool-pass-")))
    {
        return Err(Error::Configuration(
            "review and remove stale pool-pass directories before restarting owner repair",
        ));
    }
    let signer = CommandSigner {
        executable: args.signer.clone(),
        arguments: args.signer_arg.clone(),
        timeout: Duration::from_secs(args.signer_timeout),
    };
    let guard = Guard {
        args: &args,
        bytes: &bytes,
    };
    let stop = shutdown();
    tokio::pin!(stop);
    loop {
        guard.check()?;
        let remaining = Duration::from_secs(args.expires_at.saturating_sub(SystemClock.now()));
        let result = tokio::select! {
            _ = &mut stop => return Ok(()),
            _ = tokio::time::sleep(remaining) => return Err(Error::Configuration("owner pool repair authority expired")),
            result = pass(&guard,&manifest,&transport,&signer) => result,
        }?;
        state::write_private(
            &args.work_dir,
            "pool-report.json",
            &serde_json::to_vec_pretty(&result)?,
        )?;
        println!("{}", serde_json::to_string(&result)?);
        if args.once {
            return if result.protected {
                Ok(())
            } else {
                Err(Error::Configuration(
                    "pool remains below requested protection",
                ))
            };
        }
        tokio::select! { _ = &mut stop => return Ok(()), _ = tokio::time::sleep(Duration::from_secs(args.interval).min(remaining)) => {} }
    }
}
