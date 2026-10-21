//! Start-up behaviour of `wildbloomd --group-mode`, through the real binary.
//! Synthetic keys only.
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_wildbloomd");
const KEEPER: &str = "ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";

fn run(extra: &[&str]) -> Output {
    let dir = tempfile::tempdir().expect("temporary directory");
    Command::new(BIN)
        .args(["--no-tor", "--data-dir"])
        .arg(dir.path().join("data"))
        .args(["--bind", "127.0.0.1:0"])
        .args(extra)
        .env_remove("WILDBLOOM_OPEN_SHELTER")
        .output()
        .expect("run wildbloomd")
}

fn refused(extra: &[&str], needle: &str) {
    let output = run(extra);
    assert!(!output.status.success(), "{extra:?} must not start");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(needle), "{extra:?}: {stderr}");
}

#[test]
fn group_mode_refuses_to_start_beside_the_guest_tier_discovery_and_paid_profiles() {
    let keeper = format!("{KEEPER}:1048576");
    let base = ["--group-mode", "--group-keeper", keeper.as_str()];
    for (flag, value, needle) in [
        ("--open-shelter", None, "--open-shelter"),
        (
            "--service-profile",
            Some("/nonexistent/profile.json"),
            "--service-profile",
        ),
        (
            "--checkout-profile",
            Some("/nonexistent/checkout.json"),
            "--checkout-profile",
        ),
    ] {
        let mut args = base.to_vec();
        args.push(flag);
        args.extend(value);
        refused(&args, needle);
    }
    refused(&["--group-mode"], "at least one --group-keeper");
    refused(&["--group-keeper", keeper.as_str()], "--group-mode");
}
