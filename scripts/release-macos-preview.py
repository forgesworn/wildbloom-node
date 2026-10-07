#!/usr/bin/env python3
"""Turn a successful, exact-source CI preview into signed Mac release candidates.

Uses the local Keychain; never exports credentials or publishes a release.
Requires an explicit source SHA and an empty output directory. Run from the
matching clean checkout. Outputs can then be reviewed and uploaded to a draft.
"""

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import tomllib
from pathlib import Path


REPO = "forgesworn/wildbloom-node"
TARGETS = {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}


def capture(*command):
    return subprocess.check_output(command, text=True).strip()


def run(*command):
    subprocess.run([str(part) for part in command], check=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_run(info, source):
    if (info.get("head_sha") != source or info.get("conclusion") != "success"
            or info.get("status") != "completed" or info.get("event") != "workflow_dispatch"
            or info.get("path") != ".github/workflows/desktop-preview.yml"
            or info.get("head_repository", {}).get("full_name") != REPO):
        raise RuntimeError("expected a successful manual preview run from the exact repository and source SHA")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--keychain", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-current-account", action="store_true",
                        help="run native upgrade acceptance using disposable state; existing state is refused")
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() not in TARGETS:
        parser.error("a supported native Mac is required")
    if not re.fullmatch(r"[a-f0-9]{40}", args.source_commit) or args.run_id <= 0:
        parser.error("exact source SHA and positive run ID required")
    if not args.allow_current_account:
        parser.error("native upgrade acceptance requires --allow-current-account")
    root = Path(__file__).resolve().parent.parent
    if capture("git", "-C", str(root), "rev-parse", "HEAD") != args.source_commit:
        parser.error("checkout must match the build source")
    if capture("git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"):
        parser.error("tracked source must be clean")
    info = json.loads(capture("gh", "api", f"repos/{REPO}/actions/runs/{args.run_id}"))
    verify_run(info, args.source_commit)
    version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700)
    manifest = {"schema": 1, "passed": False, "source_commit": args.source_commit,
                "build_run": info["html_url"], "build_attempt": info["run_attempt"], "version": version,
                "signing_script_sha256": digest(root / "scripts/notarize-macos-preview.py"),
                "candidates": {}, "limits": ["No automatic updater acceptance", "No physical reboot acceptance"]}

    def save():
        (args.output / "macos-release-evidence.json").write_text(json.dumps(manifest, indent=2) + "\n")

    save()
    try:
        for architecture, target in TARGETS.items():
            downloaded = args.output / f"input-{architecture}"
            run("gh", "run", "download", str(args.run_id), "--repo", REPO,
                "--name", f"wildbloom-node-{target}-unsigned-preview", "--dir", downloaded)
            images = list(downloaded.rglob("*.dmg"))
            if len(images) != 1:
                raise RuntimeError("expected exactly one DMG in build artifact")
            signed = args.output / f"signed-{architecture}"
            command = [sys.executable, root / "scripts/notarize-macos-preview.py",
                       "--input", images[0], "--sha256", digest(images[0]),
                       "--source-commit", args.source_commit, "--identity", args.identity,
                       "--team-id", args.team_id, "--profile", args.profile, "--output", signed,
                       "--expected-version", version, "--expected-architecture", architecture]
            if args.keychain:
                command += ["--keychain", args.keychain]
            run(*command)
            evidence = json.loads((signed / "signing-evidence.json").read_text())
            if not evidence["passed"] or evidence["version"] != version:
                raise RuntimeError("signed candidate version differs from source")
            manifest["candidates"][architecture] = evidence
            save()
        native = args.output / f"signed-{platform.machine()}"
        run(sys.executable, root / "scripts/accept-desktop-macos-bundle.py", "--bundle", native,
            "--require-upgrade", "--output", args.output / "macos-install.json")
        acceptance = json.loads((args.output / "macos-install.json").read_text())
        if not acceptance["passed"] or acceptance["candidate_version"] != version:
            raise RuntimeError("native upgrade acceptance failed")
        manifest["native_upgrade"] = acceptance
        manifest["passed"] = True
        (args.output / "SHA256SUMS").write_text("".join(
            f"{item['output_sha256']}  {item['output']}\n" for item in manifest["candidates"].values()))
    finally:
        save()
    print(f"Signed Mac candidates and native upgrade verified: {args.output}")


if __name__ == "__main__":
    main()
