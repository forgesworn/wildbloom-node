#!/usr/bin/env python3
"""Sign a checksum-pinned preview using local Keychain authority, without exports.

Produces local candidates only. Never publishes or enables automatic updates.
Requires macOS, Xcode command-line tools and a validated notarytool profile.
"""

import argparse
import hashlib
import json
import platform
import plistlib
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(*args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stdout}\n{result.stderr}")
    return result.stdout + result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--keychain", type=Path)
    parser.add_argument("--output", required=True, type=Path,
                        help="New directory; existing output is never overwritten")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("macOS is required")
    if not re.fullmatch(r"[a-f0-9]{64}", args.sha256):
        parser.error("--sha256 must be the independently verified input digest")
    if not re.fullmatch(r"[a-f0-9]{40}", args.source_commit):
        parser.error("--source-commit must be the full preview build commit")
    if not args.identity.startswith("Developer ID Application: "):
        parser.error("a Developer ID Application identity is required")
    args.input = args.input.resolve(strict=True)
    args.output = args.output.resolve()
    if digest(args.input) != args.sha256:
        parser.error("input checksum mismatch")
    auth = ["--keychain-profile", args.profile]
    if args.keychain:
        auth += ["--keychain", str(args.keychain.resolve(strict=True))]
    # Validate without printing submission history or credential values.
    run("xcrun", "notarytool", "history", *auth, "--output-format", "json")
    args.output.mkdir(mode=0o700)
    evidence = {
        "input": args.input.name, "input_sha256": args.sha256,
        "source_commit": args.source_commit, "signing_identity": args.identity,
        "team_id": args.team_id, "started_at": datetime.now(timezone.utc).isoformat(),
        "script_sha256": digest(Path(__file__)), "passed": False,
        "scope": "Local Developer ID signing and Apple notarisation; no updater signature, publication or clean-machine acceptance",
    }

    def save():
        (args.output / "signing-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")

    def notarize(path, label):
        submission = json.loads(run("xcrun", "notarytool", "submit", path,
                                    *auth, "--output-format", "json"))
        evidence[label] = {"id": submission["id"], "submitted_sha256": digest(path)}
        save()
        print(f"{label}: submitted {submission['id']}", flush=True)
        deadline = time.monotonic() + 1800
        while True:
            info = json.loads(run("xcrun", "notarytool", "info", submission["id"],
                                  *auth, "--output-format", "json"))
            evidence[label]["status"] = info["status"]
            save()
            if info["status"] != "In Progress":
                run("xcrun", "notarytool", "log", submission["id"], *auth,
                    args.output / f"{label}-notary-log.json")
                if info["status"] != "Accepted":
                    raise RuntimeError(f"Apple rejected {label}; see retained notary log")
                print(f"{label}: Accepted", flush=True)
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("Apple submission still pending; retained ID can be checked with notarytool info")
            time.sleep(20)

    save()
    mount = args.output / "input-mount"
    mount.mkdir()
    stage = args.output / "staging"
    stage.mkdir()
    app = stage / "Wildbloom Node.app"
    try:
        run("hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", mount, args.input)
        try:
            original = mount / app.name
            run("codesign", "--verify", "--deep", "--strict", original)
            run("ditto", original, app)
        finally:
            run("hdiutil", "detach", mount)
        mount.rmdir()
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        if info["CFBundleIdentifier"] != "dev.forgesworn.wildbloom-node":
            raise RuntimeError("unexpected app identifier")
        evidence["version"] = info["CFBundleShortVersionString"]
        macho = []
        for path in sorted(app.rglob("*")):
            if path.is_symlink():
                if not path.resolve().is_relative_to(app):
                    raise RuntimeError("external app symlink refused")
                continue
            if path.is_file() and "Mach-O" in run("file", "-b", path):
                macho.append(path)
        if not macho:
            raise RuntimeError("no bundled Mach-O code")
        evidence["signed_code"] = [str(p.relative_to(app)) for p in macho]
        # Explicit inside-out signing, including transport helpers and dylibs.
        for path in [*macho, app]:
            run("codesign", "--force", "--options", "runtime", "--timestamp",
                "--sign", args.identity, path)
            run("codesign", "--verify", "--strict", path)
            details = run("codesign", "-d", "--verbose=4", path)
            if f"TeamIdentifier={args.team_id}" not in details.splitlines():
                raise RuntimeError("unexpected signing team")
            if "(runtime)" not in details or "Timestamp=" not in details:
                raise RuntimeError("hardened runtime or secure timestamp missing")
        run("codesign", "--verify", "--deep", "--strict", app)
        archive = args.output / "notary-app.zip"
        run("ditto", "-c", "-k", "--keepParent", app, archive)
        notarize(archive, "app")
        run("xcrun", "stapler", "staple", app)
        run("xcrun", "stapler", "validate", app)
        run("spctl", "--assess", "--type", "execute", "--verbose=2", app)
        (stage / "Applications").symlink_to("/Applications")
        dmg = args.output / (args.input.stem + "-signed.dmg")
        run("hdiutil", "create", "-volname", "Wildbloom Node", "-srcfolder", stage,
            "-format", "UDZO", "-fs", "HFS+", dmg)
        run("codesign", "--sign", args.identity, "--timestamp", dmg)
        notarize(dmg, "dmg")
        run("xcrun", "stapler", "staple", dmg)
        run("xcrun", "stapler", "validate", dmg)
        run("codesign", "--verify", "--strict", dmg)
        run("spctl", "--assess", "--type", "open", "--context", "context:primary-signature", "--verbose=2", dmg)
        evidence.update({"passed": True, "output": dmg.name, "output_sha256": digest(dmg),
                         "finished_at": datetime.now(timezone.utc).isoformat()})
        (args.output / "SHA256SUMS").write_text(f"{digest(dmg)}  {dmg.name}\n")
        print(f"Verified signed and stapled candidate: {dmg}", flush=True)
    finally:
        save()


if __name__ == "__main__":
    main()
