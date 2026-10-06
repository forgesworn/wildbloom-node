#!/usr/bin/env python3
"""Fetch the checksum-pinned signed baseline and test a DMG (or baseline reinstall)."""

import argparse
import hashlib
from pathlib import Path
import platform
import subprocess
import sys
import tempfile


BASELINES = {
    "arm64": ("aarch64", "d03616835df7c5fce531c8429c40a57733562f948f4a472e6802ec713acf743d"),
    "x86_64": ("x64", "255b02b6dbb3dee1560b12a4d1298ac91f3b967a08a2c41670ac720cf1231520"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, help="built bundle directory; omit to reinstall the signed baseline")
    parser.add_argument("--candidate-adhoc", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() not in BASELINES:
        parser.error("a native supported Mac is required")
    if args.candidate_adhoc and args.bundle is None:
        parser.error("ad-hoc mode requires a preview bundle")
    candidate = None
    if args.bundle:
        candidates = list(args.bundle.rglob("*.dmg"))
        if len(candidates) != 1:
            parser.error("expected exactly one candidate DMG")
        candidate = candidates[0].resolve()
    arch, expected = BASELINES[platform.machine()]
    filename = f"Wildbloom.Node_0.3.3_{arch}-signed.dmg"
    url = f"https://github.com/forgesworn/wildbloom-node/releases/download/v0.3.3-preview.2/{filename}"
    with tempfile.TemporaryDirectory(prefix="wildbloom-macos-baseline-") as directory:
        baseline = Path(directory) / filename
        # Use macOS's system TLS trust store, including when Python came from python.org.
        subprocess.run(["/usr/bin/curl", "--fail", "--silent", "--show-error", "--location",
                        "--proto", "=https", "--proto-redir", "=https", "--max-time", "180",
                        "--output", str(baseline), url], check=True)
        candidate = candidate or baseline
        with candidate.open("rb") as source:
            candidate_digest = hashlib.file_digest(source, "sha256").hexdigest()
        command = [sys.executable, str(Path(__file__).with_name("accept-desktop-macos.py")),
                   "--baseline", str(baseline), "--baseline-sha256", expected,
                   "--candidate", str(candidate), "--candidate-sha256", candidate_digest,
                   "--allow-current-account", "--output", str(args.output)]
        if args.candidate_adhoc:
            command.append("--candidate-adhoc")
        subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
