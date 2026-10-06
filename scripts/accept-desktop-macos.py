#!/usr/bin/env python3
"""Exercise real DMGs in a fresh macOS profile; never use production test hooks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import urllib.request


IDENTIFIER = "dev.forgesworn.wildbloom-node"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args, timeout=60):
    # Captured output can contain ephemeral onion addresses. Never echo it.
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=timeout)
    require(result.returncode == 0, f"{Path(args[0]).name} failed (exit {result.returncode})")
    return result.stdout.decode() + result.stderr.decode()


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify_input(path, expected):
    require(re.fullmatch(r"[0-9a-f]{64}", expected), "expected an exact SHA-256")
    require(path.is_file() and digest(path) == expected, "DMG checksum mismatch")


def processes():
    rows = {}
    for line in run("/bin/ps", "-axww", "-o", "pid=,ppid=,command=").splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3:
            rows[int(parts[0])] = (int(parts[1]), parts[2])
    return rows


def descendants(pid):
    rows = processes()
    found = {pid}
    while True:
        more = {p for p, (parent, _) in rows.items() if parent in found}
        if more <= found:
            return {p: rows[p][1] for p in found - {pid} if p in rows}
        found |= more


def until(check, message, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(1)
    raise RuntimeError(message)


def private_file(path):
    require(path.is_file() and stat.S_IMODE(path.stat().st_mode) == 0o600,
            "runtime state file is missing or has unsafe permissions")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--baseline-sha256", required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-current-account", action="store_true",
                        help="explicitly permit disposable state in this account; existing state is always refused")
    parser.add_argument("--candidate-adhoc", action="store_true",
                        help="preview build only: check code signatures without claiming Developer ID trust")
    args = parser.parse_args()
    require(platform.system() == "Darwin", "macOS is required")
    # Validate both inputs before any app/profile mutation.
    verify_input(args.baseline, args.baseline_sha256)
    verify_input(args.candidate, args.candidate_sha256)
    require(args.allow_current_account, "use a disposable account and explicitly pass --allow-current-account")
    require(not args.output.exists(), "evidence output already exists")
    profile = Path.home() / "Library/Application Support" / IDENTIFIER
    require(not os.path.lexists(profile), "existing Wildbloom profile: refusing to modify it")
    require(not any("/Wildbloom Node.app/Contents/MacOS/" in command
                    for _, command in processes().values()), "Wildbloom is already running")
    evidence = {
        "schema": 1, "passed": False, "platform": platform.platform(),
        "architecture": platform.machine(), "harness_commit": os.environ.get("GITHUB_SHA"),
        "baseline_sha256": args.baseline_sha256, "candidate_sha256": args.candidate_sha256,
        "candidate_trust": "ad-hoc preview" if args.candidate_adhoc else "Developer ID and notarisation",
        "checks": [],
        "limits": ["No physical reboot or login-item test", "No visual/UI interaction acceptance",
                   "No updater feed or automatic-update acceptance", "No independent physical-device acceptance"],
    }
    app_process = None
    owned_children = set()
    profile_owned = False
    # Tauri deliberately refuses sidecars launched through a symlinked parent.
    # macOS temporary directories commonly begin with /var -> /private/var.
    work = Path(tempfile.mkdtemp(prefix="wildbloom-macos-install-")).resolve()
    installed = work / "Applications/Wildbloom Node.app"
    log_path = work / "app.log"
    log_file = None

    def passed(label):
        evidence["checks"].append(label)
        print(label, flush=True)

    def alive():
        require(app_process.poll() is None, "installed desktop exited unexpectedly")
        return True

    def children():
        result = descendants(app_process.pid)
        owned_children.update(result)
        return result

    def launch():
        nonlocal app_process, log_file
        log_file = log_path.open("wb")
        app_process = subprocess.Popen([str(installed / "Contents/MacOS/wildbloom-desktop")],
                                       stdout=log_file, stderr=subprocess.STDOUT)

    def stop():
        nonlocal app_process, log_file
        alive()
        children()
        # A normal application quit exercises Tauri's exit cleanup, unlike killing the tree.
        path_literal = json.dumps(str(installed))
        run("/usr/bin/osascript", "-e", f"tell application {path_literal} to quit", timeout=30)
        require(app_process.wait(timeout=30) == 0, "desktop did not quit cleanly")
        until(lambda: not (owned_children & processes().keys()),
              "bundled children survived normal app quit", timeout=30)
        app_process = None
        log_file.close()
        log_file = None

    def install(dmg, adhoc=False):
        mount = work / "mount"
        mount.mkdir()
        attached = False
        try:
            if not adhoc:
                run("xcrun", "stapler", "validate", dmg)
                run("spctl", "--assess", "--type", "open", "--context", "context:primary-signature", dmg)
            run("hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", mount, dmg)
            attached = True
            source = mount / "Wildbloom Node.app"
            info = plistlib.loads((source / "Contents/Info.plist").read_bytes())
            require(info["CFBundleIdentifier"] == IDENTIFIER, "unexpected bundle identifier")
            run("codesign", "--verify", "--deep", "--strict", source)
            if not adhoc:
                run("spctl", "--assess", "--type", "execute", source)
                run("xcrun", "stapler", "validate", source)
            binary = source / "Contents/MacOS/wildbloom-desktop"
            require(platform.machine() in run("lipo", "-archs", binary).split(), "DMG is not native to this host")
            if installed.exists():
                shutil.rmtree(installed)
            installed.parent.mkdir(exist_ok=True)
            run("ditto", source, installed)
            run("codesign", "--verify", "--deep", "--strict", installed)
            daemon = installed / "Contents/MacOS/wildbloomd"
            require("--receipt-id" in run(daemon, "replicas", "pool-inspect", "--help"), "missing pool inspection")
            require("--stop-on-stdin" in run(daemon, "replicas", "pool-repair", "--help"), "missing owner repair")
            tor = installed / "Contents/Resources/tor-runtime/tor/tor"
            require("Tor version" in run(tor, "--version"), "bundled Tor cannot execute")
            return info["CFBundleShortVersionString"]
        finally:
            if attached:
                run("hdiutil", "detach", mount)
            mount.rmdir()

    settings_path = profile / "settings.json"
    database = profile / "node/wildbloom.sqlite3"
    onion_root = profile / "node/tor/onion-service"
    settings = {"allowedPubkey": "a" * 64, "friendGrants": [], "openShelter": False,
                "quotaGib": 3, "startAtLogin": False, "transport": "direct",
                "directPort": 0, "directPublicUrl": None}

    def save_settings(mode):
        settings["transport"] = mode
        settings_path.write_text(json.dumps(settings))
        settings_path.chmod(0o600)

    def ready(mode):
        diagnostic = {}
        def check():
            alive()
            running = children()
            daemons = [c for c in running.values() if "/wildbloomd --bind " in c]
            tors = [c for c in running.values() if "/tor-runtime/tor/tor " in c]
            diagnostic.update(children=len(running), daemons=len(daemons), tor_processes=len(tors),
                              phases=re.findall(r"runtime phase: ([a-z]+):", log_path.read_text()))
            errors = re.findall(r"runtime phase: error: ([^\n]+)", log_path.read_text())
            if errors:
                diagnostic["startup_errors"] = [re.sub(r"[a-z2-7]{56}\.onion", "[onion]", error)
                                                .replace(str(Path.home()), "[home]") for error in errors]
                raise RuntimeError("installed desktop reported a startup error")
            if mode == "direct":
                require(not tors and not (profile / "node/tor").exists(), "direct mode started Tor")
            if len(daemons) != 1 or (mode == "tor" and len(tors) != 1):
                return False
            require("--allow-pubkey " + "a" * 64 in daemons[0], "writer setting was not honoured")
            match = re.search(r"--bind 127\.0\.0\.1:(\d+)", daemons[0])
            if not match:
                return False
            try:
                # Never consult ambient proxy settings for the loopback health check.
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(f"http://127.0.0.1:{match[1]}/healthz", timeout=2) as response:
                    health = json.load(response)["storage"]
                diagnostic["health"] = {key: health.get(key) for key in ("blobs", "bytes", "quota_bytes")}
                return health["blobs"] == 0 and health["bytes"] == 0 and health["quota_bytes"] == 3 * 1024**3
            except (OSError, ValueError, KeyError) as error:
                diagnostic["health_error"] = type(error).__name__
                return False
        try:
            until(check, f"{mode} mode did not reach bundled-service readiness", timeout=900 if mode == "tor" else 60)
        except RuntimeError:
            evidence["readiness_diagnostic"] = diagnostic
            print(json.dumps(diagnostic), flush=True)
            raise
        private_file(database)

    try:
        # First-install checks must exercise the candidate, not merely the old baseline.
        evidence["candidate_version"] = install(args.candidate, args.candidate_adhoc)
        # Atomic creation is the ownership boundary for all subsequent profile cleanup.
        profile.mkdir(mode=0o700)
        profile_owned = True
        launch()
        until(lambda: alive() and "runtime phase: setup:" in log_path.read_text(),
              "fresh installation did not reach explicit transport setup")
        for _ in range(3):
            require(not children(), "fresh installation started a runtime before consent")
            time.sleep(1)
        stop()
        passed("Fresh installed app waits for explicit transport choice")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            settings["directPort"] = listener.getsockname()[1]
        save_settings("direct")
        launch()
        ready("direct")
        stop()
        passed("Installed direct mode honours quota/writer settings and starts no Tor")
        # The baseline must create its own database; do not accidentally test a downgrade.
        shutil.rmtree(profile)
        profile_owned = False
        profile.mkdir(mode=0o700)
        profile_owned = True
        evidence["baseline_version"] = install(args.baseline)
        save_settings("tor")
        launch()
        ready("tor")
        private_file(onion_root / "hs_ed25519_secret_key")
        require(re.fullmatch(r"[a-z2-7]{56}\.onion\s*", (onion_root / "hostname").read_text()), "invalid onion identity")
        stop()
        identity = {name: digest(onion_root / name) for name in ("hostname", "hs_ed25519_secret_key", "hs_ed25519_public_key")}
        settings_digest = digest(settings_path)
        passed("Installed Tor mode reaches Blossom readiness and keeps private state at 0600")
        require(install(args.candidate, args.candidate_adhoc) == evidence["candidate_version"],
                "candidate version changed during acceptance")
        evidence["replacement_kind"] = ("same-version reinstall" if evidence["baseline_version"] == evidence["candidate_version"] else "cross-version replacement")
        require(digest(settings_path) == settings_digest, "bundle replacement changed settings")
        launch()
        ready("tor")
        stop()
        require(digest(settings_path) == settings_digest, "replacement app changed settings")
        for name, expected in identity.items():
            require(digest(onion_root / name) == expected, "replacement app changed onion identity")
        private_file(settings_path)
        private_file(onion_root / "hs_ed25519_secret_key")
        passed("Replacement app restarts with unchanged settings and onion key/hostname")
        passed("Normal app quits stop all observed bundled children")
        shutil.rmtree(installed)
        require(not installed.exists() and database.is_file(), "app removal did not preserve operator data")
        require(digest(settings_path) == settings_digest, "app removal changed settings")
        for name, expected in identity.items():
            require(digest(onion_root / name) == expected, "app removal changed onion identity")
        passed("Removing installed app preserves operator settings, database and onion identity")
        evidence["passed"] = True
    finally:
        if app_process is not None and app_process.poll() is None:
            children()
            app_process.kill()
            app_process.wait(timeout=10)
        # Kill only surviving PIDs whose command still belongs to our unique install/profile.
        for pid, (_, command) in processes().items():
            if pid in owned_children and (str(work) in command or str(profile) in command):
                try:
                    os.kill(pid, 9)
                except ProcessLookupError:
                    pass
        if log_file:
            log_file.close()
        if profile_owned:
            shutil.rmtree(profile)
        shutil.rmtree(work)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
