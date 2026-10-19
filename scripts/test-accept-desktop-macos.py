#!/usr/bin/env python3
"""Ensure refusal paths cannot mount images, launch apps or touch existing state."""

import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("acceptance", Path(__file__).with_name("accept-desktop-macos.py"))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class RefusalTests(unittest.TestCase):
    def test_upgrade_rejects_reinstall_downgrade_and_invalid_versions(self):
        for baseline, candidate in [("0.3.3", "0.3.3"), ("0.3.4", "0.3.3"),
                                    ("0.3.3", "0.3.4-preview.1"), ("0.3.3", "00.3.4")]:
            with self.subTest(baseline=baseline, candidate=candidate), self.assertRaises(RuntimeError):
                acceptance.verify_upgrade(baseline, candidate)
        acceptance.verify_upgrade("0.3.3", "0.3.4")
        acceptance.verify_upgrade("0.9.9", "0.10.0")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.input = self.root / "input.dmg"
        self.input.write_bytes(b"synthetic test input, never mounted")
        self.hash = hashlib.sha256(self.input.read_bytes()).hexdigest()
        self.output = self.root / "evidence.json"
        self.profile = self.root / "Library/Application Support" / acceptance.IDENTIFIER
        self.args = ["acceptance", "--baseline", str(self.input), "--baseline-sha256", self.hash,
                     "--candidate", str(self.input), "--candidate-sha256", self.hash,
                     "--output", str(self.output), "--allow-current-account"]

    def refuses(self, reason):
        with patch.object(sys, "argv", self.args), patch.object(acceptance.platform, "system", return_value="Darwin"), \
                patch.object(acceptance.Path, "home", return_value=self.root), \
                patch.object(acceptance, "run", side_effect=AssertionError("must not run external commands")):
            with self.assertRaisesRegex(RuntimeError, reason):
                acceptance.main()

    def test_tampered_input(self):
        self.input.write_bytes(b"changed bytes")
        self.refuses("checksum mismatch")
        self.assertFalse(self.profile.exists())
        self.assertFalse(self.output.exists())

    def test_existing_profile_is_preserved(self):
        self.profile.mkdir(parents=True)
        sentinel = self.profile / "settings.json"
        sentinel.write_bytes(b"existing operator state")
        self.refuses("existing Wildbloom profile")
        self.assertEqual(sentinel.read_bytes(), b"existing operator state")
        self.assertFalse(self.output.exists())

    def test_dangling_profile_symlink_is_preserved(self):
        self.profile.parent.mkdir(parents=True)
        self.profile.symlink_to(self.root / "absent")
        self.refuses("existing Wildbloom profile")
        self.assertTrue(self.profile.is_symlink())

    def test_existing_evidence_is_preserved(self):
        self.output.write_bytes(b"previous evidence")
        self.refuses("evidence output already exists")
        self.assertEqual(self.output.read_bytes(), b"previous evidence")

    def test_account_opt_in_is_required(self):
        self.args.remove("--allow-current-account")
        self.refuses("explicitly pass")
        self.assertFalse(self.profile.exists())


class StaplerOutputTests(unittest.TestCase):
    """A failed ticket check shows stapler's error lines and nothing else."""

    def test_a_failure_shows_only_stapler_error_lines(self):
        script = ("print('Processing: sample.dmg'); print('abcdef.onion'); "
                  "print('error is Error Domain=NSURLErrorDomain Code=-1005'); "
                  "print('The validate action failed! Error 68.'); raise SystemExit(68)")
        with patch("builtins.print") as shown, self.assertRaisesRegex(RuntimeError, r"exit 68"):
            acceptance.run(sys.executable, "-c", script, show=acceptance.stapler_error)
        self.assertEqual([call.args[0] for call in shown.call_args_list],
                         ["error is Error Domain=NSURLErrorDomain Code=-1005",
                          "The validate action failed! Error 68."])

    def test_success_and_unfiltered_failures_show_nothing(self):
        with patch("builtins.print") as shown:
            acceptance.run(sys.executable, "-c", "print('error is fine')", show=acceptance.stapler_error)
            with self.assertRaises(RuntimeError):
                acceptance.run(sys.executable, "-c", "print('error is hidden'); raise SystemExit(1)")
        shown.assert_not_called()


if __name__ == "__main__":
    unittest.main()
