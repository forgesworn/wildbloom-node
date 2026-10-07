#!/usr/bin/env python3
"""Reject unrelated, failed and wrong-source builds before signing authority is used."""
import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release-macos-preview.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ProvenanceTests(unittest.TestCase):
    def test_only_successful_exact_source_manual_preview_is_accepted(self):
        source = "a" * 40
        valid = {"head_sha": source, "conclusion": "success", "status": "completed",
                 "event": "workflow_dispatch", "path": ".github/workflows/desktop-preview.yml",
                 "head_repository": {"full_name": release.REPO}}
        release.verify_run(valid, source)
        for key, value in [("head_sha", "b" * 40), ("conclusion", "failure"),
                           ("status", "in_progress"), ("event", "pull_request"),
                           ("path", ".github/workflows/ci.yml"),
                           ("head_repository", {"full_name": "example/other"})]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                release.verify_run({**valid, key: value}, source)


if __name__ == "__main__":
    unittest.main()
