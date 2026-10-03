#!/usr/bin/env python3
"""
Module: src.tests.hibernation.test_hibernation_corpus_tool
Purpose: Synthetic smoke test for the fixture verifier, not Windows evidence.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Synthetic smoke test for the fixture verifier, not Windows evidence.
"""

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
CHECKER = ROOT / "target/release/ntfs-chkdsk"
VERIFIER = ROOT / "tests/windows/verify_hibernation_corpus.py"

with tempfile.TemporaryDirectory() as directory:
    corpus = pathlib.Path(directory)
    page = b"HIBR" + bytes(4092)
    (corpus / "synthetic.page.bin").write_bytes(page)
    manifest = {
        "origin": "disposable-windows-vm-snapshot",
        "volume_read_only": True,
        "windows_release": "Windows11",
        "expected_transition": "hibernated",
        "classifier_expected": "active-image",
        "hibernation_file_present": True,
        "page_file": "synthetic.page.bin",
        "page_sha256": hashlib.sha256(page).hexdigest(),
    }
    manifest_path = corpus / "synthetic.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    command = [sys.executable, str(VERIFIER), str(corpus), "--checker", str(CHECKER)]
    assert subprocess.run(command, capture_output=True).returncode == 0
    assert subprocess.run(command + ["--require-complete"], capture_output=True).returncode != 0
    (corpus / "synthetic.page.bin").write_bytes(bytes(4096))
    assert subprocess.run(command, capture_output=True).returncode != 0
print("Hibernation corpus verifier smoke test passed; no Windows evidence asserted.")
