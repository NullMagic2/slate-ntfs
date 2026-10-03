#!/usr/bin/env python3
"""Module: tests.windows.verify_hibernation_corpus
Purpose: Verify reviewed hibernation fixtures from disposable VM snapshots.
Created: 2026-10-02
Architecture: Checks corpus metadata and expected state; the NTFS inspection tools validate the
captured first pages.

Verify reviewed first-page fixtures from disposable Windows VM snapshots."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

STATES = {"full-shutdown", "fast-startup", "hibernated", "resumed"}
RELEASES = {"Windows10", "Windows11"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=pathlib.Path)
    parser.add_argument("--checker", type=pathlib.Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    seen = set()
    problems = []
    manifests = sorted(args.corpus.glob("*.json"))
    if not manifests:
        problems.append("no Windows fixture manifests found")
    for manifest_path in manifests:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
            release = manifest["windows_release"]
            transition = manifest["expected_transition"]
            expected = manifest["classifier_expected"]
            if manifest["origin"] != "disposable-windows-vm-snapshot" or not manifest["volume_read_only"]:
                raise ValueError("fixture is not a read-only disposable Windows VM snapshot")
            if release not in RELEASES or transition not in STATES:
                raise ValueError("unknown Windows release or transition")
            if not expected:
                raise ValueError("classifier_expected has not been independently reviewed")
            key = (release, transition)
            if key in seen:
                raise ValueError("duplicate Windows release and transition")
            seen.add(key)
            if manifest["hibernation_file_present"]:
                page_name = pathlib.Path(manifest["page_file"])
                if page_name.name != str(page_name):
                    raise ValueError("page_file must be a basename")
                page_path = manifest_path.parent / page_name
                page = page_path.read_bytes()
                if len(page) != 4096:
                    raise ValueError("page sample is not 4096 bytes")
                digest = hashlib.sha256(page).hexdigest()
                if digest != manifest["page_sha256"].lower():
                    raise ValueError("page SHA-256 mismatch")
                run = subprocess.run(
                    [str(args.checker), "--hibernation-page", str(page_path)],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                observed = run.stdout.strip().removeprefix("hibernation_state=")
            else:
                if manifest.get("page_file") or manifest.get("page_sha256"):
                    raise ValueError("absent file must not include a page sample")
                observed = "absent"
            if observed != expected:
                raise ValueError(f"expected {expected}, observed {observed}")
            print(f"{release} {transition}: {observed}")
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            problems.append(f"{manifest_path.name}: {exc}")
    if args.require_complete:
        missing = sorted((release, state) for release in RELEASES for state in STATES if (release, state) not in seen)
        problems.extend(f"missing {release} {state}" for release, state in missing)
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
