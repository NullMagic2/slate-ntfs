#!/usr/bin/env python3
"""Module: packaging.tests.mount_helper
Purpose: Verify recovery authorization and fallback through the real shell helper.
Created: 2026-10-02
Architecture: Private subprocess doubles replace host commands; no device is
mounted or repaired. The production helper controls every tested transition.
"""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HELPER = Path(__file__).resolve().parents[1] / "deb" / "mount-ntfs"
DOUBLE = """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["MOUNT_TEST_ROOT"])
name = Path(sys.argv[0]).name
with (root / "calls").open("a") as stream:
    stream.write(json.dumps([name, *sys.argv[1:]]) + "\\n")
scenario = json.loads(os.environ["MOUNT_TEST_SCENARIO"])
if name == "ntfs-run":
    print("sidmap=S-1-5-21-1:1000,visibility=0,compatibility=ntfs")
elif name == "mount":
    counter = root / "mount-count"
    count = int(counter.read_text()) if counter.exists() else 0
    counter.write_text(str(count + 1))
    result = scenario["mounts"][count]
    if result:
        print(result)
        sys.exit(32)
elif name == "ntfs-chkdsk":
    print(scenario.get("recovery_message", "replay completed"))
    sys.exit(scenario.get("recovery_status", 0))
"""


class MountHelperTests(unittest.TestCase):
    def run_helper(self, mounts, options="rw,uid=1000,gid=1000", flags=(), **scenario):
        # Rewrite command locations only in a private copy. Arguments and shell
        # decisions remain production code, including quoted paths with spaces.
        with tempfile.TemporaryDirectory(prefix="slate-mount-policy-") as temporary:
            root = Path(temporary)
            commands = root / "commands"
            commands.mkdir()
            names = ("mount", "ntfs-run", "ntfs-chkdsk", "logger", "dmesg", "modprobe")
            for name in names:
                program = commands / name
                program.write_text(DOUBLE)
                program.chmod(0o700)
            filesystems = root / "filesystems"
            filesystems.write_text("nodev\tntfsrs\n")
            text = HELPER.read_text()
            for original, name in (
                ("/bin/mount", "mount"),
                ("/usr/bin/ntfs-run", "ntfs-run"),
                ("/usr/sbin/ntfs-chkdsk", "ntfs-chkdsk"),
                ("/sbin/modprobe", "modprobe"),
            ):
                text = text.replace(original, str(commands / name))
            text = text.replace("/proc/filesystems", str(filesystems))
            text = text.replace("/sys/module/slate_ntfs/srcversion", str(root / "absent-module"))
            text = text.replace("/usr/lib/slate-ntfs/slate-ntfs-policy", str(root / "absent-policy"))
            helper = root / "helper"
            helper.write_text(text)
            environment = os.environ.copy()
            environment.update(
                PATH=f"{commands}:/usr/bin:/bin",
                MOUNT_TEST_ROOT=str(root),
                MOUNT_TEST_SCENARIO=json.dumps({"mounts": mounts, **scenario}),
            )
            result = subprocess.run(
                [
                    "/bin/sh", str(helper), "/dev/private device",
                    "/media/private drive", "-o", options, *flags,
                ],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
            relevant = [call for call in calls if call[0] in ("mount", "ntfs-chkdsk")]
            return result, relevant

    def test_clean_mount_never_recovers(self):
        result, calls = self.run_helper([None])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[0] for call in calls], ["mount"])

    def test_supported_replay_retries_identical_writable_options(self):
        result, calls = self.run_helper(["dirty volume", None])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[0] for call in calls], ["mount", "ntfs-chkdsk", "mount"])
        self.assertEqual(calls[1], ["ntfs-chkdsk", "--recover-for-mount", "/dev/private device"])
        self.assertEqual(calls[0], calls[2])
        self.assertEqual(calls[0][-2:], ["/dev/private device", "/media/private drive"])
        self.assertIn("retrying writable admission", result.stderr)

    def test_refused_or_interrupted_replay_preserves_readonly_access_and_reason(self):
        reasons = (
            "hibernation blocks replay", "unsupported opcode", "device is busy",
            "I/O error; dirty journal retained",
        )
        for reason in reasons:
            with self.subTest(reason=reason):
                result, calls = self.run_helper(
                    ["dirty volume", None], recovery_status=1, recovery_message=reason,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([call[0] for call in calls], ["mount", "ntfs-chkdsk", "mount"])
                self.assertIn(reason, result.stderr)
                self.assertIn("READ-ONLY", result.stderr)
                self.assertNotIn("rw", calls[-1][5].split(","))
                self.assertIn("ro", calls[-1][5].split(","))

    def test_completed_replay_does_not_override_kernel_refusal(self):
        result, calls = self.run_helper(["dirty volume", "writer admission refused", None])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[0] for call in calls], ["mount", "ntfs-chkdsk", "mount", "mount"])
        self.assertIn("still failed after journal recovery", result.stderr)
        self.assertIn("writer admission refused", result.stderr)
        self.assertIn("ro", calls[-1][5].split(","))

    def test_readonly_and_fake_requests_never_recover_or_fallback(self):
        requests = (
            ("ro,uid=1000", ()), ("ro,rw,uid=1000", ()),
            ("rw,uid=1000", ("-f",)),
        )
        for options, flags in requests:
            with self.subTest(options=options, flags=flags):
                result, calls = self.run_helper(["mount refused"], options, flags)
                self.assertEqual(result.returncode, 32, result.stderr)
                self.assertEqual([call[0] for call in calls], ["mount"])

    def test_live_remounts_and_subviews_never_authorize_offline_recovery(self):
        options = (
            "remount", "bind", "rbind", "move", "loop", "loop=/dev/loop7",
            "offset=512", "sizelimit=4096", "view_readonly",
        )
        for option in options:
            with self.subTest(option=option):
                result, calls = self.run_helper(["mount refused", None], f"rw,{option},uid=1000")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([call[0] for call in calls], ["mount", "mount"])

    def test_failed_readonly_fallback_returns_failure(self):
        result, calls = self.run_helper(
            ["dirty volume", "read-only I/O failure"], recovery_status=1,
        )
        self.assertEqual(result.returncode, 32, result.stderr)
        self.assertIn("read-only I/O failure", result.stderr)
        self.assertEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main()
