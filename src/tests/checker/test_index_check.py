#!/usr/bin/env python3
"""Module: index_check_image_tests
Purpose: Verify checking modes and repairs on independently mutated test copies.
Created: 2026-10-01
Architecture: Encodes index and parent damage separately from the checker and
    preserves source hashes; copy and journal tests exercise publication separately.
"""

import argparse
import json
import pathlib
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "tests/support"))
from ntfs_image import CHECKER, attr, attrs, decode, digest, protect, put, u
from test_log_resize import Volume, mapping


def mutate(source, destination, case):
    shutil.copyfile(source, destination)
    volume = Volume(destination)
    try:
        root = volume.record(5)
        allocation = next(at for at, kind in attrs(root) if kind == 0xA0)
        lcn, count = mapping(root, allocation)[0]
        assert count * volume.cluster >= 4096
        offset = lcn * volume.cluster
        volume.file.seek(offset)
        block = decode(volume.file.read(4096))
        cursor = 24 + u(block, 24, 4)
        entries = []
        while not u(block, cursor + 12, 2) & 2:
            entries.append(cursor)
            cursor += u(block, cursor + 8, 2)
        selected = next(
            at for at in entries if u(block, at, 8) & ((1 << 48) - 1) == 6
        )
        key = selected + 16
        if case == "sequence":
            put(block, selected, u(block, selected, 8) + (1 << 48), 8)
        elif case == "name":
            # Keep collation between $BadClus and $Boot while changing the key.

            block[key + 66 + 2 * 2:key + 66 + 3 * 2] = "j".encode("utf-16le")
        elif case == "namespace":
            block[key + 65] = (block[key + 65] + 1) % 4
        elif case == "parent":
            put(block, key, u(block, key, 8) + (1 << 48), 8)
        elif case == "dangling":
            put(block, selected, 63 | (1 << 48), 8)
        elif case == "depleted":
            put(block, selected, u(block, selected, 8) + (1 << 48), 8)
            another = next(
                at for at in entries if u(block, at, 8) & ((1 << 48) - 1) == 7
            )
            put(block, another, 6 | (u(volume.record(6), 16, 2) << 48), 8)
        elif case == "order":
            left, right = entries[:2]
            a, b = u(block, left + 8, 2), u(block, right + 8, 2)
            block[left:left + a + b] = (
                bytes(block[right:right + b]) + bytes(block[left:left + a])
            )
        elif case == "fixup":
            block = protect(block)
            block[510] ^= 1
            volume.file.seek(offset)
            volume.file.write(block)
            return
        else:
            raise AssertionError(case)
        volume.file.seek(offset)
        volume.file.write(protect(block))
    finally:
        volume.close()


def audit(path, *options):
    result = subprocess.run(
        [str(CHECKER), "--json", *options, "--audit", str(path)],
        capture_output=True,
        text=True,
    )
    if result.returncode == 8 and "InvalidFixup" in result.stderr:
        # A failed preflight cannot produce a structured audit report.

        return {
            "complete": False,
            "errors": 1,
            "refused": "InvalidFixup",
            "findings": [],
        }
    assert result.returncode in (0, 4), result.stderr
    return json.loads(result.stdout)


def check_out_of_range_parent(source, destination):
    shutil.copyfile(source, destination)
    volume = Volume(destination)
    try:
        record = volume.record(6)
        filename = attr(record, 0x30)
        value = filename + u(record, filename + 20, 2)
        put(record, value, ((1 << 48) - 1) | (1 << 48), 8)
        volume.save(6, record)
    finally:
        volume.close()
    before = digest(destination)
    reports = {}
    for mode in ("full", "quick"):
        report = audit(destination, f"--index-check={mode}")
        assert any(
            finding["code"] == "invalid-parent-reference"
            and finding["record"] == 6
            for finding in report["findings"]
        ), (mode, report)
        reports[mode] = report
    assert digest(destination) == before
    return {
        "case": "out-of-range-parent",
        "source_sha256": before.hex(),
        "reports": reports,
        "repairs": "not requested",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    original = digest(args.base)
    assert audit(args.base)["errors"] == 0
    summary = []
    for case in (
        "sequence", "name", "namespace", "parent", "dangling", "depleted",
        "order", "fixup",
    ):
        image = args.output / f"{case}.img"
        mutate(args.base, image, case)
        before = digest(image)
        reports = {
            mode: audit(image, f"--index-check={mode}")
            for mode in ("full", "quick")
        }
        assert reports["full"]["errors"] > 0, (case, reports)
        if case in ("sequence", "name", "namespace"):
            assert reports["quick"]["errors"] == 0, (case, reports["quick"])
        else:
            assert reports["quick"]["errors"] > 0, (case, reports["quick"])
        if case == "depleted":
            assert reports["quick"]["index_rechecked_records"] > 0
            assert any(
                finding["code"] == "stale-index-reference"
                for finding in reports["quick"]["findings"]
            )
        expected = sorted(
            (finding["code"], finding["record"], finding["detail"])
            for finding in reports["full"]["findings"]
        )
        for passes in ("0", "1", "7", "auto"):
            report = audit(image, f"--index-cache-passes={passes}")
            actual = sorted(
                (finding["code"], finding["record"], finding["detail"])
                for finding in report["findings"]
            )
            assert actual == expected, (case, passes)
        assert digest(image) == before
        for mode in ("full", "quick"):
            repaired = args.output / f"{case}-{mode}.img"
            result = subprocess.run(
                [
                    str(CHECKER), f"--index-check={mode}", "--repair-to",
                    str(image), str(repaired),
                ],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, (
                case, mode, result.stdout, result.stderr,
            )
            assert audit(repaired, f"--index-check={mode}")["errors"] == 0
            if mode == "quick" and case in ("sequence", "name", "namespace"):
                assert audit(repaired)["errors"] > 0, (
                    "balanced entries must be retained"
                )
            else:
                assert audit(repaired)["errors"] == 0
        assert digest(image) == before
        summary.append({
            "case": case,
            "source_sha256": before.hex(),
            "reports": reports,
            "repairs": "passed",
        })
        print("PASS", case, flush=True)
    summary.append(check_out_of_range_parent(
        args.base, args.output / "out-of-range-parent.img",
    ))
    print("PASS out-of-range-parent", flush=True)
    assert digest(args.base) == original
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
