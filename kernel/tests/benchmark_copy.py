#!/usr/bin/env python3
"""
Module: kernel.tests.benchmark_copy
Purpose: Summarise cold read and copy samples per environment and driver against NTFS-3G.
Created: 2026-10-05
Architecture: benchmark_copy.sh and the VM benchmark write samples.csv rows; this
script reports medians, ranges and per-round comparisons in Markdown. It measures
nothing itself.
"""

import csv
import statistics
import sys
from collections import defaultdict

# Speeds are decimal megabytes per second, as disk vendors and the README state them.
BYTES_PER_MEGABYTE = 1_000_000
BASELINE_DRIVER = "ntfs-3g"
PERCENT = 100
# How reports name each driver; samples use mount-oriented identifiers.
DRIVER_NAMES = {"ntfsrs": "slate-ntfs", "ntfs": "Linux ntfs"}
OPERATION_NAMES = {"read": "cold read", "copy": "copy to the destination, flushed"}
# Samples written before reads were measured have no operation column.
DEFAULT_OPERATION = "copy"


def read_samples(path):
    # Rows as dictionaries. A shell in a decimal-comma locale writes the
    # seconds as "5,166", which splits that field in two: join it again.

    rows = list(csv.reader(open(path, newline="")))
    fields = rows[0]
    seconds = fields.index("seconds")
    samples = []
    for row in rows[1:]:
        if len(row) == len(fields) + 1:
            row = row[:seconds] + [row[seconds] + "." + row[seconds + 1]] + row[seconds + 2:]
        if len(row) != len(fields):
            sys.exit(f"malformed sample row in {path}: {row}")
        sample = dict(zip(fields, row))
        sample["driver"] = DRIVER_NAMES.get(sample["driver"], sample["driver"])
        sample.setdefault("operation", DEFAULT_OPERATION)
        samples.append(sample)
    return samples


def speed(sample):
    # Megabytes per second of one copy.

    return int(sample["bytes"]) / BYTES_PER_MEGABYTE / float(sample["seconds"])


def compared(value, baseline):
    # "12% slower" or "5% faster" than the baseline speed.

    change = (value / baseline - 1) * PERCENT
    return f"{abs(change):.0f}% {'faster' if change >= 0 else 'slower'}"


def summarise(path):
    samples = read_samples(path)
    for sample in samples:
        if sample["operation"] == "copy" and sample["verified"] != "yes":
            sys.exit(f"unverified copy in round {sample['round']} ({sample['driver']})")
        if int(sample["disk_read_bytes"]) < int(sample["bytes"]):
            sys.exit(f"round {sample['round']} ({sample['driver']}) read less than the file from disk")
    groups = defaultdict(lambda: defaultdict(list))
    for sample in samples:
        groups[(sample["environment"], sample["operation"])][sample["driver"]].append(sample)
    lines = []
    for (environment, operation), drivers in groups.items():
        reference = [speed(s) for s in drivers.get(BASELINE_DRIVER, [])]
        baseline = statistics.median(reference) if reference else None
        lines += [
            f"### {environment}: {OPERATION_NAMES.get(operation, operation)}",
            "",
            "| Driver | Median | Range | Compared with NTFS-3G |",
            "| --- | --- | --- | --- |",
        ]
        for driver, rows in drivers.items():
            speeds = [speed(s) for s in rows]
            median = statistics.median(speeds)
            versus = "baseline" if driver == BASELINE_DRIVER or baseline is None else compared(median, baseline)
            lines.append(f"| {driver} | {median:.0f} MB/s | {min(speeds):.0f} – {max(speeds):.0f} MB/s | {versus} |")
        lines += ["", "| Round | " + " | ".join(drivers) + " |", "| --- |" + " --- |" * len(drivers)]
        rounds = sorted({int(s["round"]) for rows in drivers.values() for s in rows})
        for number in rounds:
            cells = []
            for rows in drivers.values():
                match = [s for s in rows if int(s["round"]) == number]
                cells.append(f"{speed(match[0]):.0f} MB/s ({float(match[0]['seconds']):.2f} s)" if match else "")
            lines.append(f"| {number} | " + " | ".join(cells) + " |")
        lines.append("")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: benchmark_copy.py SAMPLES.csv [MORE.csv ...]")
    for path in sys.argv[1:]:
        print(summarise(path))


if __name__ == "__main__":
    main()
