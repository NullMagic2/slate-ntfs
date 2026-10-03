#!/usr/bin/env python3
# Module: semantic_duplication_tools.build
# Purpose: Build the CodeGraph exporter without joining Slate's workspace.
# Created: 2026-10-03
# Architecture: Generates a local Cargo project; the supplied CodeGraph crate
# remains an external path dependency; Cargo manages its existing registry cache.

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description="Build the CodeGraph JSON exporter")
    parser.add_argument("--codegraph", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    codegraph = arguments.codegraph.resolve()
    if not (codegraph / "Cargo.toml").is_file():
        parser.error("--codegraph must name the extracted CodeGraph crate directory")
    tool = Path(__file__).resolve().parent
    target = tool / "target"
    project = target / "exporter"
    project.mkdir(parents=True, exist_ok=True)
    manifest = project / "Cargo.toml"
    manifest.write_text(
        "[package]\nname = \"semantic-duplication-exporter\"\n"
        "version = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n"
        "[dependencies]\ncodegraph = { path = "
        + json.dumps(str(codegraph), ensure_ascii=False)
        + " }\nserde_json = \"1\"\n\n[[bin]]\nname = \"extract\"\npath = "
        + json.dumps(str(tool / "extract.rs"), ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(target / "cargo-target")
    command = ["cargo", "build", "--manifest-path", str(manifest)]
    if arguments.offline:
        command.append("--offline")
    subprocess.run(command, env=environment, check=True, stdout=sys.stderr)
    print(target / "cargo-target" / "debug" / "extract")


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"build: {error}", file=sys.stderr)
        sys.exit(1)
