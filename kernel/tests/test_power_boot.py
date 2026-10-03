#!/usr/bin/env python3
"""
Module: kernel.tests.test_power_boot
Purpose: Exercise a retained Ubuntu NTFS root through suspend and hibernation.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Exercise a retained Ubuntu NTFS root through suspend and hibernation.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def run(*args):
    subprocess.run(args, check=True)


def configure(image, repo, mode):
    with tempfile.TemporaryDirectory(prefix="slate-power-mount-") as mount:
        run("ntfs-3g", "-o", "permissions", str(image), mount)
        try:
            root = Path(mount)
            (root / "etc/systemd/system/multi-user.target.wants/slate-root-proof.service").unlink(missing_ok=True)
            run("install", "-D", "-m", "0755", str(repo / "kernel/tests/power_boot_guest"),
                str(root / "usr/local/sbin/power_boot_guest"))
            run("install", "-D", "-m", "0644", str(repo / "kernel/tests/power_boot_guest.service"),
                str(root / "etc/systemd/system/power_boot_guest.service"))
            link = root / "etc/systemd/system/multi-user.target.wants/power_boot_guest.service"
            if not link.exists() and not link.is_symlink():
                link.symlink_to("../power_boot_guest.service")
            run("install", "-D", "-m", "0755", str(repo / "boot/systemd/system-shutdown/ntfsrs"),
                str(root / "lib/systemd/system-shutdown/ntfsrs"))
            (root / "power-mode").write_text(mode + "\n")
            run("sync")
        finally:
            run("umount", mount)


def qmp_wakeup(process, path):
    deadline = time.monotonic() + 60
    while not path.exists() and time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("QEMU exited before QMP became available")
        time.sleep(0.1)
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(20)
        client.connect(str(path))
        stream = client.makefile("rwb", buffering=0)
        json.loads(stream.readline())
        stream.write(b'{"execute":"qmp_capabilities"}\n')
        while "return" not in json.loads(stream.readline()):
            pass
        while True:
            event = json.loads(stream.readline())
            if event.get("event") == "SUSPEND":
                stream.write(b'{"execute":"system_wakeup"}\n')
                while True:
                    reply = json.loads(stream.readline())
                    if "error" in reply:
                        raise RuntimeError(f"QEMU wakeup failed: {reply['error']}")
                    if "return" in reply:
                        return


def boot(kernel, initrd, image, swap, mode, pass_number):
    log = Path(f"{image}.{mode}-{pass_number}.log")
    qmp = Path(f"{image}.qmp")
    qmp.unlink(missing_ok=True)
    command = ["qemu-system-x86_64", "-machine", "pc,accel=kvm:tcg", "-cpu", "max",
               "-m", "1024", "-smp", "2", "-display", "none", "-monitor", "none",
               "-no-reboot", "-kernel", str(kernel), "-initrd", str(initrd),
               "-append", "console=ttyS0,115200 ignore_loglevel no_console_suspend panic=-1 root=/dev/sda "
                          "rootfstype=ntfsrs "
                          "rootflags=compatibility=linux,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18 " +
                          ("resume=/dev/sdb ro" if mode == "hibernate-shutdown" else "noresume ro"),
               "-drive", f"file={image},if=ide,index=0,format=raw,cache=none",
               "-drive", f"file={swap},if=ide,index=1,format=raw,cache=none",
               "-qmp", f"unix:{qmp},server=on,wait=off"]
    with log.open("wb") as output:
        process = subprocess.Popen(command + ["-serial", "stdio"], stdout=output, stderr=subprocess.STDOUT)
        try:
            if mode == "suspend":
                qmp_wakeup(process, qmp)
            process.wait(timeout=40 if mode == "suspend" else 150)
        except Exception:
            process.kill()
            process.wait()
            raise
        finally:
            qmp.unlink(missing_ok=True)
    if process.returncode:
        raise RuntimeError(f"QEMU exited {process.returncode}; see {log}")
    return log.read_text(errors="replace")


def clean(image):
    info = subprocess.run(["ntfsinfo", "-m", str(image)], capture_output=True, text=True)
    if info.returncode or "Volume Flags: 0x0000" not in info.stdout:
        raise RuntimeError(f"NTFS volume dirty after shutdown: {info.stderr.strip()}")


def main():
    if len(sys.argv) != 6 or os.geteuid() != 0:
        raise SystemExit("usage: sudo test_power_boot.py KERNEL INITRD CLEAN_UBUNTU_IMAGE POWER_IMAGE SWAP_IMAGE")
    kernel, initrd, base, image, swap = map(Path, sys.argv[1:])
    repo = Path(__file__).resolve().parents[2]
    if not image.exists():
        run("cp", "--reflink=auto", "--sparse=always", str(base), str(image))
        print(f"Created retained power image: {image}", flush=True)
    else:
        print(f"Reusing retained power image: {image}", flush=True)
    if not swap.exists():
        run("truncate", "-s", "2G", str(swap))
        print(f"Created retained swap backing file: {swap}", flush=True)
    swap.chmod(0o600)
    for mode in ("suspend", "hibernate-test", "hibernate-shutdown"):
        clean(image)
        configure(image, repo, mode)
        if mode != "suspend":
            run("mkswap", "-f", str(swap))
        first = boot(kernel, initrd, image, swap, mode, 1)
        if f"SLATE_POWER_START:{mode}" not in first:
            raise RuntimeError(f"Power test never started: {mode}")
        if mode == "suspend" and ("PM: suspend entry" not in first or "PM: suspend exit" not in first):
            raise RuntimeError("Kernel did not complete the suspend transition")
        if mode != "suspend" and "PM: hibernation: Wrote" not in first:
            raise RuntimeError("Kernel did not write a hibernation image")
        if mode == "hibernate-shutdown":
            if f"SLATE_POWER_RESUMED:{mode}" in first:
                raise RuntimeError("Hibernation returned without a VM restart")
            second = boot(kernel, initrd, image, swap, mode, 2)
            if "Image successfully loaded" not in second:
                raise RuntimeError("Kernel did not load the hibernation image")
            if f"SLATE_POWER_RESUMED:{mode}" not in second:
                raise RuntimeError("Hibernation image did not resume")
        elif f"SLATE_POWER_RESUMED:{mode}" not in first:
            raise RuntimeError(f"Power test did not resume: {mode}")
        clean(image)
        print(f"{mode}: resumed, wrote root, clean shutdown", flush=True)


if __name__ == "__main__":
    main()
