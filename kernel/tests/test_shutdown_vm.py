#!/usr/bin/env python3
"""Module: kernel.tests.shutdown_vm
Purpose: Test logout, reboot and USB removal without mounting host devices.
Created: 2026-10-21
Architecture: Boots Ubuntu systemd/logind in a private RAM root with a copied
NTFS fixture; the host retains images and serial logs for independent checks.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
from textwrap import dedent
import uuid

REPO = Path(__file__).resolve().parents[2]
MEMORY_MIB = 1024
CPUS = 2
VM_TIMEOUT_SECONDS = 120
POLL_SECONDS = 0.1
QMP_TIMEOUT_SECONDS = 10
EXECUTABLE_MODE = 0o755
DATA_MOUNT = "/media/x/Novo volume"
SID_MAP = "u:0:S-1-5-18;u:1000:S-1-5-32-544;g:0:S-1-5-32-544;g:1000:S-1-22-2-1000"

CONTROLLER = r'''#!/bin/sh
# Module: kernel.tests.shutdown_controller
# Purpose: Drive real logind termination and normal systemd shutdown.
# Created: 2026-10-21
# Architecture: Runs only inside the private shutdown-test guest.
set -eu
export PATH=/bin:/usr/bin:/usr/sbin
root='/media/x/Novo volume'
device_wait_seconds=20
session_wait_seconds=20
idle_wait_seconds=12
cleanup_wait_seconds=25
mode=$(cat /etc/d26-mode)
device=$(cat /etc/d26-device)
fail()
{
    echo D26_FAILED
    dmesg
    systemctl poweroff
    exit 1
}
trap fail EXIT
mkdir -p "$root" /run/d26
chmod 0777 /run/d26
attempt=0
while [ ! -b "$device" ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt "$device_wait_seconds" ] || exit 1
    sleep 1
done
view=$(cat /etc/d26-view)
mount -t ntfsrs -o "rw,compatibility=$view,permissions=desktop,uid=1000,gid=1000,sidmap=@SID_MAP@" "$device" "$root"
if [ "$mode" = recovered ]; then
    test-shutdown-guest verify "$root"
    [ ! -e "$root/must-not-exist" ]
    echo D26_RECOVERED_PASS
    trap - EXIT
    systemctl poweroff
    exit 0
fi
if [ "$mode" = reboot ] && [ -f "$root/reboot-requested" ]; then
    test-shutdown-guest verify "$root"
    [ ! -e "$root/victim.bin" ]
    [ ! -e "$root/must-not-exist" ]
    echo D26_REBOOT_SECOND_BOOT_PASS
    trap - EXIT
    systemctl poweroff
    exit 0
fi
test-shutdown-guest exercise "$root"
systemctl start d26-session.service
attempt=0
while [ ! -f /run/d26/ready ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt "$session_wait_seconds" ] || exit 1
    sleep 1
done
case "$mode" in
    logout)
        sleep "$idle_wait_seconds"
        ntfs-chkdsk --recovery-status "$device" > /run/d26/before
        cat /run/d26/before
        grep -q '^dirty=1$' /run/d26/before
        if mount -i -o remount,ro -- "$root"; then exit 1; fi
        printf 'still writable after busy remount' > "$root/after-busy-remount.txt"
        sessions=$(loginctl show-user x --property Sessions --value)
        [ -n "$sessions" ]
        echo "D26_REAL_LOGIN_SESSIONS:$sessions"
        loginctl terminate-user x
        attempt=0
        while :; do
            ntfs-chkdsk --recovery-status "$device" > /run/d26/after
            if ! systemctl is-active --quiet d26-session.service && grep -q '^dirty=0$' /run/d26/after; then
                break
            fi
            attempt=$((attempt + 1))
            [ "$attempt" -lt "$cleanup_wait_seconds" ] || exit 1
            sleep 1
        done
        cat /run/d26/after
        printf 'resumed after logout' > "$root/after-logout.txt"
        ntfs-chkdsk --recovery-status "$device" | grep -q '^dirty=1$'
        sync
        /usr/lib/systemd/system-shutdown/ntfsrs
        ntfs-chkdsk --recovery-status "$device" | grep -q '^dirty=0$'
        if printf forbidden > "$root/must-not-exist"; then exit 1; fi
        echo D26_LOGOUT_PASS
        ;;
    reboot)
        printf 'normal reboot requested' > "$root/reboot-requested"
        sync
        echo D26_REBOOT_REQUESTED
        trap - EXIT
        systemctl reboot
        exit 0
        ;;
    unplug)
        test-shutdown-guest unplug "$root"
        echo D26_UNPLUG_PASS
        ;;
esac
trap - EXIT
systemctl poweroff
'''

INIT = '''#!/bin/sh
# Module: kernel.tests.shutdown_init
# Purpose: Start the isolated Ubuntu systemd test environment.
# Created: 2026-10-21
# Architecture: Initializes RAM-root mounts before handing PID 1 to systemd.
export PATH=/bin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
insmod /slate-ntfs.ko || poweroff -f
if test -f /usb-storage.ko; then insmod /usb-storage.ko || poweroff -f; fi
exec /usr/lib/systemd/systemd --system --log-target=console
'''


def write(root, name, content, executable=False):
    destination = root / name.lstrip("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content)
    if executable:
        destination.chmod(EXECUTABLE_MODE)


def copy_program(root, source, destination=None):
    source = Path(source)
    target = root / str(destination or source).lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    dependencies = subprocess.run(["ldd", str(source)], capture_output=True, text=True)
    for name in re.findall(r"(/[^\s()]+)", dependencies.stdout):
        library = Path(name)
        target = root / library.relative_to("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(library, target)


def unit(root, name, body):
    header = ("# Module: kernel.tests.shutdown_unit\n"
              "# Purpose: Configure an isolated shutdown regression.\n"
              "# Created: 2026-10-21\n"
              "# Architecture: This unit runs only in the disposable guest.\n\n")
    write(root, f"/etc/systemd/system/{name}", header + dedent(body).strip() + "\n")


def stage(args, *, helper_source=None, helper_name="test-shutdown-guest", controller=CONTROLLER, extra_setup=None):
    root = args.output / "root"
    root.mkdir()
    for directory in ["proc", "sys", "dev", "run", "tmp", "var/tmp", "home/x", "etc/pam.d"]:
        (root / directory).mkdir(parents=True, exist_ok=True)
    programs = ["/usr/lib/systemd/systemd", "/usr/lib/systemd/systemd-shutdown",
                "/usr/lib/systemd/systemd-executor", "/usr/lib/systemd/systemd-logind",
                "/usr/lib/systemd/systemd-user-runtime-dir", "/usr/lib/systemd/systemd-journald",
                "/usr/bin/systemctl", "/usr/bin/loginctl", "/usr/bin/dbus-daemon",
                "/usr/lib/x86_64-linux-gnu/security/pam_systemd.so",
                "/usr/lib/x86_64-linux-gnu/security/pam_permit.so"]
    for program in programs:
        copy_program(root, program)
    copy_program(root, "/usr/bin/busybox", "/bin/busybox")
    copy_program(root, "/usr/bin/mount", "/bin/mount")
    copy_program(root, args.checker, "/bin/ntfs-chkdsk")
    subprocess.run(["strip", "--strip-debug", str(root / "bin/ntfs-chkdsk")], check=True)
    for name in ["sh", "umount", "mkdir", "chmod", "cat", "grep", "sleep", "insmod", "poweroff", "sync", "dmesg"]:
        (root / "bin" / name).symlink_to("busybox")
    helper = root / "bin" / helper_name
    helper_source = helper_source or REPO / "kernel/tests/test_shutdown_guest.c"
    subprocess.run(["gcc", "-static", "-pthread", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(helper_source), "-o", str(helper)], check=True)
    shutil.copy2(args.module, root / "slate-ntfs.ko")
    if args.case == "unplug":
        module = subprocess.check_output(
            ["modinfo", "-k", args.kernel_version, "-n", "usb-storage"], text=True
        ).strip()
        with (root / "usb-storage.ko").open("wb") as output:
            if module.endswith(".zst"):
                subprocess.run(["zstd", "-dc", module], stdout=output, check=True)
            else:
                with Path(module).open("rb") as source:
                    shutil.copyfileobj(source, output)
    shutdown = REPO / "boot/systemd/system-shutdown/ntfsrs"
    copy_program(root, shutdown, "/usr/lib/systemd/system-shutdown/ntfsrs")
    (root / "usr/lib/systemd/system-shutdown/ntfsrs").chmod(EXECUTABLE_MODE)
    for path in Path("/usr/lib/systemd/system").glob("*.target"):
        write(root, "/usr/lib/systemd/system/" + path.name, path.read_text())
    for path in Path("/usr/lib/systemd/system").glob("*.slice"):
        write(root, "/usr/lib/systemd/system/" + path.name, path.read_text())
    for name in ["systemd-poweroff.service", "systemd-reboot.service"]:
        path = Path("/usr/lib/systemd/system") / name
        write(root, "/usr/lib/systemd/system/" + name, path.read_text())
    write(root, "/etc/passwd", "root:x:0:0:root:/:/bin/sh\nx:x:1000:1000:test:/home/x:/bin/sh\n")
    write(root, "/etc/group", "root:x:0:\nx:x:1000:\n")
    write(root, "/etc/nsswitch.conf", "passwd: files\ngroup: files\nshadow: files\n")
    write(root, "/etc/machine-id", uuid.uuid4().hex + "\n")
    write(root, "/etc/d26-mode", args.case + "\n")
    write(root, "/etc/d26-view", args.view + "\n")
    write(root, "/etc/d26-device", "/dev/sda\n" if args.case == "unplug" else "/dev/vda\n")
    write(root, "/etc/systemd/logind.conf", "[Login]\nKillUserProcesses=yes\nUserStopDelaySec=0\n")
    write(root, "/etc/pam.d/slate-d26", "auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_systemd.so\n")
    write(root, "/etc/dbus-1/system.conf", '''<busconfig>
<type>system</type><user>root</user><listen>unix:path=/run/dbus/system_bus_socket</listen>
<auth>EXTERNAL</auth><policy context="default"><allow own="*"/>
<allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>\n''')
    write(root, "/init", INIT, True)
    write(root, "/bin/d26-controller", controller.replace("@SID_MAP@", SID_MAP), True)
    unit(root, "dbus.socket", '''
        [Socket]
        ListenStream=/run/dbus/system_bus_socket
        SocketMode=0666
    ''')
    unit(root, "dbus.service", '''
        [Unit]
        Requires=dbus.socket
        After=dbus.socket
        [Service]
        Type=notify
        ExecStart=/usr/bin/dbus-daemon --config-file=/etc/dbus-1/system.conf --address=systemd: --nofork --nopidfile --systemd-activation
        RuntimeDirectory=dbus
        StandardOutput=tty
        StandardError=tty
        TTYPath=/dev/console
    ''')
    unit(root, "systemd-logind.service", '''
        [Unit]
        Requires=dbus.service
        After=dbus.service
        [Service]
        Type=dbus
        BusName=org.freedesktop.login1
        ExecStart=/usr/lib/systemd/systemd-logind
        RuntimeDirectory=systemd/sessions systemd/seats systemd/users systemd/inhibit systemd/shutdown
    ''')
    unit(root, "user-runtime-dir@.service", '''
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/lib/systemd/systemd-user-runtime-dir start %i
        ExecStop=/usr/lib/systemd/systemd-user-runtime-dir stop %i
    ''')
    unit(root, "user@.service", '''
        [Service]
        Type=exec
        User=%i
        ExecStart=/bin/sleep infinity
    ''')
    unit(root, "d26-session.service", f'''
        [Unit]
        After=systemd-logind.service
        [Service]
        Type=exec
        User=x
        PAMName=slate-d26
        ExecStart=/bin/test-shutdown-guest hold "{DATA_MOUNT}"
        StandardOutput=tty
        StandardError=tty
        TTYPath=/dev/console
    ''')
    unit(root, "d26-controller.service", '''
        [Unit]
        Requires=systemd-logind.service
        After=systemd-logind.service
        [Service]
        Type=oneshot
        ExecStart=/bin/d26-controller
        StandardOutput=tty
        StandardError=tty
        TTYPath=/dev/console
        TimeoutStartSec=90
    ''')
    unit(root, "d26.target", '''
        [Unit]
        Requires=d26-controller.service
        After=basic.target
    ''')
    if extra_setup is not None:
        extra_setup(root)
    initrd = args.output / "initrd.cpio.gz"
    names = ["."] + sorted(str(path.relative_to(root)) for path in root.rglob("*"))
    archive = subprocess.run(["cpio", "--null", "-o", "-H", "newc", "--owner=0:0"],
                             input=("\0".join(names) + "\0").encode(), cwd=root, capture_output=True, check=True)
    with initrd.open("wb") as output:
        subprocess.run(["gzip", "-1"], input=archive.stdout, stdout=output, check=True)
    return initrd


def qmp(path, command, arguments=None):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(QMP_TIMEOUT_SECONDS)
        client.connect(str(path))
        stream = client.makefile("rwb", buffering=0)
        json.loads(stream.readline())
        for request in [{"execute": "qmp_capabilities"}, {"execute": command, "arguments": arguments or {}}]:
            stream.write(json.dumps(request).encode() + b"\n")
            while True:
                result = json.loads(stream.readline())
                if "error" in result:
                    raise RuntimeError(result)
                if "return" in result:
                    break
        return result["return"]


def boot(args, initrd, image, number):
    control = Path("/tmp") / f"slate-d26-{uuid.uuid4().hex[:12]}.sock"
    command = ["qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-m", str(MEMORY_MIB),
               "-smp", str(CPUS), "-display", "none", "-nic", "none", "-serial", "stdio", "-monitor", "none",
               "-no-reboot", "-kernel", str(args.kernel), "-initrd", str(initrd),
               "-append", "console=ttyS0 loglevel=5 panic=-1 noresume systemd.unit=d26.target systemd.log_target=console",
               "-qmp", f"unix:{control},server=on,wait=off"]
    if args.case == "unplug":
        command.extend(["-device", "qemu-xhci,id=d26usb", "-drive", f"file={image},if=none,id=d26drive,format=raw,cache=none",
                        "-device", "usb-storage,bus=d26usb.0,drive=d26drive,id=d26target,serial=D26TEST"])
    else:
        sector = getattr(args, "device_sector_bytes", None)
        if sector is None:
            command.extend(["-drive", f"file={image},if=virtio,format=raw,cache=none"])
        else:
            command.extend([
                "-drive", f"file={image},if=none,id=d26drive,format=raw,cache=none",
                "-device", f"virtio-blk-pci,drive=d26drive,logical_block_size={sector},physical_block_size={sector}",
            ])
    log = args.output / f"boot-{number}.log"
    with log.open("w") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + VM_TIMEOUT_SECONDS
        unplugged = False
        try:
            while process.poll() is None:
                text = log.read_text(errors="replace")
                if args.case == "unplug" and not unplugged and "D26_UNPLUG_READY" in text:
                    qmp(control, "device_del", {"id": "d26target"})
                    unplugged = True
                if time.monotonic() > deadline:
                    raise TimeoutError(f"guest timed out; inspect {log}")
                time.sleep(POLL_SECONDS)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            control.unlink(missing_ok=True)
    text = log.read_text(errors="replace")
    if process.returncode or "D26_FAILED" in text:
        raise RuntimeError(f"guest failed; inspect {log}")
    return text


def check_image(args, image, dirty):
    result = subprocess.run(
        [str(args.checker), "--recovery-status", str(image)],
        check=True, capture_output=True, text=True,
    ).stdout
    if f"dirty={dirty}\n" not in result:
        raise RuntimeError(f"unexpected final volume state: {result}")
    if not dirty and "log_state=clean-shutdown\n" not in result:
        raise RuntimeError(f"clean volume has unresolved journal history: {result}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["module", "kernel", "checker", "fixture", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--case", choices=["logout", "reboot", "unplug", "recovered"], required=True)
    parser.add_argument("--view", choices=["ntfs", "linux"], required=True)
    args = parser.parse_args()
    for name in ["module", "kernel", "checker", "fixture", "output"]:
        setattr(args, name, getattr(args, name).resolve())
    if not args.fixture.is_file():
        parser.error("--fixture must be a regular disposable image, never a block device")
    args.kernel_version = subprocess.check_output(
        ["modinfo", "-F", "vermagic", str(args.module)], text=True
    ).split()[0]
    args.output.mkdir(parents=True, exist_ok=False)
    image = args.output / "volume.img"
    shutil.copyfile(args.fixture, image)
    initrd = stage(args)
    first = boot(args, initrd, image, 1)
    if args.case == "reboot":
        assert "D26_REBOOT_REQUESTED" in first
        check_image(args, image, 0)
        second = boot(args, initrd, image, 2)
        assert "D26_REBOOT_SECOND_BOOT_PASS" in second
    else:
        assert f"D26_{args.case.upper()}_PASS" in first
    (args.output / "recovery-status.txt").write_text(check_image(args, image, int(args.case == "unplug")))
    print(f"PASS D26 {args.case} {args.view}: {image}")


if __name__ == "__main__":
    main()
