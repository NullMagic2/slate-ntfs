"""Module: permissions.permissions_core
Purpose: Define per-drive NTFS access policy for local users.
Created: 2026-10-02
Architecture: Python policy callers share these parsers and mount options; the privileged
backend applies policy to the driver.

Per-drive NTFS access policy for local users.

Each drive has an access mode, kept in /etc/slate-ntfs/permissions/<UUID>.conf:

desktop (default)  NTFS-3G-style "mounting permissions": one owner, one group
                   and read/write/execute bits for owner, group and everyone
                   else, applied to the whole drive while it is mounted.
                   Windows ownership and ACLs stay on the drive untouched and
                   are not evaluated. Default: only the mounting user
                   (files 0600, folders 0700).
windows            Strict Windows ACL enforcement. Each local user gets a
                   level that becomes an identity in the driver's SID map:
                     full  -> BUILTIN\\Administrators (one user per drive)
                     write -> a unique Unix user SID (Windows' usual
                              "Authenticated Users: Modify" makes data drives
                              writable)
                     read  -> as write, with low integrity: Windows'
                              no-write-up rule refuses changes
                     none  -> unmapped; the driver refuses all access

Policy file lines (any order, "#" comments):
    mode desktop|windows
    owner <UID>|auto          group <GID>|auto
    files <octal>             folders <octal>
    user <UID> none|read|write|full
Files that only contain "user" lines (version 1) are windows mode.
Every group of every mapped identity is mapped too, because the driver
refuses callers with an unmapped group. Root is always SYSTEM.
"""
import grp
import json
import os
import pwd
import re
import subprocess

POLICY_DIR = "/etc/slate-ntfs/permissions"
MODES = ("desktop", "windows")
LEVELS = ("none", "read", "write", "full")
MAX_ENTRIES = 64
_UUID = re.compile(r"^[0-9A-Fa-f-]{1,64}$")


class PolicyError(Exception):
    pass


def default_policy():
    return {"mode": "desktop", "owner": None, "group": None,
            "file_mode": 0o600, "dir_mode": 0o700, "users": {}}


# ---------------------------------------------------------------- drives ---
def _flag(value):
    return value in (True, 1, "1", "true")


def classify(disk, part):
    """portable / ssd / hdd, judged from the physical disk."""
    tran = (disk.get("tran") or "").lower()
    if tran in ("usb", "mmc", "ieee1394", "sdio", "memstick") or \
            _flag(disk.get("rm")) or _flag(disk.get("hotplug")) or _flag(part.get("hotplug")):
        return "portable"
    return "hdd" if _flag(disk.get("rota")) else "ssd"


def list_drives():
    out = subprocess.run(
        ["lsblk", "-J", "-b", "-o",
         "NAME,PATH,TYPE,FSTYPE,LABEL,UUID,SIZE,ROTA,RM,HOTPLUG,TRAN,MODEL,VENDOR,MOUNTPOINTS"],
        capture_output=True, text=True, check=True).stdout
    drives = []

    def walk(node, disk):
        if node.get("type") == "disk":
            disk = node
        if (node.get("fstype") or "").lower() in ("ntfs", "ntfsrs") and node.get("uuid"):
            d = disk or node
            mounts = [m for m in (node.get("mountpoints") or []) if m]
            model = " ".join(filter(None, [(d.get("vendor") or "").strip(),
                                           (d.get("model") or "").strip()]))
            drives.append({
                "device": node.get("path") or "/dev/" + node["name"],
                "uuid": node["uuid"],
                "label": node.get("label") or "",
                "size": int(node.get("size") or 0),
                "kind": classify(d, node),
                "model": model,
                "mountpoints": mounts,
            })
        for child in node.get("children") or []:
            walk(child, disk)

    for top in json.loads(out).get("blockdevices", []):
        walk(top, None)
    return drives


def human_size(size):
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(size)
    for unit in units:
        if value < 1000 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit in ("B", "KB") or value >= 100 \
                else f"{value:.1f} {unit}"
        value /= 1000
    return f"{size} B"


# ----------------------------------------------------------------- users ---
def _login_defs():
    lo, hi = 1000, 60000
    try:
        for line in open("/etc/login.defs"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "UID_MIN":
                lo = int(parts[1])
            elif len(parts) >= 2 and parts[0] == "UID_MAX":
                hi = int(parts[1])
    except (OSError, ValueError):
        pass
    return lo, hi


def list_users():
    lo, hi = _login_defs()
    users = []
    for p in pwd.getpwall():
        if not lo <= p.pw_uid <= hi:
            continue
        if p.pw_shell.endswith(("nologin", "/false")):
            continue
        real = p.pw_gecos.split(",")[0].strip()
        icon = f"/var/lib/AccountsService/icons/{p.pw_name}"
        users.append({"uid": p.pw_uid, "name": p.pw_name, "real_name": real or p.pw_name,
                      "icon": icon if os.path.isfile(icon) else None})
    return sorted(users, key=lambda u: (u["real_name"].lower(), u["uid"]))


# ---------------------------------------------------------------- policy ---
def _path(uuid):
    if not _UUID.match(uuid or ""):
        raise PolicyError(f"invalid volume UUID {uuid!r}")
    return os.path.join(POLICY_DIR, uuid.upper() + ".conf")


def _octal(text, where):
    try:
        value = int(text, 8)
    except ValueError:
        value = -1
    if not 0 <= value <= 0o777:
        raise PolicyError(f"{where}: expected permission bits like 0660")
    return value


def read_policy(uuid):
    """The saved policy, or None when this drive has none (defaults apply)."""
    try:
        text = open(_path(uuid)).read()
    except FileNotFoundError:
        return None
    policy = default_policy()
    saw_mode = False
    for number, line in enumerate(text.splitlines(), 1):
        where = f"{_path(uuid)}:{number}"
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        key, args = fields[0], fields[1:]
        if key == "mode" and len(args) == 1 and args[0] in MODES:
            policy["mode"], saw_mode = args[0], True
        elif key in ("owner", "group") and len(args) == 1 and (args[0] == "auto" or args[0].isdigit()):
            policy[key] = None if args[0] == "auto" else int(args[0])
        elif key == "files" and len(args) == 1:
            policy["file_mode"] = _octal(args[0], where)
        elif key == "folders" and len(args) == 1:
            policy["dir_mode"] = _octal(args[0], where)
        elif key == "user" and len(args) == 2 and args[0].isdigit() and args[1] in LEVELS:
            policy["users"][int(args[0])] = args[1]
        else:
            raise PolicyError(f"{where}: cannot understand {line.strip()!r}")
    if not saw_mode:
        policy["mode"] = "windows"  # version-1 files were strict per-user levels
    return policy


def validate_policy(policy):
    if policy.get("mode") not in MODES:
        raise PolicyError("mode must be desktop or windows")
    for key in ("file_mode", "dir_mode"):
        if not isinstance(policy.get(key), int) or not 0 <= policy[key] <= 0o777:
            raise PolicyError(f"{key} must be within 0777")
    for key in ("owner", "group"):
        if policy.get(key) is not None and (not isinstance(policy[key], int) or policy[key] < 0):
            raise PolicyError(f"invalid {key}")
    users = policy.get("users") or {}
    for uid, level in users.items():
        if level not in LEVELS or int(uid) <= 0:
            raise PolicyError(f"invalid entry for UID {uid}")
    if sum(1 for level in users.values() if level == "full") > 1:
        raise PolicyError("only one user per drive can have full control")


def write_policy(uuid, policy):
    validate_policy(policy)
    lines = ["# NTFS drive permissions, managed by slate-ntfs-permissions.",
             f"mode {policy['mode']}",
             f"owner {'auto' if policy.get('owner') is None else policy['owner']}",
             f"group {'auto' if policy.get('group') is None else policy['group']}",
             f"files {policy['file_mode']:04o}",
             f"folders {policy['dir_mode']:04o}"]
    for uid in sorted(int(u) for u in policy.get("users") or {}):
        lines.append(f"user {uid} {policy['users'].get(uid, policy['users'].get(str(uid)))}")
    os.makedirs(POLICY_DIR, mode=0o755, exist_ok=True)
    target = _path(uuid)
    temporary = f"{target}.{os.getpid()}.tmp"
    with open(temporary, "w") as handle:
        handle.write("\n".join(lines) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o644)
    os.replace(temporary, target)


def policy_from_json(data):
    """GUI/JSON form -> policy dict (keys may be strings)."""
    policy = default_policy()
    policy["mode"] = data.get("mode", "desktop")
    policy["owner"] = None if data.get("owner") is None else int(data["owner"])
    policy["group"] = None if data.get("group") is None else int(data["group"])
    policy["file_mode"] = int(data.get("file_mode", 0o600))
    policy["dir_mode"] = int(data.get("dir_mode", 0o700))
    policy["users"] = {int(u): lvl for u, lvl in (data.get("users") or {}).items()}
    validate_policy(policy)
    return policy


def policy_to_json(policy):
    data = dict(policy)
    data["users"] = {str(u): lvl for u, lvl in policy["users"].items()}
    return data


# --------------------------------------------------- friendly permissions ---
# The interface shows Read / Write / Execute for owner, group and others.
#   Read    files r, folders r+x (so their contents can be opened)
#   Write   files w, folders w   (needs Read)
#   Execute files x              (run programs from the drive)
CLASSES = (("owner", 6), ("group", 3), ("others", 0))


def modes_from_rwx(rwx):
    """{"owner": (r, w, x), ...} -> (file_mode, dir_mode)."""
    file_mode = dir_mode = 0
    for name, shift in CLASSES:
        read, write, execute = rwx[name]
        write = write and read
        file_mode |= ((4 if read else 0) | (2 if write else 0) | (1 if execute else 0)) << shift
        dir_mode |= ((5 if read else 0) | (2 if write else 0)) << shift
    return file_mode, dir_mode


def rwx_from_modes(file_mode, dir_mode):
    rwx = {}
    for name, shift in CLASSES:
        f, d = (file_mode >> shift) & 7, (dir_mode >> shift) & 7
        rwx[name] = (bool(f & 4 or d & 4), bool(f & 2 or d & 2), bool(f & 1))
    return rwx


PRESETS = (
    ("private", "Only the owner", 0o600, 0o700),
    ("group", "Owner and group", 0o660, 0o770),
    ("read-all", "Everyone can read", 0o644, 0o755),
    ("everyone", "Everyone can read and write", 0o666, 0o777),
)


def list_groups():
    """Groups that make sense to share a drive with: regular groups (in the
    GID_MIN..GID_MAX range, including each user's personal group) and 'users'."""
    lo, hi = 1000, 60000
    try:
        for line in open("/etc/login.defs"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "GID_MIN":
                lo = int(parts[1])
            elif len(parts) >= 2 and parts[0] == "GID_MAX":
                hi = int(parts[1])
    except (OSError, ValueError):
        pass
    humans = {u["name"]: u for u in list_users()}
    primary = {}
    for user in humans.values():
        try:
            primary.setdefault(pwd.getpwnam(user["name"]).pw_gid, []).append(user["name"])
        except KeyError:
            pass
    groups = []
    for g in grp.getgrall():
        if not (lo <= g.gr_gid <= hi or g.gr_name == "users"):
            continue
        members = sorted(set(g.gr_mem) | set(primary.get(g.gr_gid, [])))
        members = [m for m in members if m in humans]
        groups.append({"gid": g.gr_gid, "name": g.gr_name, "members": members})
    return sorted(groups, key=lambda g: (g["name"] != "users", g["name"]))


# ------------------------------------------------------ mount-time options ---
def resolve_owner(policy, mount_uid, mount_gid):
    """(uid, gid) for a desktop-mode mount."""
    uid = policy["owner"] if policy.get("owner") is not None else mount_uid
    if policy.get("group") is not None:
        gid = policy["group"]
    elif mount_uid == uid and mount_gid is not None:
        gid = mount_gid
    else:
        try:
            gid = pwd.getpwuid(uid).pw_gid
        except KeyError:
            gid = mount_gid or 0
    return uid, gid


def effective_levels(policy, owner_uid):
    """Windows-mode levels, with the mounting user full by default."""
    levels = dict(policy.get("users") or {})
    if owner_uid and owner_uid not in levels and "full" not in levels.values():
        levels[owner_uid] = "full"
    return levels


def build_sidmap(levels, extra_groups=()):
    entries = ["u:0:S-1-5-18"]
    groups = {0, *extra_groups}
    full_given = False
    for uid in sorted(levels):
        level = levels[uid]
        if uid == 0 or level == "none":
            continue
        try:
            account = pwd.getpwuid(uid)
        except KeyError:
            continue  # deleted account: never map it
        if level == "full" and not full_given:
            sid, full_given = "S-1-5-32-544", True
        else:
            sid = f"S-1-22-1-{uid}"
        entries.append(f"u:{uid}:{sid}" + (":low-integrity" if level == "read" else ""))
        groups.update(os.getgrouplist(account.pw_name, account.pw_gid))
    for gid in sorted(groups):
        try:
            name = grp.getgrgid(gid).gr_name
        except KeyError:
            name = ""
        if gid == 0:
            sid = "S-1-5-32-544"
        elif name == "users":
            sid = "S-1-5-32-545"
        else:
            sid = f"S-1-22-2-{gid}"
        entries.append(f"g:{gid}:{sid}")
    if len(entries) > MAX_ENTRIES:
        raise PolicyError(f"{len(entries)} identities needed; the driver supports {MAX_ENTRIES}. "
                          "Grant access to fewer users.")
    return ";".join(entries)


def access_options(policy, mount_uid, mount_gid):
    """Only the access part (no sidmap): used for live remounts."""
    if policy["mode"] == "windows":
        return "permissions=windows"
    uid, gid = resolve_owner(policy, mount_uid, mount_gid)
    return (f"permissions=desktop,uid={uid},gid={gid},"
            f"fmask={0o777 & ~policy['file_mode']:04o},dmask={0o777 & ~policy['dir_mode']:04o}")


def mount_options(policy, mount_uid, mount_gid):
    """Complete fs-specific options for mount.ntfs: SID map plus access policy.
    In desktop mode the map holds the owner (who is recorded as the owner of
    every new file) and the chosen group; access itself is decided by the bits."""
    if policy["mode"] == "desktop":
        uid, gid = resolve_owner(policy, mount_uid, mount_gid)
        sidmap = build_sidmap({uid: "full"} if uid else {}, extra_groups=(gid,))
    else:
        sidmap = build_sidmap(effective_levels(policy, mount_uid))
    return f"sidmap={sidmap},{access_options(policy, mount_uid, mount_gid)}"


def effective_policy(uuid):
    return read_policy(uuid) or default_policy()


def who_can_access(policy, owner_uid):
    """uids that can reach the drive (for /media/<user> traverse rights)."""
    if policy["mode"] == "windows":
        return {u for u, lvl in effective_levels(policy, owner_uid).items() if lvl != "none"}
    uid, gid = resolve_owner(policy, owner_uid, None)
    allowed = {uid}
    if (policy["dir_mode"] >> 3) & 7:
        try:
            members = set(grp.getgrgid(gid).gr_mem)
        except KeyError:
            members = set()
        for user in list_users():
            if user["name"] in members or pwd.getpwnam(user["name"]).pw_gid == gid:
                allowed.add(user["uid"])
    if policy["dir_mode"] & 7:
        allowed.update(u["uid"] for u in list_users())
    return allowed


def describe(policy, owner_uid, names=None):
    """One plain sentence for the interface."""
    names = names or {}

    def who(uid):
        return names.get(uid) or (pwd.getpwuid(uid).pw_name if _exists(uid) else f"UID {uid}")

    if policy["mode"] == "windows":
        return "Windows permissions are enforced for the people listed below."
    uid, gid = resolve_owner(policy, owner_uid, None) if owner_uid is not None or \
        policy.get("owner") is not None else (None, policy.get("group"))
    rwx = rwx_from_modes(policy["file_mode"], policy["dir_mode"])

    def can(bits):
        read, write, execute = bits
        if not read:
            return "no access"
        text = "read and write" if write else "read only"
        return text + (", and run programs" if execute else "")

    owner_text = "The person the drive is opened for" if uid is None else who(uid)
    try:
        group_text = f"members of “{grp.getgrgid(gid).gr_name}”" if gid is not None else "the owner's group"
    except KeyError:
        group_text = f"group {gid}"
    return (f"{owner_text}: {can(rwx['owner'])}. "
            f"{group_text[0].upper() + group_text[1:]}: {can(rwx['group'])}. "
            f"Everyone else: {can(rwx['others'])}.")


def _exists(uid):
    try:
        pwd.getpwuid(uid)
        return True
    except KeyError:
        return False


def device_uuid(device):
    result = subprocess.run(["blkid", "-o", "value", "-s", "UUID", device],
                            capture_output=True, text=True)
    return result.stdout.strip() or None


# ------------------------------------------------------------- applying ---
def _fstab_owner(uuid):
    try:
        for line in open("/etc/fstab"):
            fields = line.split()
            if len(fields) >= 4 and fields[0].upper() == f"UUID={uuid.upper()}":
                for option in fields[3].split(","):
                    if option.startswith("uid=") and option[4:].isdigit():
                        return int(option[4:]), fields[1].replace("\\040", " ")
                return None, fields[1].replace("\\040", " ")
    except OSError:
        pass
    return None, None


def drive_owner(drive):
    """The account a drive is mounted for (the default owner)."""
    uid, _ = _fstab_owner(drive["uuid"])
    if uid is not None:
        return uid
    for target in drive.get("mountpoints") or []:
        parts = target.split("/")
        if len(parts) >= 4 and parts[1] == "media":
            try:
                return pwd.getpwnam(parts[2]).pw_uid
            except KeyError:
                pass
    return None


def _run(argv):
    result = subprocess.run(argv, capture_output=True, text=True)
    return result.returncode, (result.stderr or result.stdout).strip()


def _sync_traverse_acls(parents):
    """Let permitted users walk into /media/<owner>/ (udisks makes it 0750).
    Only '--x' entries are managed, so udisks' own r-x grants stay intact."""
    if not parents or not os.path.exists("/usr/bin/setfacl"):
        return
    by_parent = {p: set() for p in parents}
    for drive in list_drives():
        owner = drive_owner(drive)
        policy = effective_policy(drive["uuid"])
        for target in drive["mountpoints"]:
            parent = os.path.dirname(target)
            if parent in by_parent:
                by_parent[parent].update(who_can_access(policy, owner))
    for parent, wanted in by_parent.items():
        code, text = _run(["getfacl", "-cpn", parent])
        existing = {}
        for line in text.splitlines() if code == 0 else []:
            parts = line.split(":")
            if len(parts) == 3 and parts[0] == "user" and parts[1].isdigit():
                existing[int(parts[1])] = parts[2]
        dir_owner = os.stat(parent).st_uid
        for uid in wanted - {0, dir_owner}:
            if uid not in existing:
                _run(["setfacl", "-m", f"u:{uid}:--x", parent])
        for uid, perms in existing.items():
            if perms == "--x" and uid not in wanted:
                _run(["setfacl", "-x", f"u:{uid}", parent])


def _mount_fs_options(target):
    code, text = _run(["findmnt", "-n", "-o", "VFS-OPTIONS,FS-OPTIONS", "--mountpoint", target])
    return text if code == 0 else ""


def apply_drive(uuid):
    """Make a mounted drive use its saved policy now.
    Returns (status, message); status is applied|pending|busy|error."""
    drive = next((d for d in list_drives() if d["uuid"].upper() == uuid.upper()), None)
    if drive is None:
        return "pending", "Saved. It applies the next time the drive is connected."
    if not drive["mountpoints"]:
        return "pending", "Saved. It applies the next time the drive is opened."
    policy = effective_policy(uuid)
    owner = drive_owner(drive)
    owner_gid = pwd.getpwuid(owner).pw_gid if owner is not None and _exists(owner) else None
    targets = sorted(drive["mountpoints"], key=len, reverse=True)
    wanted = mount_options(policy, owner if owner is not None else 0, owner_gid)
    wanted_map = wanted.split(",", 1)[0]
    current = re.split(r"[\s,]+", _mount_fs_options(targets[-1]))
    # Mounting permissions change live when the identity map is unchanged.
    if policy["mode"] == "desktop" and "permissions=desktop" in current and wanted_map in current:
        state = "ro" if current[:1] == ["ro"] else "rw"
        options = f"remount,{state},{access_options(policy, owner or 0, owner_gid)}"
        code, text = _run(["mount", "-i", "-t", "ntfsrs", "-o", options, targets[-1]])
        if code == 0:
            _sync_traverse_acls({os.path.dirname(t) for t in targets})
            return "applied", "Permissions updated."
    fstab_uid, fstab_target = _fstab_owner(uuid)
    for target in targets:
        code, text = _run(["umount", target])
        if code != 0:
            if "busy" in text.lower():
                return "busy", ("Saved, but the drive is in use. Close its files and windows, "
                                "then click Save again (or reconnect the drive).")
            return "error", f"Saved, but unmounting failed: {text}"
    target = targets[-1]
    if fstab_target == target:
        code, text = _run(["mount", target])
    else:
        options = "nosuid,nodev"
        if owner is not None:
            options += f",uid={owner},gid={owner_gid}"
        code, text = _run(["mount", "-t", "ntfs", "-o", options, drive["device"], target])
    if code != 0:
        return "error", f"Saved, but remounting failed: {text}. Reconnect the drive."
    _sync_traverse_acls({os.path.dirname(t) for t in targets})
    return "applied", "Permissions updated."


def save_and_apply(changes):
    """changes: {uuid: policy-json} -> {uuid: {"status", "message"}}"""
    results = {}
    for uuid, data in changes.items():
        try:
            write_policy(uuid, policy_from_json(data))
            status, message = apply_drive(uuid)
        except (PolicyError, OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
            status, message = "error", str(error)
        results[uuid] = {"status": status, "message": message}
    return results
