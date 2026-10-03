<!--
Module: documentation.vdi_case_2022
Purpose: Document Windows 11 VirtualBox image: hibernation round trip.
Created: 2026-10-02
Architecture: Records a read-only VDI investigation; vdi_probe and vdi_extract_partition provide
container access for fixture analysis.
-->

# Windows 11 VirtualBox image: hibernation round trip

The user supplied a 2022 Windows 11 Pro dynamic VDI for interoperability
testing. The VDI and extracted partition are local test data and are not part
of the source tree or release archive. The image's origin and installation
history have not been independently established.

## Extraction

`vdi_probe.py` reads the VDI geometry and GPT without modifying it.
`vdi_extract_partition.py` creates a new sparse raw image of one NTFS GPT
partition. It opens the VDI read-only and refuses to overwrite its output.

```sh
python3 tests/windows/vdi_probe.py "$VDI"
python3 tests/windows/vdi_extract_partition.py "$VDI" 3 "$NTFS_COPY"
```

The disk has a 15 GiB logical size and four GPT partitions: EFI, Microsoft
reserved, NTFS system, and NTFS recovery. GPT partition 3 is the system
volume. It has 512-byte sectors, 4096-byte clusters, 1024-byte MFT records,
and NTFS version 3.1.

## Results from the extracted, offline system partition

| Test | Observation |
| --- | --- |
| `ntfs-chkdsk --status` | `dirty=0` |
| `ntfs-chkdsk --recovery-status` | `log_state=replay-required`, `hibernation_file_present=0`, `dirty=0` |
| `ntfs-inspect` | MFT zero and root index parsed; 33 root entries |
| `ntfs-chkdsk --check` | 199498 allocated MFT records, 918113 attributes, 193740 security IDs, 33 reachable root entries; exits with unresolved recovery prerequisite |
| `ntfs-chkdsk --log-inventory` | 5774 pages scanned, 5595 RCRD pages, 0 decoded records, 5579 unresolved pages, 195 invalid pages |
| `ntfsinfo -m` (NTFS-3G tools) | `$Volume` flags `0x0000`, matching the driver's dirty flag |
| `ntfsls -f -p /` (NTFS-3G tools) | `hiberfil.sys` absent from root |

The `replay-required` label currently means that the newer parsed `$LogFile`
restart page has an active client. The clean `$Volume` flag and this label are
different observations. This case does not establish that replay is truly
required, or that this driver can replay it. The log inventory cannot decode
the Windows journal records in this image; improving that parser is required
before attempting general NTFS writes or repair.

The later `--replay-plan` diagnostic was run on read-only loop views of the
hibernated and resumed 30 GiB overlay captures. The hibernated capture had
an active NTFS client, a checkpoint record inside a 16-page transfer, and
three referenced checkpoint table records. The parser validated all three,
including an open-attribute table record spanning three pages. The resumed,
fully shut down capture had an active client and a valid checkpoint record
with zero referenced tables. Both reported `replay_ready=0`: the current
circular log window, transaction decisions, and metadata targets still need
validation before replay or writes.

## Live guest hibernation round trip

The VDI was booted in a network-isolated QEMU guest through a separate QCOW2
overlay. The overlay was expanded from 15 to 30 GiB. In that disposable
overlay only, the recovery partition was removed and the NTFS system
partition extended to give Windows room to create a full hibernation file.
Windows then accepted `powercfg /h /type full`, advertised Hibernate through
`powercfg /a`, and hibernated with `shutdown /h`.

The stopped overlay was converted to a raw test image and its system partition
attached read-only. The checker reported `dirty=0`,
`hibernation_file_present=1`, `hibernation_state=active-image`, and
`log_state=replay-required`. The first four bytes of `hiberfil.sys` were
`HIBR`. `ntfs-chkdsk --check` refused to declare the volume safe for writes.
This confirms that checking the dirty bit alone would miss a real hibernated
Windows installation.

The guest resumed into the same open command prompt and then ran
`shutdown /s /t 0`. A second stopped-disk inspection found that
`hiberfil.sys` still existed, now beginning with `WAKE`. The checker reported
`hibernation_state=invalidated-image`, `dirty=0`, and
`log_state=replay-required`. The session is no longer marked as an active
`HIBR` image. The checker still does not authorize writes, both because its
log replay is incomplete and because the write gate conservatively blocks
any present hibernation file. This single Windows 11 build does not establish
the full range of Fast Startup, interrupted-resume, or Windows 10 behavior.

The kernel driver and `ntfs-chkdsk` did not write to the provided VDI. All
guest modifications went to the disposable overlay.
