//! Module: ntfs_utils::bin::ntfs_format
//! Purpose: Provide the ntfs-format command-line entry point.
//! Created: 2026-10-01
//! Architecture: Utility API callers and commands use this module over the shared NTFS core.

use ntfs_utils::{format_device, FormatOptions, OperationResult, Status};
const USAGE: &str = "usage: ntfs-format DEVICE_OR_IMAGE --yes [OPTIONS] [NUMBER_OF_SECTORS]
Destructive native Rust NTFS 3.1 data-volume format. Quick is not secure erasure.
  -Q, -f, --quick, --fast       Quick format (default)
  --full                       Zero the selected volume before formatting
  -L, --label TEXT              Volume label
  -s, --sector-size BYTES       Logical sector size (default: device/512)
  -c, --cluster-size BYTES      Cluster size (default: automatic)
  -p, --partition-start SECTOR  BPB partition start; does not repartition
  -H, --heads NUMBER            BPB geometry
  -S, --sectors-per-track N     BPB geometry
  -z, --mft-zone-multiplier N   MFT growth layout hint, 1..4
  -C, --enable-compression     Root compression inheritance (clusters <=4096)
  -I, --no-indexing            Root not-content-indexed default
  -T, --zero-time              Creation times: 1970-01-01 UTC
  -U, --with-uuid              Volume object ID and matching index entry
  -n, --no-action, --dry-run   Validate and report layout without writes
  -q, --quiet                  Suppress success message
  -v, --verbose, --debug       Include format plan in success message
  --yes                       Acknowledge destruction; never bypasses busy/permission checks";
fn main() {
    let (result, quiet) = run().unwrap_or_else(|| (OperationResult::new(Status::InvalidArgument, USAGE), false));
    if !quiet || !result.is_success() {
        println!("{}: {}", if result.is_success() { "SUCCESS" } else { "FAILURE" }, result.message);
    }
    std::process::exit(result.status as i32);
}
fn run() -> Option<(OperationResult, bool)> {
    let mut args = std::env::args_os().skip(1);
    let mut path = None;
    let mut options = FormatOptions::default();
    let mut yes = false;
    let mut quiet = false;
    let mut verbose = false;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--help" | "-h") => return Some((OperationResult::new(Status::Success, USAGE), false)),
            Some("--version" | "-V") => {
                return Some((OperationResult::new(Status::Success, "slate-ntfs native formatter 0.2"), false))
            }
            Some("--yes") => yes = true,
            Some("--full") => options.quick = false,
            Some("--quick" | "--fast" | "-Q" | "-f") => options.quick = true,
            Some("--no-action" | "--dry-run" | "-n") => options.dry_run = true,
            Some("--enable-compression" | "-C") => options.compression = true,
            Some("--no-indexing" | "-I") => options.disable_indexing = true,
            Some("--zero-time" | "-T") => options.epoch_time = true,
            Some("--with-uuid" | "-U") => options.with_uuid = true,
            Some("--quiet" | "-q") => quiet = true,
            Some("--verbose" | "--debug" | "-v") => verbose = true,
            Some("--label" | "-L") => options.label = args.next()?.into_string().ok()?,
            Some(
                flag @ ("--sector-size"
                | "-s"
                | "--cluster-size"
                | "-c"
                | "--partition-start"
                | "-p"
                | "--heads"
                | "-H"
                | "--sectors-per-track"
                | "-S"
                | "--mft-zone-multiplier"
                | "-z"),
            ) => {
                let n = args.next()?.into_string().ok()?.parse::<u64>().ok()?;
                match flag {
                    "--sector-size" | "-s" => options.sector_size = n.try_into().ok()?,
                    "--cluster-size" | "-c" => options.cluster_size = n.try_into().ok()?,
                    "--partition-start" | "-p" => options.partition_start = n.try_into().ok()?,
                    "--heads" | "-H" => options.heads = n.try_into().ok()?,
                    "--sectors-per-track" | "-S" => options.sectors_per_track = n.try_into().ok()?,
                    _ => options.mft_zone_multiplier = n.try_into().ok()?,
                }
            }
            _ if path.is_none() && !arg.to_string_lossy().starts_with('-') => path = Some(arg),
            _ if path.is_some() && options.sectors == 0 => options.sectors = arg.to_str()?.parse().ok()?,
            _ => return None,
        }
    }
    if !yes && !options.dry_run {
        return None;
    }
    let path = path?;
    let mut result = format_device(&path, &options);
    if verbose && result.is_success() && !options.dry_run {
        options.dry_run = true;
        let plan = format_device(&path, &options);
        let layout = plan.message.strip_prefix("dry run: ").unwrap_or(&plan.message);
        let layout = layout.strip_suffix("; no writes performed").unwrap_or(layout);
        result.message.push_str(&format!("; layout: {layout}"));
    }
    Some((result, quiet))
}
