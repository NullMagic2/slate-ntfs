//! Module: writer_lifecycle::hidden_move
//! Purpose: Prepare a hidden Git directory and system file for move testing.
//! Created: 2026-10-14
//! Architecture: Reuses the lifecycle adapter and real metadata writer; the
//! mounted VM checks recursive copying and source removal on private images.

use super::*;
use ntfs_rs::{file_lifecycle::NodeKind, mft::system_record, std_info};

const ROOT_SEQUENCE: u16 = 5;
const HISTORY: &[u8] = b"preserved repository history\n";
const VISIBLE_DATA_BYTES: usize = 8 * 1024;
const HIDDEN_STREAM_ENTRIES: usize = 256;
const SYSTEM_DATA: &[u8] = b"preserved ordinary system file\n";

#[test]
fn hidden_project_move_fixture() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a disposable image");
    let (mut image, path, boot) = open_copy(&source, "hidden-project-move");
    let root = system_record::ROOT | (u64::from(ROOT_SEQUENCE) << 48);
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let mut references = Vec::new();
    for name in ["project", "cli-project", "override-project"] {
        let project = writer
            .create_node(&mut image, root, name, NodeKind::Directory, &NULL_DACL, 0, None, &[], &mut scratch)
            .unwrap();
        let git = writer
            .create_node(&mut image, project, ".git", NodeKind::Directory, &NULL_DACL, 0, None, &[], &mut scratch)
            .unwrap();
        let config = writer.file_lifecycle(&mut image, git, "config", None, &NULL_DACL, 0, &mut scratch).unwrap();
        writer.write(&mut image, config, 0, HISTORY, &mut scratch).unwrap();
        writer
            .set_std_info(&mut image, git, [None; 4], Some((std_info::HIDDEN, std_info::HIDDEN)), &mut scratch)
            .unwrap();
        let system =
            writer.file_lifecycle(&mut image, project, "system.dat", None, &NULL_DACL, 0, &mut scratch).unwrap();
        writer.write(&mut image, system, 0, SYSTEM_DATA, &mut scratch).unwrap();
        writer
            .set_std_info(&mut image, system, [None; 4], Some((std_info::SYSTEM, std_info::SYSTEM)), &mut scratch)
            .unwrap();
        let visible =
            writer.file_lifecycle(&mut image, project, "visible.txt", None, &NULL_DACL, 0, &mut scratch).unwrap();
        writer.write(&mut image, visible, 0, &vec![b'v'; VISIBLE_DATA_BYTES], &mut scratch).unwrap();
        let objects = writer
            .create_node(&mut image, git, "objects", NodeKind::Directory, &NULL_DACL, 0, None, &[], &mut scratch)
            .unwrap();
        let bucket = writer
            .create_node(&mut image, objects, "df", NodeKind::Directory, &NULL_DACL, 0, None, &[], &mut scratch)
            .unwrap();
        let object =
            writer.file_lifecycle(&mut image, bucket, "readonly-object", None, &NULL_DACL, 0, &mut scratch).unwrap();
        writer.write(&mut image, object, 0, HISTORY, &mut scratch).unwrap();
        let object_flags = std_info::READONLY | std_info::ARCHIVE;
        writer.set_std_info(&mut image, object, [None; 4], Some((object_flags, object_flags)), &mut scratch).unwrap();
        references.push((config, system));
    }
    let large = writer
        .create_node(&mut image, root, "large-hints", NodeKind::Directory, &NULL_DACL, 0, None, &[], &mut scratch)
        .unwrap();
    for ordinal in 0..HIDDEN_STREAM_ENTRIES {
        let name = format!("hidden-entry-{ordinal:04}-long-filename.dat");
        let file = writer.file_lifecycle(&mut image, large, &name, None, &NULL_DACL, 0, &mut scratch).unwrap();
        writer
            .set_std_info(&mut image, file, [None; 4], Some((std_info::HIDDEN, std_info::HIDDEN)), &mut scratch)
            .unwrap();
    }
    writer.finish(&mut image, &mut scratch).unwrap();
    for (config, system) in references {
        assert_eq!(read_resolved(&mut image, boot, config), HISTORY);
        assert_eq!(read_resolved(&mut image, boot, system), SYSTEM_DATA);
    }
    if let Some(folder) = std::env::var_os("SLATE_HIDDEN_MOVE_FIXTURES") {
        std::fs::copy(&path, std::path::PathBuf::from(folder).join("hidden-project.img")).unwrap();
    }
    drop(image);
    std::fs::remove_file(path).unwrap();
}
