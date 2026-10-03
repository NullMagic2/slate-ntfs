//! Module: examples.benchmark_writer
//! Purpose: Benchmark direct Rust writes on a disposable NTFS image.
//! Created: 2026-10-02
//! Architecture: Adapts a host file to ReadAt and WriteIo; the core Writer owns NTFS mutation and draining.

//! Direct Rust writer benchmark on a freshly formatted disposable image copy.
//! This excludes the kernel VFS bridge. Invoke only on a copy, never a device.
use ntfs_rs::{
    batch::BATCH_BYTES,
    boot::BootSector,
    resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES},
    volume::ReadAt,
    Error, Result,
};
use std::{
    env,
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    time::Instant,
};

struct Io {
    file: std::fs::File,
    held: Vec<(u64, Vec<u8>)>,
}
impl ReadAt for Io {
    fn read_exact_at(&mut self, at: u64, out: &mut [u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(at)).and_then(|_| self.file.read_exact(out)).map_err(|_| Error::Io)?;
        for (start, bytes) in &self.held {
            let from = at.max(*start);
            let to = (at + out.len() as u64).min(*start + bytes.len() as u64);
            if from < to {
                out[(from - at) as usize..(to - at) as usize]
                    .copy_from_slice(&bytes[(from - *start) as usize..(to - *start) as usize]);
            }
        }
        Ok(())
    }
}
impl WriteIo for Io {
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(at)).and_then(|_| self.file.write_all(bytes)).map_err(|_| Error::Io)
    }
    fn flush(&mut self) -> Result<()> {
        self.file.sync_all().map_err(|_| Error::Io)
    }
    fn hold_at(&mut self, at: u64, bytes: &[u8], _first: bool) -> Result<()> {
        if let Some((_, data)) = self.held.iter_mut().find(|(start, _)| *start == at) {
            data.clear();
            data.extend_from_slice(bytes);
        } else {
            self.held.push((at, bytes.to_vec()));
        }
        Ok(())
    }
    fn release_at(&mut self, at: u64, _len: usize) {
        self.held.retain(|(start, _)| *start != at);
    }
}

fn seconds(action: impl FnOnce() -> Result<()>) -> Result<f64> {
    let start = Instant::now();
    action()?;
    Ok(start.elapsed().as_secs_f64())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("benchmark failed: {error:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let path = env::args().nth(1).ok_or(Error::Unsupported)?;
    let mut io =
        Io { file: OpenOptions::new().read(true).write(true).open(path).map_err(|_| Error::Io)?, held: vec![] };
    let mut boot_raw = [0; 512];
    io.read_exact_at(0, &mut boot_raw)?;
    let boot = BootSector::parse(&boot_raw)?;
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut io, boot, &mut scratch)?;
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice()))?;
    writer.initialize(&mut io, &mut scratch)?;
    let mut sd = [0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    let root = (5u64 << 48) | 5;
    eprintln!("stage: create overwrite");
    let file = writer.file_lifecycle(&mut io, root, "overwrite.bin", None, &sd, 0, &mut scratch)?;
    eprintln!("stage: pre-fill overwrite");
    let zeroes = vec![0; 65536];
    for i in 0..64 {
        writer.write(&mut io, file, i * 65536, &zeroes, &mut scratch)?;
    }
    eprintln!("stage: pre-drain overwrite");
    writer.drain(&mut io, &mut scratch)?;
    let block = vec![b'x'; 4096];
    let overwrite = seconds(|| {
        eprintln!("stage: overwrite");
        for i in 0..512 {
            writer.write(&mut io, file, ((i * 7919) % 1024 * 4096) as u64, &block, &mut scratch)?;
        }
        writer.drain(&mut io, &mut scratch)?;
        io.flush()
    })?;
    let appended = writer.file_lifecycle(&mut io, root, "append.bin", None, &sd, 0, &mut scratch)?;
    eprintln!("stage: append");
    let append_block = vec![b'a'; 65536];
    let append = seconds(|| {
        for i in 0..128 {
            writer.write(&mut io, appended, i * 65536, &append_block, &mut scratch)?;
        }
        writer.drain(&mut io, &mut scratch)?;
        io.flush()
    })?;
    let names = seconds(|| {
        eprintln!("stage: names");
        let mut references = Vec::with_capacity(20);
        for i in 0..20 {
            let name = format!("entry-{i:04}");
            references.push(writer.file_lifecycle(&mut io, root, &name, None, &sd, 0, &mut scratch).map_err(
                |error| {
                    eprintln!("create {i}: {error:?}");
                    error
                },
            )?);
        }
        for (i, reference) in references.into_iter().enumerate() {
            let name = format!("entry-{i:04}");
            writer.file_lifecycle(&mut io, root, &name, Some(reference), &[], 0, &mut scratch).map_err(|error| {
                eprintln!("delete {i}: {error:?}");
                error
            })?;
        }
        writer.drain(&mut io, &mut scratch)?;
        io.flush()
    })?;
    let sync_file = writer.file_lifecycle(&mut io, root, "sync.bin", None, &sd, 0, &mut scratch)?;
    eprintln!("stage: sync each");
    let sync_each = seconds(|| {
        for i in 0..100 {
            writer.write(&mut io, sync_file, i * 4096, &block, &mut scratch)?;
            writer.drain(&mut io, &mut scratch)?;
            io.flush()?;
        }
        Ok(())
    })?;
    writer.finish(&mut io, &mut scratch)?;
    println!("overwrite_4k_512={overwrite:.6}");
    println!("append_64k_128={append:.6}");
    println!("create_unlink_20={names:.6}");
    println!("append_fsync_4k_100={sync_each:.6}");
    Ok(())
}
