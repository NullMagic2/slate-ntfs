//! Module: examples.read_security
//! Purpose: Read a security descriptor from an offline NTFS image.
//! Created: 2026-10-02
//! Architecture: Adapts a read-only host file to Volume; security_store owns descriptor lookup and validation.

//! Read a descriptor by MFT record number from an offline image, never writable.
use ntfs_rs::{
    boot::BootSector,
    mft::MftRecord,
    security_store,
    volume::{ReadAt, Volume},
    Error,
};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};
struct Reader(File);
impl ReadAt for Reader {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> ntfs_rs::Result<()> {
        self.0.seek(SeekFrom::Start(offset)).and_then(|_| self.0.read_exact(output)).map_err(|_| Error::Io)
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: read_security IMAGE MFT_RECORD".into());
    }
    let result = run(&args[1], args[2].parse()?);
    match result {
        Ok(bytes) => {
            for byte in bytes {
                print!("{byte:02x}");
            }
            println!();
            Ok(())
        }
        Err(e) => Err(e.to_string().into()),
    }
}
fn run(path: &str, number: u64) -> ntfs_rs::Result<Vec<u8>> {
    let mut reader = Reader(File::open(path).map_err(|_| Error::Io)?);
    let mut boot = [0; 512];
    reader.read_exact_at(0, &mut boot)?;
    let boot = BootSector::parse(&boot)?;
    let mut volume = Volume::new(reader, boot)?;
    let mut zero = vec![0; boot.record_bytes as usize];
    volume.read_mft_zero(&mut zero)?;
    let mft = MftRecord::parse(&mut zero, boot.bytes_per_sector)?;
    let mut file = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, number, &mut file)?;
    let file = MftRecord::parse(&mut file, boot.bytes_per_sector)?;
    let mut secure = vec![0; boot.record_bytes as usize];
    let mut index = vec![0; boot.index_block_bytes as usize];
    let mut output = vec![0; 0x20014];
    let descriptor = security_store::read_descriptor(&mut volume, &mft, &file, &mut secure, &mut index, &mut output)?;
    Ok(descriptor.raw().to_vec())
}
