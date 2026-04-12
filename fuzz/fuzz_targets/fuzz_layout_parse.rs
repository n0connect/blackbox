#![no_main]

use libfuzzer_sys::fuzz_target;
use scb_vka_io::layout::{
    FileTableEntry, Superblock, VaultHeader, FILE_ENTRY_SIZE, SUPERBLOCK_SIZE,
};

fuzz_target!(|data: &[u8]| {
    let mut sb_buf = [0u8; SUPERBLOCK_SIZE];
    let copy_len_sb = data.len().min(SUPERBLOCK_SIZE);
    sb_buf[..copy_len_sb].copy_from_slice(&data[..copy_len_sb]);
    let _ = Superblock::parse(&sb_buf);

    let header_size = std::mem::size_of::<VaultHeader>();
    let mut header_buf = vec![0u8; header_size];
    let copy_len_header = data.len().min(header_size);
    header_buf[..copy_len_header].copy_from_slice(&data[..copy_len_header]);
    let _ = VaultHeader::parse(&header_buf);

    let mut entry_buf = [0u8; FILE_ENTRY_SIZE];
    let copy_len_entry = data.len().min(FILE_ENTRY_SIZE);
    entry_buf[..copy_len_entry].copy_from_slice(&data[..copy_len_entry]);
    let _ = FileTableEntry::parse(&entry_buf);
});
