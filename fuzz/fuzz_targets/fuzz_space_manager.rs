#![no_main]

use libfuzzer_sys::fuzz_target;
use scb_vka_io::manager::{SpaceManager, RESERVED_BLOCKS};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let base_blocks = u64::from(data[0] % 64) + RESERVED_BLOCKS + 1;
    let mut sm = match SpaceManager::new(base_blocks) {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut allocations: Vec<(u64, u64)> = Vec::new();

    for chunk in data[1..].chunks(3).take(256) {
        let op = chunk[0] % 4;
        let n = u64::from(*chunk.get(1).unwrap_or(&1) % 32) + 1;
        let idx = usize::from(*chunk.get(2).unwrap_or(&0));

        match op {
            0 => {
                if let Ok(start) = sm.allocate(n) {
                    allocations.push((start, n));
                    if allocations.len() > 128 {
                        allocations.remove(0);
                    }
                }
            }
            1 => {
                if !allocations.is_empty() {
                    let i = idx % allocations.len();
                    let (start, count) = allocations.swap_remove(i);
                    let _ = sm.deallocate(start, count);
                } else {
                    let _ = sm.deallocate(RESERVED_BLOCKS, n);
                }
            }
            2 => {
                let grow = u64::from(*chunk.get(1).unwrap_or(&0) % 64);
                let _ = sm.expand(grow);
            }
            _ => {
                let bitmap = sm.export_bitmap();
                let _ = SpaceManager::from_bytes(bitmap, sm.total_blocks());
            }
        }
    }
});
