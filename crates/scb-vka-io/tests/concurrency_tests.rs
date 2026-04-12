use scb_vka_common::error::VaultErrorKind;
use scb_vka_io::VaultLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use tempfile::tempdir;

#[test]
fn test_concurrent_lock_acquisition() {
    let dir = tempdir().unwrap();
    let lock_path = dir.path().join("test_kvs.lock");

    // Pre-create the lock file so threads don't fail trying to open a non-existent file
    std::fs::File::create(&lock_path).unwrap();

    let num_threads = 50;
    let mut handles = vec![];

    // Counter for how many threads successfully acquired the lock
    let success_count = Arc::new(AtomicUsize::new(0));
    // Counter for how many threads were correctly rejected with VaultBusy
    let busy_count = Arc::new(AtomicUsize::new(0));

    for _ in 0..num_threads {
        let lock_path_clone = lock_path.clone();
        let success_clone = Arc::clone(&success_count);
        let busy_clone = Arc::clone(&busy_count);

        let handle = thread::spawn(move || {
            // Attempt to acquire lock
            match VaultLock::acquire(&lock_path_clone) {
                Ok(lock) => {
                    success_clone.fetch_add(1, Ordering::SeqCst);
                    // Hold the lock briefly to simulate work and increase collision probability
                    thread::sleep(std::time::Duration::from_millis(10));
                    // Explicitly release (Drop) the lock
                    drop(lock);
                }
                Err(e) => {
                    if e.kind == VaultErrorKind::VaultBusy {
                        busy_clone.fetch_add(1, Ordering::SeqCst);
                    } else {
                        panic!("Unexpected lock acquisition error: {e:?}");
                    }
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to finish
    for handle in handles {
        handle.join().unwrap();
    }

    let final_success = success_count.load(Ordering::SeqCst);
    let final_busy = busy_count.load(Ordering::SeqCst);

    println!("Threads completed. Acquired: {final_success}, Busy: {final_busy}");

    // Assertions
    // At most `num_threads` could succeed, but due to collisions, we expect many `VaultBusy` rejections.
    // What's critical is that NO OTHER errors occurred (success + busy = num_threads).
    assert_eq!(
        final_success + final_busy,
        num_threads,
        "Every thread should either succeed or fail with VaultBusy"
    );

    // At least ONE thread should succeed
    assert!(
        final_success >= 1,
        "At least one thread must acquire the lock"
    );
}
