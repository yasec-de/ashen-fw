pub mod c_heap;
pub mod masked_slots;

#[cfg(target_os = "none")]
pub fn seed_entropy(dest: &mut [u8]) -> Result<(), ()> {
    crate::hw_rng::fill_bytes(dest);
    Ok(())
}

/// Host stand-in for the STM32 TRNG. Deterministic on purpose: the host build
/// exists to exercise the TPM command paths under `cargo test`, not to produce
/// keys anybody trusts.
#[cfg(not(target_os = "none"))]
pub fn seed_entropy(dest: &mut [u8]) -> Result<(), ()> {
    use core::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    for chunk in dest.chunks_mut(8) {
        let mut x = STATE.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        STATE.store(x, Ordering::Relaxed);
        let bytes = x.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    Ok(())
}
