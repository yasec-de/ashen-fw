//! Shared test-only infrastructure, used by both this crate's unit tests and
//! the host-side integration tests under `tests/`.

use alloc::boxed::Box;

use crate::noise_link::Random;

/// A minimal xorshift64* PRNG.
///
/// **Not cryptographically secure.** This exists purely as a deterministic,
/// fast [`Random`] source for tests, so that test runs are fully
/// reproducible. Production code must use a true hardware entropy source
/// (see [`crate::hw_rng`]).
#[derive(Clone)]
pub struct XorShiftRng(u64);

impl XorShiftRng {
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

impl Random for XorShiftRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

/// Returns a fresh, boxed [`XorShiftRng`] seeded with `seed`.
pub fn rng(seed: u64) -> Box<dyn Random> {
    Box::new(XorShiftRng::new(seed))
}
