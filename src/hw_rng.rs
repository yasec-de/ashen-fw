//! Hardware random number generation, backed by the STM32G4's RNG
//! peripheral.
//!
//! This module provides [`HwRng`], an implementation of
//! [`crate::noise_link::Random`] (snow's RNG trait) suitable for use with
//! [`crate::noise_link::generate_keypair`] and
//! [`crate::noise_link::NoiseLink::responder_handshake`].

use embassy_stm32::rng::{Instance, Rng};

use crate::noise_link::Random;

/// A [`Random`] source backed by the STM32 hardware RNG peripheral.
///
/// Internally this waits (busy-polling, via [`embassy_futures::block_on`])
/// for the peripheral to signal that fresh random data is ready, and
/// recovers from seed/clock errors by resetting the peripheral and retrying,
/// up to [`Self::MAX_RETRIES`] times before giving up with
/// [`snow::Error::Rng`].
pub struct HwRng<'d, T: Instance> {
    rng: Rng<'d, T>,
}

impl<'d, T: Instance> HwRng<'d, T> {
    /// Maximum number of times a failed fill is retried (after resetting the
    /// peripheral) before [`Random::try_fill_bytes`] gives up.
    const MAX_RETRIES: u32 = 8;

    /// Wraps an already-initialized RNG peripheral.
    pub fn new(rng: Rng<'d, T>) -> Self {
        Self { rng }
    }
}

impl<'d, T: Instance + Sync> Random for HwRng<'d, T> {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        for _ in 0..Self::MAX_RETRIES {
            match embassy_futures::block_on(self.rng.async_fill_bytes(dest)) {
                Ok(()) => return Ok(()),
                // The peripheral reports and recovers from seed/clock
                // errors internally; just retry the fill afterwards.
                Err(embassy_stm32::rng::Error::SeedError | embassy_stm32::rng::Error::ClockError) => {
                    continue;
                }
            }
        }
        Err(snow::Error::Rng)
    }
}
