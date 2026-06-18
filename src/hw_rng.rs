//! Hardware random number generation, backed by the STM32G4's RNG
//! peripheral.
//!
//! This module provides [`HwRng`], an implementation of
//! [`crate::noise_link::Random`] (snow's RNG trait) suitable for use with
//! [`crate::noise_link::generate_keypair`] and
//! [`crate::noise_link::NoiseLink::responder_handshake`].
//!
//! The peripheral is owned by this module: [`init`] is called once at startup
//! to hand over the [`Rng`] driver, after which any number of [`HwRng`]
//! handles can be created freely. Each handle is a zero-sized token; the
//! single underlying driver is shared behind an async [`Mutex`], so handles
//! need neither exclusive access nor a lifetime tied to the peripheral. The
//! mutex serializes callers (only one fill runs at a time) but, unlike a
//! `critical_section`, takes its lock only momentarily on entry/exit rather
//! than masking interrupts for the whole fill.

use embassy_stm32::peripherals::RNG;
use embassy_stm32::rng::Rng;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;

use crate::noise_link::Random;

/// The one RNG driver, installed by [`init`] and shared by all [`HwRng`]
/// handles.
static RNG_DRIVER: Mutex<CriticalSectionRawMutex, Option<Rng<'static, RNG>>> = Mutex::new(None);

/// Installs the RNG driver. Call exactly once, before any [`HwRng`] is used.
///
/// The driver (and thus the peripheral and its clock) lives for the rest of
/// the program; it is never dropped, so the RNG clock is never disabled.
pub fn init(rng: Rng<'static, RNG>) {
    *RNG_DRIVER
        .try_lock()
        .expect("hw_rng::init() called while the RNG was already in use") = Some(rng);
}

/// A [`Random`] source backed by the STM32 hardware RNG peripheral.
///
/// Construct freely with [`HwRng::new`] once [`init`] has run; the handle
/// itself carries no state.
#[derive(Clone, Copy, Default)]
pub struct HwRng;

impl HwRng {
    const MAX_CONSECUTIVE_FAILURES: u32 = 3;

    /// Creates a new RNG handle. [`init`] must have been called first.
    pub fn new() -> Self {
        Self
    }

    pub async fn read_word(&mut self) -> u32 {
        let mut guard = RNG_DRIVER.lock().await;
        let rng = guard.as_mut().expect("HwRng used before hw_rng::init()");

        let mut word = [0u8; 4];
        for _ in 0..Self::MAX_CONSECUTIVE_FAILURES {
            if rng.async_fill_bytes(&mut word).await.is_ok() {
                return u32::from_ne_bytes(word);
            }
        }

        panic!("hardware RNG failed to recover");
    }
}

impl Random for HwRng {
    /// Fills `dest` with hardware random data, retrying across the
    /// peripheral's self-recovery until it succeeds, or panicking after
    /// [`Self::MAX_CONSECUTIVE_FAILURES`] consecutive failures.
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        embassy_futures::block_on(async {
            let mut guard = RNG_DRIVER.lock().await;
            let rng = guard.as_mut().expect("HwRng used before hw_rng::init()");

            let mut failures = 0u32;
            loop {
                match rng.async_fill_bytes(dest).await {
                    Ok(()) => return,
                    Err(_) => {
                        failures += 1;
                        assert!(
                            failures < Self::MAX_CONSECUTIVE_FAILURES,
                            "hardware RNG failed to recover",
                        );
                    }
                }
            }
        });
        Ok(())
    }
}
