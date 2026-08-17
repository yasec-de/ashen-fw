#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod cobs;
pub mod framing;
// disabled on the U5 port. The regular-group DMA ring scan relies on
// embassy-stm32's ring-buffered ADC API (`into_ring_buffered`/`RingBufferedAdc`),
// which 0.6 gates to G4/v2/v3-class ADCs and does NOT provide for the U5 (adc_v4).
// The PAC-level injected group + AWD1/AWD2 watchdogs are already U5-ported; re-enable
// this once the ADC is wired into main, either after embassy gains U5 ring support or
// with a hand-rolled GPDMA circular buffer replacing the regular monitor.
// #[cfg(target_os = "none")]
// pub mod analog_sensors;
pub mod log;
#[cfg(target_os = "none")]
pub mod flash_keystore;
#[cfg(target_os = "none")]
pub mod hw_rng;
#[cfg(target_os = "none")]
pub mod sensors;
pub mod noise_link;
#[cfg(target_os = "none")]
pub mod panic_link;
pub mod protocol;
#[cfg(target_os = "none")]
pub mod masked_memory;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
