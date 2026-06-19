#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod cobs;
pub mod framing;
#[cfg(target_os = "none")]
pub mod analog_sensors;
#[cfg(target_os = "none")]
pub mod defmt_link;
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
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
