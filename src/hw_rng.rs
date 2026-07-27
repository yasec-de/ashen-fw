//! STM32 Hardware random number generation

use embassy_stm32::peripherals::RNG;
use embassy_stm32::rng::Rng;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;

use crate::noise_link::Random;

static RNG_DRIVER: Mutex<CriticalSectionRawMutex, Option<Rng<'static, RNG>>> = Mutex::new(None);

pub fn init(rng: Rng<'static, RNG>) {
    *RNG_DRIVER
        .try_lock()
        .expect("hw_rng::init() called while the RNG was already in use") = Some(rng);
}

#[derive(Clone, Copy, Default)]
pub struct HwRng;

impl HwRng {
    const MAX_CONSECUTIVE_FAILURES: u32 = 3;

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
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        embassy_futures::block_on(async {
            for chunk in dest.chunks_mut(4) {
                let bytes = self.read_word().await.to_ne_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        });
        Ok(())
    }
}
