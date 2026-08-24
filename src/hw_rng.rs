//! STM32 Hardware random number generation

use core::cell::RefCell;

use critical_section::Mutex;
use embassy_stm32::peripherals::RNG;
use embassy_stm32::rng::Rng;

use crate::noise_link::Random;

static RNG_DRIVER: Mutex<RefCell<Option<Rng<'static, RNG>>>> = Mutex::new(RefCell::new(None));

pub fn init(rng: Rng<'static, RNG>) {
    critical_section::with(|cs| {
        let mut driver = RNG_DRIVER.borrow(cs).borrow_mut();
        assert!(
            driver.is_none(),
            "hw_rng::init() called while the RNG was already in use"
        );
        *driver = Some(rng);
    })
}

/// Fills `dest` from the hardware TRNG.
///
/// Blocking rather than async, and guarded by a critical section rather than
/// an `embassy_sync` mutex, so that it is safe to call from tasks running on
/// executors of different priorities. An async mutex here would deadlock: a
/// high-priority interrupt-executor task spinning in `block_on` waiting for a
/// lock held by a thread-mode task can never make progress, because the
/// thread-mode task cannot run until the interrupt handler returns.
pub fn fill_bytes(dest: &mut [u8]) {
    critical_section::with(|cs| {
        let mut driver = RNG_DRIVER.borrow(cs).borrow_mut();
        let rng = driver.as_mut().expect("HwRng used before hw_rng::init()");
        rng.fill_bytes(dest);
    })
}

pub fn read_word() -> u32 {
    let mut word = [0u8; 4];
    fill_bytes(&mut word);
    u32::from_ne_bytes(word)
}

#[derive(Clone, Copy, Default)]
pub struct HwRng;

impl HwRng {
    pub fn new() -> Self {
        Self
    }

    pub fn read_word(&mut self) -> u32 {
        read_word()
    }
}

impl Random for HwRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        fill_bytes(dest);
        Ok(())
    }
}
