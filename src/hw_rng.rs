//! STM32 Hardware random number generation

use core::cell::RefCell;

use critical_section::Mutex;
use embassy_stm32::pac;
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

/// Polls this many times for one 32-bit word before giving up. The TRNG
/// produces a word roughly every 40 kernel-clock cycles, so this is several
/// orders of magnitude of headroom over a healthy part.
const POLL_LIMIT: u32 = 100_000;

/// Reads one word, or `None` if the TRNG flagged an error or never became
/// ready. Register access rather than `Rng::next_u32` because embassy's
/// blocking path retries a seed error forever, which inside our critical
/// section would mean interrupts disabled forever.
fn poll_word() -> Option<u32> {
    for _ in 0..POLL_LIMIT {
        let sr = pac::RNG.sr().read();
        if sr.seis() || sr.ceis() {
            return None;
        }
        if sr.drdy() {
            return Some(pac::RNG.dr().read());
        }
    }
    None
}

/// Fills `dest` from the hardware TRNG.
///
/// Blocking rather than async, and guarded by a critical section rather than
/// an `embassy_sync` mutex, so that it is safe to call from tasks running on
/// executors of different priorities. An async mutex here would deadlock: a
/// high-priority interrupt-executor task spinning in `block_on` waiting for a
/// lock held by a thread-mode task can never make progress, because the
/// thread-mode task cannot run until the interrupt handler returns.
///
/// A seed or clock error, or a word that never arrives, panics. There is no
/// retry: this is an HSM, and a TRNG that fails its health test is a hardware
/// defect to surface, not one to paper over.
pub fn fill_bytes(dest: &mut [u8]) {
    for chunk in dest.chunks_mut(4) {
        // One word per critical section, so the interrupt-off window stays
        // bounded by a single poll, and a failure panics outside it.
        let word = critical_section::with(|cs| {
            let mut driver = RNG_DRIVER.borrow(cs).borrow_mut();
            driver.as_mut().expect("HwRng used before hw_rng::init()");
            poll_word()
        });

        let word = word.expect("hardware TRNG failed to produce a word");
        chunk.copy_from_slice(&word.to_ne_bytes()[..chunk.len()]);
    }
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
