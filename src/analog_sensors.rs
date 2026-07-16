//! Continuous, hardware-assisted analog watchdog over ADC1.
//!
//! This replaces an earlier polling design with one that never stops watching.
//! A single ADC (ADC1) is run in continuous mode using *both* of its conversion
//! groups:
//!
//! * The **regular group** scans `[VREFINT, ext0, ext1, ...]` into a DMA ring
//!   buffer. VREFINT is always rank 0, so the sequence is non-empty even with no
//!   external channels. [`run_regular_monitor`] reads the buffer on the DMA
//!   half-transfer interrupt, derives the supply voltage (VDDA) from VREFINT, and
//!   range-checks each external input in software (leaving room for richer
//!   filtering later).
//! * The **injected group** holds VREFINT and the internal temperature sensor,
//!   auto-triggered after every regular scan (`JAUTO`), so both are sampled
//!   continuously without their own DMA; their results live in `JDR0` (VREFINT)
//!   and `JDR1` (temperature). The watchdog interrupt handler re-reads these
//!   registers so it reports the value that *actually* tripped the watchdog, not
//!   a stale cached one. (VREFINT is also a regular channel — see below.)
//!
//! Two hardware analog watchdogs provide the hard interlock:
//!
//! * **AWD1** (with input filtering) watches the regular VREFINT channel, i.e.
//!   the supply rail. Its thresholds are fixed: the VREFINT-count ↔ VDDA mapping
//!   is constant (`VDDA = VREF_CALIB_MV * VREFINTCAL / vrefint`), so a VCC window
//!   maps to a fixed VREFINT-count window (inverted: high VCC ⇒ low count).
//! * **AWD2** watches the injected temperature channel. Its thresholds depend on
//!   the live VDDA, so [`run_calibration`] recomputes them periodically.
//!
//! When either watchdog trips, the `ADC1` interrupt fires and the handler
//! **panics** with the offending channel and its reading converted to a physical
//! unit (routed out over the secure link by [`crate::panic_link`]).
//!
//! embassy-stm32 has no analog-watchdog or `JAUTO` API for the U5, so the
//! injected group and both watchdogs are configured through `embassy_stm32::pac`
//! (the `unstable-pac` feature is enabled).
//!
//! # Wiring (caller's responsibility)
//!
//! ```ignore
//! bind_interrupts!(struct Irqs {
//!     GPDMA1_CH0 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::GPDMA1_CH0>;
//! });
//!
//! // DMA buffer length must be 2 * (1 + N_external) * K; the monitor's read
//! // buffer (HALF) is exactly half of it.
//! const N: usize = 1;                       // external channels
//! const FRAME: usize = 1 + N;               // VREFINT + externals
//! const HALF: usize = FRAME * 8;            // samples read per half-buffer
//! const DMA_LEN: usize = HALF * 2;
//! static DMA_BUF: StaticCell<[u16; DMA_LEN]> = StaticCell::new();
//!
//! let externals = [(p.PA0.degrade_adc(), SampleTime::CYCLES160_5)];
//! let limits = [ExternalLimit { name: "vbat_div", min_mv: 0, max_mv: 1800 }];
//! let cfg = WatchdogConfig {
//!     vcc_min_mv: 3000, vcc_max_mv: 3600,
//!     temp_min_c: -40, temp_max_c: 105,
//!     awd1_filter: 4,
//!     calibration_interval: DEFAULT_CALIBRATION_INTERVAL,
//! };
//!
//! let rb = analog_sensors::init(p.ADC1, p.DMA1_CH1, Irqs, DMA_BUF.init([0; DMA_LEN]), externals, &cfg);
//! spawner.must_spawn(regular_task(rb, limits));        // wraps run_regular_monitor::<HALF, N>
//! spawner.must_spawn(calibration_task(cfg.calibration_interval)); // wraps run_calibration
//! ```
//!
//! ADC1 needs a kernel clock: configure the ADC clock source in the RCC config
//! passed to [`embassy_stm32::init`], otherwise conversions never complete.

use core::ptr::read_volatile;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use cortex_m::peripheral::NVIC;
use embassy_stm32::Peri;
use embassy_stm32::adc::{
    Adc, AdcChannel, AdcConfig, AnyAdcChannel, CONTINUOUS, RingBufferedAdc, Resolution, RxDma,
    SampleTime, VREF_CALIB_MV,
};
use embassy_stm32::dma::InterruptHandler as DmaInterruptHandler;
use embassy_stm32::interrupt::typelevel::Binding;
use embassy_stm32::pac;
use embassy_stm32::pac::Interrupt;
use embassy_stm32::pac::adc::vals::Exten;
use embassy_stm32::pac::interrupt;
use embassy_stm32::peripherals::ADC1;
use embassy_time::{Duration, Timer};

/// Resolution we run the ADC at; fixes the full-scale count.
const ADC_RESOLUTION: Resolution = Resolution::BITS12;
/// Full-scale count for [`ADC_RESOLUTION`] (`2**12 - 1`).
const ADC_MAX_COUNT: u32 = 4095;

/// ADC channel numbers on ADC1 (STM32U5).
const VREFINT_CH: u8 = 0;
const TEMPERATURE_CH: u8 = 19;

/// Sample time for the slow internal channels (VREFINT, temperature), which both
/// have long minimum sampling times. The longest setting the U5 main ADC offers
/// (160.5 cycles) keeps them valid across ADC-clock configurations.
const INTERNAL_SAMPLE_TIME: SampleTime = SampleTime::CYCLES160_5;

/// Default interval between automatic VDDA recalibrations / AWD2 threshold updates.
pub const DEFAULT_CALIBRATION_INTERVAL: Duration = Duration::from_secs(10);

// Factory calibration values for the STM32U585, in the packaging/UID flash
// region based at 0x0BFA_0700 (RM0456 / DS13086). stm32-metapac maps neither the
// VREFINT nor the temperature-sensor calibration for the U5, so both are read
// from their documented addresses here.
//
// ponytail: hard-coded DS addresses; if a future part in this family relocates
// the cal block, these three consts are the one place to update.
const VREFINTCAL_ADDR: *const u16 = 0x0BFA_07A5 as *const u16;
// Temperature-sensor cal: raw 12-bit counts captured at VDDA = 3.0 V, at 30 °C
// and 130 °C.
const TS_CAL1_ADDR: *const u16 = 0x0BFA_0710 as *const u16;
const TS_CAL2_ADDR: *const u16 = 0x0BFA_0742 as *const u16;
const TS_CAL1_TEMP_C: i32 = 30;
const TS_CAL2_TEMP_C: i32 = 130;
/// VDDA at which the temperature sensor was factory-calibrated (U5: 3.0 V).
const TS_CAL_VDDA_MV: i32 = 3000;

/// Reads the factory VREFINT calibration count (captured at VDDA = `VREF_CALIB_MV`).
fn vrefint_cal() -> u32 {
    unsafe { read_volatile(VREFINTCAL_ADDR) as u32 }
}

/// Sets an ADC1 channel's sample time. The U5 main ADC splits the sample-time
/// bits across SMPR1 (channels 0..=9) and SMPR2 (channels 10..=19).
fn set_channel_sample_time(ch: u8, t: SampleTime) {
    let ch = ch as usize;
    if ch < 10 {
        pac::ADC1.smpr(0).modify(|w| w.set_smp(ch, t));
    } else {
        pac::ADC1.smpr(1).modify(|w| w.set_smp(ch - 10, t));
    }
}

// Configured limits, stored once by [`init`] so the interrupt handler can name
// the window it crossed.
static VCC_MIN_MV: AtomicU32 = AtomicU32::new(0);
static VCC_MAX_MV: AtomicU32 = AtomicU32::new(0);
static TEMP_MIN_C: AtomicI32 = AtomicI32::new(0);
static TEMP_MAX_C: AtomicI32 = AtomicI32::new(0);

/// Hardware-watchdog configuration for the internal rails.
pub struct WatchdogConfig {
    /// VCC (VDDA) lower bound, in millivolts. Below this AWD1 trips.
    pub vcc_min_mv: u32,
    /// VCC (VDDA) upper bound, in millivolts. Above this AWD1 trips.
    pub vcc_max_mv: u32,
    /// Junction-temperature lower bound, in °C. Below this AWD2 trips.
    pub temp_min_c: i32,
    /// Junction-temperature upper bound, in °C. Above this AWD2 trips.
    pub temp_max_c: i32,
    /// AWD1 input filter: number of consecutive out-of-range samples (0..=7)
    /// required before the watchdog trips. Suppresses glitches.
    pub awd1_filter: u8,
    /// How often [`run_calibration`] re-derives VDDA and rewrites the AWD2
    /// temperature thresholds.
    pub calibration_interval: Duration,
}

/// Range limits for one software-monitored external input.
pub struct ExternalLimit {
    /// Label used in the panic message when this input leaves its range.
    pub name: &'static str,
    pub min_mv: u32,
    pub max_mv: u32,
}

/// Supply voltage (VDDA) in mV implied by a raw VREFINT count.
fn vdda_from_vrefint(vrefint_raw: u16) -> u32 {
    if vrefint_raw == 0 {
        return 0;
    }
    let cal = vrefint_cal();
    VREF_CALIB_MV * cal / vrefint_raw as u32
}

/// Reads the freshest supply voltage (VDDA) from the injected VREFINT result
/// register (`JDR0`). Returns `0` before the first injected conversion completes.
fn live_vdda_mv() -> u32 {
    vdda_from_vrefint(pac::ADC1.jdr(0).read().jdata())
}

/// Converts a raw ratiometric count to millivolts using the given VDDA.
fn raw_to_mv(raw: u16, vdda_mv: u32) -> u32 {
    vdda_mv * raw as u32 / ADC_MAX_COUNT
}

/// Converts a raw temperature-sensor count to °C via the factory two-point
/// calibration, rescaling the reading from the live VDDA to the calibration VDDA.
fn temperature_c(raw: u16, vdda_mv: u32) -> i32 {
    let cal1 = unsafe { read_volatile(TS_CAL1_ADDR) } as i32;
    let cal2 = unsafe { read_volatile(TS_CAL2_ADDR) } as i32;
    let ts = raw as i32 * vdda_mv as i32 / TS_CAL_VDDA_MV;
    (TS_CAL2_TEMP_C - TS_CAL1_TEMP_C) * (ts - cal1) / (cal2 - cal1) + TS_CAL1_TEMP_C
}

/// Fixed AWD1 thresholds (VREFINT counts) for a VCC window. Higher VCC produces a
/// *lower* VREFINT count, so the bounds invert.
fn awd1_thresholds(vcc_min_mv: u32, vcc_max_mv: u32) -> (u16, u16) {
    let cal = vrefint_cal();
    let lt1 = (VREF_CALIB_MV * cal / vcc_max_mv) as u16;
    let ht1 = (VREF_CALIB_MV * cal / vcc_min_mv) as u16;
    (lt1, ht1)
}

/// AWD2 thresholds (full-width ADC counts) for a temperature window at the given
/// live VDDA. Unlike the G4, the U5 main-ADC watchdog thresholds (LTR2/HTR2) are
/// full-resolution, so no truncation to the upper 8 bits is needed.
fn awd2_thresholds(temp_min_c: i32, temp_max_c: i32, vdda_mv: u32) -> (u16, u16) {
    let cal1 = unsafe { read_volatile(TS_CAL1_ADDR) } as i32;
    let cal2 = unsafe { read_volatile(TS_CAL2_ADDR) } as i32;
    let raw = |t: i32| -> i32 {
        let ts = (t - TS_CAL1_TEMP_C) * (cal2 - cal1) / (TS_CAL2_TEMP_C - TS_CAL1_TEMP_C) + cal1;
        (ts * TS_CAL_VDDA_MV / vdda_mv as i32).clamp(0, ADC_MAX_COUNT as i32)
    };
    let lt2 = raw(temp_min_c) as u16;
    let ht2 = raw(temp_max_c) as u16;
    (lt2, ht2)
}

/// An iterator that yields VREFINT first, then the caller's external channels,
/// preserving `ExactSizeIterator` (which [`Adc::into_ring_buffered`] requires and
/// `core::iter::Chain` does not provide).
struct RegularSequence<'d, I> {
    head: Option<(AnyAdcChannel<'d, ADC1>, SampleTime)>,
    rest: I,
}

impl<'d, I> Iterator for RegularSequence<'d, I>
where
    I: ExactSizeIterator<Item = (AnyAdcChannel<'d, ADC1>, SampleTime)>,
{
    type Item = (AnyAdcChannel<'d, ADC1>, SampleTime);

    fn next(&mut self) -> Option<Self::Item> {
        match self.head.take() {
            Some(head) => Some(head),
            None => self.rest.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.rest.len() + self.head.is_some() as usize;
        (n, Some(n))
    }
}

impl<'d, I> ExactSizeIterator for RegularSequence<'d, I> where
    I: ExactSizeIterator<Item = (AnyAdcChannel<'d, ADC1>, SampleTime)>
{
}

/// Sets up ADC1 and returns the running regular-group ring buffer.
///
/// Configures the regular DMA scan (`[VREFINT, externals...]`), the injected
/// temperature channel (auto-triggered via `JAUTO`), and watchdogs AWD1 (VCC) and
/// AWD2 (temperature). The watchdog *interrupts* stay masked until
/// [`run_calibration`] completes its first pass, so a settling supply at power-on
/// cannot trip a spurious panic. Conversions are started before returning.
///
/// `dma_buf.len()` must be `2 * (1 + N) * K` for some `K >= 1`; the monitor's read
/// buffer is exactly `dma_buf.len() / 2`.
pub fn init<'d, D, Irq, const N: usize>(
    adc: Peri<'d, ADC1>,
    dma: Peri<'d, D>,
    irq: Irq,
    dma_buf: &'d mut [u16],
    external: [(AnyAdcChannel<'d, ADC1>, SampleTime); N],
    cfg: &WatchdogConfig,
) -> RingBufferedAdc<'d, ADC1>
where
    D: RxDma<ADC1>,
    Irq: Binding<D::Interrupt, DmaInterruptHandler<D>> + 'd,
{
    VCC_MIN_MV.store(cfg.vcc_min_mv, Ordering::Relaxed);
    VCC_MAX_MV.store(cfg.vcc_max_mv, Ordering::Relaxed);
    TEMP_MIN_C.store(cfg.temp_min_c, Ordering::Relaxed);
    TEMP_MAX_C.store(cfg.temp_max_c, Ordering::Relaxed);

    let adc = Adc::new(
        adc,
        AdcConfig {
            resolution: Some(ADC_RESOLUTION),
            ..Default::default()
        },
    );

    // Enable the internal channels (sets the common-block buffer enables). The
    // temperature marker is dropped; the injected group references it by channel
    // number through the PAC below.
    let vrefint = adc.enable_vrefint().degrade_adc();
    let _temperature = adc.enable_temperature();

    let frame_len = 1 + N;
    let sequence = RegularSequence {
        head: Some((vrefint, INTERNAL_SAMPLE_TIME)),
        rest: external.into_iter(),
    };

    // Regular group: continuous scan into the DMA ring buffer. This leaves the
    // ADC enabled but not started (ADSTART = 0), so the PAC writes below are legal.
    let mut rb = adc.into_ring_buffered(dma, dma_buf, irq, sequence, CONTINUOUS, Exten::DISABLED);
    rb.set_alignment(frame_len);

    // Injected group: VREFINT (JDR0) then temperature (JDR1), auto-triggered
    // after each regular sequence. VREFINT is injected as well as regular so the
    // watchdog ISR can re-read a fresh supply estimate from a register.
    set_channel_sample_time(VREFINT_CH, INTERNAL_SAMPLE_TIME);
    set_channel_sample_time(TEMPERATURE_CH, INTERNAL_SAMPLE_TIME);
    pac::ADC1.jsqr().modify(|w| {
        w.set_jl(1); // two injected conversions
        w.set_jsq(0, VREFINT_CH);
        w.set_jsq(1, TEMPERATURE_CH);
        w.set_jexten(Exten::DISABLED);
    });
    pac::ADC1.cfgr().modify(|w| {
        w.set_jauto(true);
        w.set_jdiscen(false);
        // AWD1: filtered, single regular channel = VREFINT.
        w.set_awd1en(true);
        w.set_awd1sgl(true);
        w.set_awd1ch(VREFINT_CH);
    });

    let (lt1, ht1) = awd1_thresholds(cfg.vcc_min_mv, cfg.vcc_max_mv);
    // On the U5, AWD1's thresholds and its input filter live in the LTR1/HTR1
    // registers (AWDFILT1 in HTR1[31:29]), not a combined TR1 as on the G4.
    pac::ADC1.ltr1().modify(|w| w.set_ltr1(lt1 as u32));
    pac::ADC1.htr1().modify(|w| {
        w.set_htr1(ht1 as u32);
        w.set_awdfilt1(cfg.awd1_filter);
    });

    // AWD2: temperature channel, provisional wide window until the first
    // calibration writes real thresholds.
    pac::ADC1.awd2cr().modify(|w| w.set_awd2ch(TEMPERATURE_CH as usize, true));
    pac::ADC1.ltr2().modify(|w| w.set_ltr2(0));
    pac::ADC1.htr2().modify(|w| w.set_htr2(ADC_MAX_COUNT));

    // Keep watchdog interrupts masked until the first calibration.
    pac::ADC1.ier().modify(|w| {
        w.set_awd1ie(false);
        w.set_awd2ie(false);
    });

    rb.start();
    rb
}

/// Regular-group monitor: continuously reads `[VREFINT, externals...]` from the
/// DMA ring buffer (waking on the half-transfer interrupt) and panics if any
/// external input leaves its configured window. Each frame's external samples are
/// converted with the VDDA derived from that same frame's VREFINT, so the supply
/// estimate is always fresh.
///
/// `HALF` must equal `dma_buf.len() / 2` (and be a multiple of `1 + N`). `N` is the
/// number of external channels and may be `0`. Wrap this in an
/// `#[embassy_executor::task]` in the caller.
pub async fn run_regular_monitor<const HALF: usize, const N: usize>(
    mut rb: RingBufferedAdc<'static, ADC1>,
    limits: [ExternalLimit; N],
) -> ! {
    let frame_len = 1 + N;
    let mut buf = [0u16; HALF];

    loop {
        if rb.read(&mut buf).await.is_err() {
            // Fell behind the DMA; the next read restarts the stream. The
            // hardware watchdogs keep guarding VCC/temperature meanwhile.
            defmt::warn!("analog_sensors: regular ADC ring-buffer overrun");
            continue;
        }

        for frame in buf.chunks_exact(frame_len) {
            let vdda_mv = vdda_from_vrefint(frame[0]);
            for (j, limit) in limits.iter().enumerate() {
                let mv = raw_to_mv(frame[1 + j], vdda_mv);
                if mv < limit.min_mv || mv > limit.max_mv {
                    defmt::panic!(
                        "External ADC input {=str} out of range: {=u32} mV not within [{=u32}, {=u32}] mV",
                        limit.name,
                        mv,
                        limit.min_mv,
                        limit.max_mv,
                    );
                }
            }
        }
    }
}

/// Background calibration: periodically rewrites the live AWD2 temperature
/// thresholds from the latest VDDA, and enables the watchdog interrupts after the
/// first valid VDDA is available. Wrap in an `#[embassy_executor::task]`.
pub async fn run_calibration(interval: Duration) -> ! {
    loop {
        Timer::after(interval).await;

        let vdda_mv = live_vdda_mv();
        if vdda_mv == 0 {
            // No injected VREFINT conversion yet; conversions haven't run.
            continue;
        }

        let (lt2, ht2) = awd2_thresholds(
            TEMP_MIN_C.load(Ordering::Relaxed),
            TEMP_MAX_C.load(Ordering::Relaxed),
            vdda_mv,
        );

        // Update thresholds with the AWD2 interrupt masked to avoid a spurious
        // trip from a transient mismatch during the write.
        pac::ADC1.ier().modify(|w| w.set_awd2ie(false));
        pac::ADC1.ltr2().modify(|w| w.set_ltr2(lt2 as u32));
        pac::ADC1.htr2().modify(|w| w.set_htr2(ht2 as u32));
        pac::ADC1.isr().write(|w| w.set_awd2(true)); // clear any pending flag

        if !pac::ADC1.ier().read().awd1ie() {
            // First valid calibration: clear stale flags and arm both watchdogs.
            pac::ADC1.isr().write(|w| {
                w.set_awd1(true);
                w.set_awd2(true);
            });
            pac::ADC1.ier().modify(|w| {
                w.set_awd1ie(true);
                w.set_awd2ie(true);
            });
            unsafe { NVIC::unmask(Interrupt::ADC1) };
        } else {
            pac::ADC1.ier().modify(|w| w.set_awd2ie(true));
        }
    }
}

/// Analog-watchdog interrupt: an AWD1 (VCC) or AWD2 (temperature) trip is a hard
/// fault, so report it with the reading in physical units and panic.
#[interrupt]
fn ADC1() {
    let isr = pac::ADC1.isr().read();
    // Re-read the freshest injected results so the reported value is the one that
    // tripped the watchdog, not a stale cached estimate. JDR0 = VREFINT, JDR1 = temp.
    let vdda_mv = live_vdda_mv();

    if isr.awd1() {
        defmt::panic!(
            "VCC analog watchdog tripped: {=u32} mV not within [{=u32}, {=u32}] mV",
            vdda_mv,
            VCC_MIN_MV.load(Ordering::Relaxed),
            VCC_MAX_MV.load(Ordering::Relaxed),
        );
    }

    if isr.awd2() {
        let temp_c = temperature_c(pac::ADC1.jdr(1).read().jdata(), vdda_mv);
        defmt::panic!(
            "Temperature analog watchdog tripped: {=i32} C not within [{=i32}, {=i32}] C",
            temp_c,
            TEMP_MIN_C.load(Ordering::Relaxed),
            TEMP_MAX_C.load(Ordering::Relaxed),
        );
    }
}
