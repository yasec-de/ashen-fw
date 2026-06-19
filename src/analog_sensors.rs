//! Analog watchdog over the STM32G4's ADC1.
//!
//! [`AnalogSensors`] owns ADC1, a DMA channel, and the two internal analog
//! channels (VREFINT and the temperature sensor). It offers a handful of
//! *polling* `check_*` methods that read a channel, convert the raw count into
//! a physical quantity, and **panic** if the value falls outside the limits the
//! caller passes in. The intent is a hard safety interlock: an out-of-range
//! supply rail or junction temperature is treated as unrecoverable, so it trips
//! the panic handler (which reports over the secure link, see
//! [`crate::panic_link`]) rather than being swallowed.
//!
//! # Calibration
//!
//! Absolute ADC readings depend on the true supply/reference voltage (VDDA),
//! which is not known a priori. We recover it from the factory-trimmed internal
//! reference: VREFINT reads a fixed ~1.2 V, and the factory stores the raw count
//! it produced at [`VREF_CALIB_MV`] (`VREFINTCAL`). Measuring VREFINT now gives
//!
//! ```text
//! VDDA = VREF_CALIB_MV * VREFINTCAL / vrefint_now
//! ```
//!
//! from which every other channel converts to millivolts. [`AnalogSensors::new`]
//! calibrates once at construction, and the `check_*` methods recalibrate
//! lazily whenever [`DEFAULT_CALIBRATION_INTERVAL`] (configurable via
//! [`AnalogSensors::set_calibration_interval`]) has elapsed, so VDDA tracks slow
//! supply drift without a dedicated task.
//!
//! # Usage
//!
//! The DMA channel's interrupt must be bound by the caller and the binding
//! handed in, mirroring [`embassy_stm32::adc::Adc::read`]:
//!
//! ```ignore
//! bind_interrupts!(struct Irqs {
//!     DMA1_CH1 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::DMA1_CH1>;
//! });
//!
//! let mut sensors = AnalogSensors::new(p.ADC1, p.DMA1_CH1, Irqs).await;
//! sensors.check_vcc_mv(3000, 3600).await;          // panics outside 3.0–3.6 V
//! sensors.check_temperature_c(-40, 105).await;     // panics outside −40–105 °C
//! sensors.check_external_mv("vbat_div", &mut vbat_chan, SampleTime::CYCLES247_5, 0, 1800).await;
//! ```
//!
//! Note: ADC1 needs a kernel clock; configure the ADC clock source in the RCC
//! config passed to [`embassy_stm32::init`], otherwise conversions never
//! complete.

use core::ptr::read_volatile;

use embassy_stm32::Peri;
use embassy_stm32::adc::{
    Adc, AdcChannel, AdcConfig, AnyAdcChannel, Resolution, RxDma, SampleTime, VrefInt,
    resolution_to_max_count,
};
use embassy_stm32::adc::VREF_CALIB_MV;
use embassy_stm32::dma::InterruptHandler as DmaInterruptHandler;
use embassy_stm32::interrupt::typelevel::Binding;
use embassy_stm32::peripherals::ADC1;
use embassy_time::{Duration, Instant, Timer};

/// Resolution we run the ADC at; fixes the full-scale count.
const ADC_RESOLUTION: Resolution = Resolution::BITS12;

/// Full-scale count for [`ADC_RESOLUTION`] (`2**bits - 1`).
const ADC_MAX_COUNT: u32 = resolution_to_max_count(ADC_RESOLUTION);

/// Sample time used for the slow internal channels (VREFINT, temperature),
/// which both have long minimum sampling times. The longest setting keeps the
/// readings valid across ADC-clock configurations at negligible cost given how
/// rarely we poll.
const INTERNAL_SAMPLE_TIME: SampleTime = SampleTime::CYCLES640_5;

/// Settling time allowed after enabling the internal reference and temperature
/// sensor buffers before the first conversion (datasheet t_START, with margin).
const INTERNAL_STARTUP: Duration = Duration::from_micros(200);

/// Default interval between automatic VDDA recalibrations.
pub const DEFAULT_CALIBRATION_INTERVAL: Duration = Duration::from_secs(10);

// Factory temperature-sensor calibration for the STM32G4 family. Each is a
// right-aligned 12-bit raw ADC count captured at VDDA = `VREF_CALIB_MV`, the
// first at 30 °C and the second at 130 °C (RM0440 / DS12288). stm32-metapac
// maps `VREFINTCAL` but not these, so they are read straight from system
// memory.
const TS_CAL1_ADDR: *const u16 = 0x1FFF_75A8 as *const u16;
const TS_CAL2_ADDR: *const u16 = 0x1FFF_75CA as *const u16;
const TS_CAL1_TEMP_C: i32 = 30;
const TS_CAL2_TEMP_C: i32 = 130;

/// Polling analog watchdog over ADC1; see the [module docs](self).
///
/// Generic over the DMA channel `D` driving the conversions and the interrupt
/// binding `Irq` for that channel's interrupt.
pub struct AnalogSensors<'d, D, Irq>
where
    D: RxDma<ADC1>,
    Irq: Binding<D::Interrupt, DmaInterruptHandler<D>> + Copy + 'static,
{
    adc: Adc<'d, ADC1>,
    dma: Peri<'d, D>,
    irq: Irq,
    vrefint: AnyAdcChannel<'d, ADC1>,
    temperature: AnyAdcChannel<'d, ADC1>,
    /// Factory `VREFINTCAL`: VREFINT raw count at [`VREF_CALIB_MV`].
    vrefint_cal: u32,
    /// Factory temperature calibration counts at 30 °C / 130 °C.
    ts_cal1: i32,
    ts_cal2: i32,
    /// Most recent supply voltage (VDDA) estimate, in millivolts.
    vdda_mv: u32,
    calibration_interval: Duration,
    last_calibration: Instant,
}

impl<'d, D, Irq> AnalogSensors<'d, D, Irq>
where
    D: RxDma<ADC1>,
    Irq: Binding<D::Interrupt, DmaInterruptHandler<D>> + Copy + 'static,
{
    pub async fn new(adc: Peri<'d, ADC1>, dma: Peri<'d, D>, irq: Irq) -> Self {
        let config = AdcConfig {
            resolution: Some(ADC_RESOLUTION),
            ..Default::default()
        };
        let adc = Adc::new(adc, config);

        let vrefint_marker = adc.enable_vrefint();
        let vrefint_cal = vrefint_marker.calibrated_value() as u32;
        let vrefint = vrefint_marker.degrade_adc();
        let temperature = adc.enable_temperature().degrade_adc();

        // Let the reference/temperature buffers settle before converting.
        Timer::after(INTERNAL_STARTUP).await;

        let mut this = Self {
            adc,
            dma,
            irq,
            vrefint,
            temperature,
            vrefint_cal,
            ts_cal1: unsafe { read_volatile(TS_CAL1_ADDR) } as i32,
            ts_cal2: unsafe { read_volatile(TS_CAL2_ADDR) } as i32,
            vdda_mv: VREF_CALIB_MV, // Set on first cal
            calibration_interval: DEFAULT_CALIBRATION_INTERVAL,
            last_calibration: Instant::now(),
        };
        this.calibrate().await;
        this
    }

    pub fn set_calibration_interval(&mut self, interval: Duration) {
        self.calibration_interval = interval;
    }

    pub fn supply_mv(&self) -> u32 {
        self.vdda_mv
    }

    pub async fn calibrate(&mut self) {
        let raw = Self::read_channel(
            &mut self.adc,
            &mut self.dma,
            self.irq,
            &mut self.vrefint,
            INTERNAL_SAMPLE_TIME,
        )
        .await;
        assert!(raw != 0, "VREFINT read back as zero; is the ADC clock enabled?");
        // VDDA = VREF_CALIB_MV * VREFINTCAL / VREFINT_now
        self.vdda_mv = VREF_CALIB_MV * self.vrefint_cal / raw as u32;
        self.last_calibration = Instant::now();
    }

    async fn ensure_calibrated(&mut self) {
        if self.last_calibration.elapsed() >= self.calibration_interval {
            self.calibrate().await;
        }
    }

    pub async fn check_temperature_c(&mut self, min_c: i32, max_c: i32) {
        self.ensure_calibrated().await;
        let raw = Self::read_channel(
            &mut self.adc,
            &mut self.dma,
            self.irq,
            &mut self.temperature,
            INTERNAL_SAMPLE_TIME,
        )
        .await;
        let temp_c = self.raw_to_temperature_c(raw);
        assert_within("die temperature", "C", temp_c, min_c, max_c);
    }

    pub async fn check_vcc_mv(&mut self, min_mv: u32, max_mv: u32) {
        self.calibrate().await;
        assert_within("VCC", "mV", self.vdda_mv as i32, min_mv as i32, max_mv as i32);
    }

    pub async fn check_external_mv(
        &mut self,
        name: &str,
        channel: &mut AnyAdcChannel<'d, ADC1>,
        sample_time: SampleTime,
        min_mv: u32,
        max_mv: u32,
    ) {
        self.ensure_calibrated().await;
        let raw = Self::read_channel(&mut self.adc, &mut self.dma, self.irq, channel, sample_time).await;
        let mv = self.raw_to_mv(raw);
        assert_within(name, "mV", mv as i32, min_mv as i32, max_mv as i32);
    }

    fn raw_to_mv(&self, raw: u16) -> u32 {
        self.vdda_mv * raw as u32 / ADC_MAX_COUNT
    }

    fn raw_to_temperature_c(&self, raw: u16) -> i32 {
        let ts_data = raw as i32 * self.vdda_mv as i32 / VREF_CALIB_MV as i32;
        (TS_CAL2_TEMP_C - TS_CAL1_TEMP_C) * (ts_data - self.ts_cal1) / (self.ts_cal2 - self.ts_cal1)
            + TS_CAL1_TEMP_C
    }

    /// Performs one async DMA conversion of a single channel and returns the raw
    /// count. Takes the constituent fields by individual borrow so the caller
    /// can also hold a disjoint `&mut` to the channel being read.
    async fn read_channel(
        adc: &mut Adc<'d, ADC1>,
        dma: &mut Peri<'d, D>,
        irq: Irq,
        channel: &mut AnyAdcChannel<'d, ADC1>,
        sample_time: SampleTime,
    ) -> u16 {
        let mut reading = [0u16; 1];
        adc.read(
            dma.reborrow(),
            irq,
            [(channel, sample_time)].into_iter(),
            &mut reading,
        )
        .await;
        reading[0]
    }
}

fn assert_within(name: &str, unit: &str, value: i32, min: i32, max: i32) {
    if value < min || value > max {
        defmt::panic!(
            "Analog sensor {=str} out of range: {=i32} {=str} not within [{=i32}, {=i32}]",
            name,
            value,
            unit,
            min,
            max,
        );
    }
}
