
use embassy_stm32::Peri;
use embassy_stm32::gpio::{AnyPin, Input, Output, Level, Speed, Pull};
use embassy_time::Timer;

use crate::hw_rng::HwRng;

pub async fn monitor_contacts<const N: usize, const M: usize>(
    stimulus: [Peri<'static, AnyPin>; N],
    monitor: [Peri<'static, AnyPin>; M],
    mapping: &[usize; M],
) -> ! {
    const { assert!(N <= 32, "Can only handle a maximum of 32 stimulus signals")};
    let mut stim_drv = stimulus.map(|pin| Output::new(pin, Level::Low, Speed::Low));
    let mon_drv = monitor.map(|pin| Input::new(pin, Pull::Up));

    let mut rng = HwRng::new();

    loop {
        let pattern = rng.read_word().await;
        for i in 0..N {
            stim_drv[i].set_level((pattern & (1 << i) != 0).into());
        }

        Timer::after_micros(100).await;
        for i in 0..M {
            let observed = mon_drv[i].is_high();

            if observed != (pattern & (1 << mapping[i]) != 0) {
                crate::error!("Tamper contact {} tripped", i);
            }
        }
    }
}
