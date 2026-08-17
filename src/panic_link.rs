//! Best-effort reporting of firmware panics over the secure Noise channel.

use core::cell::RefCell;

use critical_section::Mutex;
use embedded_io_async::{Read, Write as IoWrite};

use crate::noise_link::NoiseLink;

pub trait PanicReport: Send {
    fn flush_log_queue(&mut self);
}

/// Allows registering a slot that is briefly empty while the link is being
/// re-handshaked (see the session loop in `main`).
impl<T: Read + IoWrite + Send> PanicReport for Option<NoiseLink<T>> {
    fn flush_log_queue(&mut self) {
        if let Some(link) = self {
            let _ = embassy_futures::block_on(NoiseLink::drain_log_queue(link));
        }
    }
}

static PANIC_LINK: Mutex<RefCell<Option<&'static mut dyn PanicReport>>> =
    Mutex::new(RefCell::new(None));

pub fn register(link: &'static mut dyn PanicReport) {
    critical_section::with(|cs| {
        *PANIC_LINK.borrow_ref_mut(cs) = Some(link);
    });
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::error!("panic: {}", info);

    let link = critical_section::with(|cs| PANIC_LINK.borrow_ref_mut(cs).take());
    if let Some(link) = link {
        link.flush_log_queue();
    }

    cortex_m::interrupt::disable();

    unsafe extern "C" {
        static mut _ram_start: u32;
        static mut _ram_end: u32;
    }

    unsafe {
        core::arch::asm!(
            // clear SHCSR.USGFAULTENA, make udf hard fault
            "  ldr  {val}, [{shcsr}]",
            "  bic  {val}, {val}, #(1 << 18)",
            "  str  {val}, [{shcsr}]",
            // wipe all SRAM memory
            "1:",
            "  str  {val}, [{ptr}], #4",
            "  cmp  {ptr}, {end}",
            "  blo  1b",
            // execute the undefined instruction
            "2:",
            "  udf  #0",
            "  b    2b",
            ptr = in(reg) &raw mut _ram_start,
            end = in(reg) &raw mut _ram_end,
            val = in(reg) 0u32,
            shcsr = in(reg) 0xE000ED24u32,
            options(nostack, noreturn),
        );
    }
}
