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
    flush_wipe_and(Halt::Fault)
}

/// What to do once SRAM has been wiped.
pub enum Halt {
    /// Fault and stay dead until externally reset.
    Fault,
    /// Reset the MCU, so it comes back up unkeyed with a freshly manufactured TPM.
    Reset,
}

/// Flush queued log messages over the link (best effort), then wipe all SRAM
/// (TPM seeds and NV, masked key slots, session keys, stacks) and halt.
pub fn flush_wipe_and(halt: Halt) -> ! {
    let link = critical_section::with(|cs| PANIC_LINK.borrow_ref_mut(cs).take());
    if let Some(link) = link {
        link.flush_log_queue();
    }
    wipe_and(halt)
}

/// Wipe all SRAM and halt, without touching the link.
pub fn wipe_and(halt: Halt) -> ! {
    cortex_m::interrupt::disable();

    unsafe extern "C" {
        static mut _ram_start: u32;
        static mut _ram_end: u32;
    }

    match halt {
        Halt::Fault => unsafe {
            core::arch::asm!(
                // clear SHCSR.USGFAULTENA, make udf hard fault
                "  ldr  {val}, [{shcsr}]",
                "  bic  {val}, {val}, #(1 << 18)",
                "  str  {val}, [{shcsr}]",
                // the wipe below stores {val}; make sure that's zero, not SHCSR
                "  mov  {val}, #0",
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
        },
        Halt::Reset => unsafe {
            core::arch::asm!(
                // wipe all SRAM memory
                "1:",
                "  str  {zero}, [{ptr}], #4",
                "  cmp  {ptr}, {end}",
                "  blo  1b",
                // AIRCR = VECTKEY | SYSRESETREQ
                "  dsb",
                "  str  {req}, [{aircr}]",
                "  dsb",
                "2:",
                "  b    2b",
                ptr = in(reg) &raw mut _ram_start,
                end = in(reg) &raw mut _ram_end,
                zero = in(reg) 0u32,
                req = in(reg) 0x05FA_0004u32,
                aircr = in(reg) 0xE000_ED0Cu32,
                options(nostack, noreturn),
            );
        },
    }
}
