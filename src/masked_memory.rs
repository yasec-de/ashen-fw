/** Masked memory: RefCell-like thing that wear-levels the memory underneath a 
 *  value to mitigate SRAM remanence effects.
 * 
 *  Beware, this file contains some memory crimes. 
 * 
 *  Embedded microcontrollers use SRAM memory for RAM and registers. SRAM 
 *  memory cells consist of several (usually 4 or 6) transistors, half of which 
 *  are turned on and the other half of which are turned off. The state of the 
 *  cell can be switched by switching which transistors are turned off.
 * 
 *  As a result of this architecture, during operation, when storing static 
 *  content, half the transistors of an SRAM cell are permanently ON and the 
 *  other half are permanently OFF. The ON transistors permanently pass a small 
 *  current, and experience different static voltage levels at their terminals 
 *  compared to the OFF transistors.
 * 
 *  Over long periods of time, this difference in operating conditions leads to 
 *  slow, asymmetric degradation of the transistors in an SRAM cell. The major 
 *  causes of this degradation are electromigration and hot carrier injection. 
 *  In electromigration, the DC current's electrons kick around metal atoms, 
 *  slowly displacing them and physically deforming the conductor. Hot carrier 
 *  injection is a process where electrons (charge carriers) get "wedged"
 *  inside the chip's silicon dioxide insulating material. The static electric
 *  field of many such electrons wedged in odd places can eventually add up to
 *  (slightly) distort the operation of its transistors.
 * 
 *  An attacker can measure this long-time wear using standard semiconductor
 *  fault analysis techniques such as looking at the device under a scanning
 *  electron microscope. When wear has progressed, it eventually starts 
 *  affecting the turn-on behavior of the SRAM cells. SRAM cells are symmetric, 
 *  and whether they flip into a stable "1" or "0" state on power-up depends on
 *  which of their transistors are "faster", i.e. have lower threshold voltages.
 *  In SRAM inside microcontrollers and other complex chips, this behavior is 
 *  accepted, and the memory cells usually still contain this random initial
 *  state after the program starts running. An attacker can use this to
 *  statistically profile the behavior of the cell and gain some amount of
 *  information about its past contents.
 * 
 *  In our application, this is problematic since it may allow for the recovery
 *  of cryptographic secrets after they have been deleted. This is especially
 *  problematic since cryptographic secrets such as keys are the kind of thing
 *  you'd put in some memory location, and then leave it there for the life of
 *  the device.
 * 
 *  The construction in this file largely mitigates this issue by keeping an 
 *  instance of a type in two alternating buffers. When an user accesses the
 *  instance, they temporarily borrow a ref from the currently active cell
 *  Periodically (every ~2s), a "remask" task runs that swaps the instance
 *  between the active and inactive cells. The data of the old instance that's 
 *  left over in the inactive cell gets inverted in memory to ensure that the 
 *  SRAM cells age evenly.
 * 
 *  Obviously, this requires some unsafe code as we're reading and writing
 *  to the bytes backing a struct's memory.
 * 
 *  An overview of the topic, and an outline of the mitigation can be found in
 *  this classic USENIX paper:
 * 
 *  https://www.usenix.org/legacy/events/sec01/full_papers/gutmann/gutmann.pdf
 */

#[cfg(target_os = "none")]
use embassy_time::{Duration, Ticker};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use alloc::vec::Vec;
use core::cell::{RefCell, Ref, RefMut, BorrowError, BorrowMutError};
use core::mem::{self, MaybeUninit};
use alloc::boxed::Box;

type LiveCell<T> = RefCell<Box<MaybeUninit<T>>>;

trait Remask: Send {
    fn remask(&mut self) -> Result<(), BorrowMutError>;
}

/// List of entries to periodicaly remask in the run() task
static REGISTRY:
    Mutex<CriticalSectionRawMutex, Vec<Box<dyn Remask>>> = Mutex::new(Vec::new());


/// Handle that gets handed out to users. Users should borrow a fresh ref from 
/// this whenever they need to use it, and make sure they return the ref as soon
/// as reasonably possible. Remasking is paused while refs are borrowed, and 
/// will resume once they have been returned.
#[derive(Clone, Copy)]
pub struct MaskedCell<T: 'static> {
    live: &'static LiveCell<T>,
}

struct Masker<T: 'static> {
    live: &'static LiveCell<T>,
    masked: Box<MaybeUninit<T>>,
    /// Tracks skipped masking cycles when the RefCell was in use when we tried
    /// to re-mask
    parity: i32,
}

unsafe impl<T> Send for Masker<T> {}

/// Remasking task to be spawned by the user.
#[cfg(target_os = "none")]
#[embassy_executor::task]
pub async fn run() {
    /* 1789 isn't just the year of the storming of the Bastille, it's also a nice prime number. Since we need take locks of the RefCell here, we don't want this task to run in perfect lockstep with other things. Having it occur at a prime-number millisecond interval is an easy way to make that less likely.
    */
    let mut ticker = Ticker::every(Duration::from_millis(1789));
    loop {
        ticker.next().await;
        for entry in REGISTRY.lock().await.iter_mut() {
            entry.remask().unwrap_or(());
        }
    }
}

impl<T> MaskedCell<T> {
    /// Constructor creating a new masked cell and registering its masking 
    /// store and metadata.
    pub fn new(value: T) -> MaskedCell<T> {
        let live: &'static LiveCell<T> =
            Box::leak(Box::new(RefCell::new(Box::new(MaybeUninit::new(value)))));

        REGISTRY.try_lock().expect("MaskedCell::new called while registry busy").push(Box::new(Masker::new(live)));

        MaskedCell { live }
    }

    pub fn borrow(&self) -> Ref<'_, T> {
        Ref::map(self.live.borrow(), |live| unsafe { live.assume_init_ref() })
    }

    pub fn try_borrow(&self) -> Result<Ref<'_, T>, BorrowError> {
        Ok(Ref::map(self.live.try_borrow()?, |live| unsafe {
            live.assume_init_ref()
        }))
    }

    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        RefMut::map(self.live.borrow_mut(), |live| unsafe {
            live.assume_init_mut()
        })
    }

    pub fn try_borrow_mut(&self) -> Result<RefMut<'_, T>, BorrowMutError> {
        Ok(RefMut::map(self.live.try_borrow_mut()?, |live| unsafe {
            live.assume_init_mut()
        }))
    }
}

impl<T> Masker<T> {
    fn new(live: &'static LiveCell<T>) -> Masker<T> {
        Masker {
            live,
            masked: Box::new(MaybeUninit::zeroed()),
            parity: 0,
        }
    }
}

impl<T> Remask for Masker<T> {
    fn remask(&mut self) -> Result<(), BorrowMutError> {
        if self.parity < 0 {
            self.parity += 1;
            return Ok(());
        }

        critical_section::with(|_| {
            let mut live = match self.live.try_borrow_mut() {
                Ok(guard) => guard,
                Err(err) => {
                    self.parity += 1;
                    if self.parity > 3600 {
                        panic!("Memory remanence countermeasure parity out of bounds");
                    }
                    return Err(err);
                }
            };

            mem::swap(&mut **live, &mut *self.masked);
            mem::swap(&mut *live, &mut self.masked);

            self.parity = -self.parity;

            Ok(())
        })?;

        for byte in self.masked.as_bytes_mut().iter_mut() {
            unsafe {
                byte.write(!byte.assume_init());
            }
        }

        Ok(())
    }
}
