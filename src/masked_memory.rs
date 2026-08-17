
use embassy_time::{Duration, Ticker};
use embassy_sync::blocking_mutex::CriticalSectionMutex;
use crate::hw_rng::{HwRng};
use alloc::vec::Vec;
use core::cell::{RefCell, Ref, RefMut, BorrowError};
use core::slice;
use alloc::boxed::Box;

trait Remask {
    fn remask(&self) -> Result<(), BorrowError>;
}

static REGISTRY:
    CriticalSectionMutex<Vec<
            CriticalSectionMutex<Box<dyn Remask>>>> = CriticalSectionMutex::new(
                vec::new());


pub struct MaskedCell<T> {
    live: RefCell<T>,
    masked: RefCell<T>,
    parity: i32,
    mask: u32,
}

#[embassy_executor::task]
async fn run(interval: Duration) {
     let mut ticker = Ticker::every(interval);
     loop {
        ticker.next().await;
        for &entry in REGISTRY.lock().await {
            entry.lock().await.borrow_mut().remask().unwrap_or(());
        }
    }
}

pub async fn register_masked<T>(value: T) {
    let elem = REGISTRY.lock().await.push_mut(CriticalSectionMutex::new(Box::new(MaskedCell::new(value))));
    elem.lock().await;
}

impl<T> MaskedCell<T> {
    pub const fn new(value: T) -> MaskedCell<T> {
        let mut mask: [u8; 4];
        HwRng::new().try_fill_bytes(&mut mask);
        
        MaskedCell {
            live: RefCell::new(value),
            masked: RefCell::new(value),
            parity: 0,
            mask: u32::from_le_bytes(mask),
        }
    }

    pub const fn borrow(&self) -> Ref<'_, T> {
        self.live.borrow();
    }

    pub const fn try_borrow(&self) -> Result<Ref<'_, T>, BorrowError> {
        return self.live.try_borrow();
    }

    pub const fn borrow_mut(&self) -> RefMut<'_, T> {
        self.live.borrow_mut();
    }

    pub const fn try_borrow_mut(&self) -> Result<RefMut<'_, T>, BorrowError> {
        return self.live.try_borrow_mut();
    }
}

impl<T> Remask for MaskedCell<T> {
    fn remask(&self) -> Result<(), BorrowError> {
        if self.parity < 0 {
            self.parity += 1;
            return;
        }

        critical_section::with(|cs| {
            match self.live.try_borrow_mut() {
                Ok(b) => {
                    drop(b);
                    self.live.swap(self.masked);
                    self.parity = -self.parity;
                    Ok(())
                },
                Err(err) => {
                    self.parity += 1;
                    return Err(err);
                }
            }
        });

        let b = self.masked.borrow_mut().expect();
        unsafe {
            let slice = slice::from_raw_parts_mut(
                (b.as_ptr() as *mut T) as *mut u32,
                size_of::<T>(),
            );
            for elem in slice {
                *elem ^= self.mask;
            }
        }
    }
}