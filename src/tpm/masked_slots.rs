use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::{RefCell, RefMut};
use core::ffi::c_int;

use critical_section::Mutex;

use crate::masked_memory::MaskedCell;

pub const SLOT_OWNER_SEED: u32 = 0;
pub const SLOT_ENDORSEMENT_SEED: u32 = 1;
pub const SLOT_PLATFORM_SEED: u32 = 2;
pub const SLOT_NULL_SEED: u32 = 3;
pub const SLOT_CTX_PROTECT_KEY: u32 = 4;
pub const SLOT_OWNER_AUTH: u32 = 5;
pub const SLOT_ENDORSEMENT_AUTH: u32 = 6;
pub const SLOT_PLATFORM_AUTH: u32 = 7;
pub const SLOT_LOCKOUT_AUTH: u32 = 8;
pub const SLOT_NV_INTEGRITY_KEY: u32 = 9;

pub const SLOT_COUNT: u32 = 10;

const SEED_LEN: usize = 48;
const KEY_LEN: usize = 32;
const AUTH_LEN: usize = 72;

#[derive(Clone, Copy)]
#[repr(C)]
struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Default for Secret<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

trait Slot: Send {
    fn len(&self) -> usize;
    fn acquire(&mut self) -> *mut u8;
    fn release(&mut self);
    fn zeroize(&mut self);
    fn is_held(&self) -> bool;
}

struct TypedSlot<const N: usize> {
    cell: MaskedCell<Secret<N>>,
    guard: Option<RefMut<'static, Secret<N>>>,
}

unsafe impl<const N: usize> Send for TypedSlot<N> {}

impl<const N: usize> TypedSlot<N> {
    fn new() -> Self {
        Self {
            cell: MaskedCell::new(),
            guard: None,
        }
    }
}

impl<const N: usize> Slot for TypedSlot<N> {
    fn len(&self) -> usize {
        N
    }

    fn acquire(&mut self) -> *mut u8 {
        if self.guard.is_some() {
            return core::ptr::null_mut();
        }
        match self.cell.try_borrow_mut_static() {
            Ok(mut guard) => {
                let ptr = guard.0.as_mut_ptr();
                self.guard = Some(guard);
                ptr
            }
            Err(_) => core::ptr::null_mut(),
        }
    }

    fn release(&mut self) {
        self.guard = None;
    }

    fn zeroize(&mut self) {
        self.release();
        if let Ok(mut guard) = self.cell.try_borrow_mut_static() {
            guard.0.fill(0);
        }
    }

    fn is_held(&self) -> bool {
        self.guard.is_some()
    }
}

static SLOTS: Mutex<RefCell<Vec<Box<dyn Slot>>>> = Mutex::new(RefCell::new(Vec::new()));

/// Allocates the masked secret slots. Must run once, before the TPM core
/// starts, and after the remasking registry exists.
pub fn init() {
    critical_section::with(|cs| {
        let mut slots = SLOTS.borrow(cs).borrow_mut();
        assert!(slots.is_empty(), "masked slots initialised twice");
        slots.push(Box::new(TypedSlot::<SEED_LEN>::new()));
        slots.push(Box::new(TypedSlot::<SEED_LEN>::new()));
        slots.push(Box::new(TypedSlot::<SEED_LEN>::new()));
        slots.push(Box::new(TypedSlot::<SEED_LEN>::new()));
        slots.push(Box::new(TypedSlot::<KEY_LEN>::new()));
        slots.push(Box::new(TypedSlot::<AUTH_LEN>::new()));
        slots.push(Box::new(TypedSlot::<AUTH_LEN>::new()));
        slots.push(Box::new(TypedSlot::<AUTH_LEN>::new()));
        slots.push(Box::new(TypedSlot::<AUTH_LEN>::new()));
        slots.push(Box::new(TypedSlot::<KEY_LEN>::new()));
        debug_assert_eq!(slots.len(), SLOT_COUNT as usize);
    })
}

/// Wipes every slot. Used when the TPM identity is destroyed on erase.
pub fn zeroize_all() {
    critical_section::with(|cs| {
        for slot in SLOTS.borrow(cs).borrow_mut().iter_mut() {
            slot.zeroize();
        }
    })
}

fn with_slot<R>(handle: u32, f: impl FnOnce(&mut Box<dyn Slot>) -> R, fallback: R) -> R {
    critical_section::with(|cs| {
        let mut slots = SLOTS.borrow(cs).borrow_mut();
        match slots.get_mut(handle as usize) {
            Some(slot) => f(slot),
            None => fallback,
        }
    })
}

/// Borrows a masked secret and returns a pointer to its live buffer, or null
/// if the handle is unknown or already held. Remasking of that slot is
/// suspended until [`ashen_masked_release`], so the pointer stays valid — but
/// only until then.
#[unsafe(no_mangle)]
pub extern "C" fn ashen_masked_acquire(handle: u32) -> *mut u8 {
    with_slot(handle, |slot| slot.acquire(), core::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn ashen_masked_release(handle: u32) {
    with_slot(handle, |slot| slot.release(), ())
}

#[unsafe(no_mangle)]
pub extern "C" fn ashen_masked_size(handle: u32) -> c_int {
    with_slot(handle, |slot| slot.len() as c_int, -1)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The slot table and the remasking registry are process-wide, and
    // `MaskedCell::new` panics if it cannot take the registry lock. Serialise
    // the tests that touch either rather than racing them.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static INIT: std::sync::Once = std::sync::Once::new();

    fn ensure_init() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        INIT.call_once(init);
        guard
    }

    #[test]
    fn acquire_returns_a_writable_buffer_and_release_frees_it() {
        let _guard = ensure_init();

        let p = ashen_masked_acquire(SLOT_OWNER_SEED);
        assert!(!p.is_null());
        assert_eq!(ashen_masked_size(SLOT_OWNER_SEED), SEED_LEN as c_int);

        unsafe { core::slice::from_raw_parts_mut(p, SEED_LEN) }.fill(0xA5);
        ashen_masked_release(SLOT_OWNER_SEED);

        // The value survives release, and comes back on the next acquire.
        let q = ashen_masked_acquire(SLOT_OWNER_SEED);
        assert!(!q.is_null());
        assert!(unsafe { core::slice::from_raw_parts(q, SEED_LEN) }
            .iter()
            .all(|&b| b == 0xA5));
        ashen_masked_release(SLOT_OWNER_SEED);
    }

    #[test]
    fn double_acquire_is_refused_rather_than_aliasing() {
        let _guard = ensure_init();

        let first = ashen_masked_acquire(SLOT_CTX_PROTECT_KEY);
        assert!(!first.is_null());
        // A second acquire must not hand out a second mutable pointer.
        assert!(ashen_masked_acquire(SLOT_CTX_PROTECT_KEY).is_null());

        ashen_masked_release(SLOT_CTX_PROTECT_KEY);
        assert!(!ashen_masked_acquire(SLOT_CTX_PROTECT_KEY).is_null());
        ashen_masked_release(SLOT_CTX_PROTECT_KEY);
    }

    // The whole acquire/release design rests on this: while C holds the
    // pointer the backing buffer must not move, and once C lets go it must.
    #[test]
    fn remasking_is_suspended_while_held_and_resumes_after_release() {
        let _guard = ensure_init();

        let held = ashen_masked_acquire(SLOT_ENDORSEMENT_SEED);
        assert!(!held.is_null());
        unsafe { core::slice::from_raw_parts_mut(held, SEED_LEN) }.fill(0x5A);

        for _ in 0..4 {
            crate::masked_memory::remask_once();
            // Address pinned and contents intact for as long as the guard lives.
            assert_eq!(ashen_masked_acquire(SLOT_ENDORSEMENT_SEED), core::ptr::null_mut());
            assert!(unsafe { core::slice::from_raw_parts(held, SEED_LEN) }
                .iter()
                .all(|&b| b == 0x5A));
        }

        ashen_masked_release(SLOT_ENDORSEMENT_SEED);

        let mut moved = false;
        for _ in 0..4 {
            crate::masked_memory::remask_once();
            let now = ashen_masked_acquire(SLOT_ENDORSEMENT_SEED);
            assert!(!now.is_null());
            assert!(unsafe { core::slice::from_raw_parts(now, SEED_LEN) }
                .iter()
                .all(|&b| b == 0x5A));
            moved |= now != held;
            ashen_masked_release(SLOT_ENDORSEMENT_SEED);
        }
        assert!(moved, "cell never relocated after the guard was dropped");
    }

    #[test]
    fn unknown_handles_fail_closed() {
        let _guard = ensure_init();

        assert!(ashen_masked_acquire(SLOT_COUNT).is_null());
        assert!(ashen_masked_acquire(u32::MAX).is_null());
        assert_eq!(ashen_masked_size(SLOT_COUNT), -1);
        ashen_masked_release(SLOT_COUNT);
    }

    #[test]
    fn zeroize_all_wipes_slots_and_drops_outstanding_guards() {
        let _guard = ensure_init();

        let p = ashen_masked_acquire(SLOT_PLATFORM_AUTH);
        unsafe { core::slice::from_raw_parts_mut(p, AUTH_LEN) }.fill(0xFF);

        // Erase must not be blocked by a slot that is still held.
        zeroize_all();

        let q = ashen_masked_acquire(SLOT_PLATFORM_AUTH);
        assert!(!q.is_null());
        assert!(unsafe { core::slice::from_raw_parts(q, AUTH_LEN) }
            .iter()
            .all(|&b| b == 0));
        ashen_masked_release(SLOT_PLATFORM_AUTH);
    }
}
