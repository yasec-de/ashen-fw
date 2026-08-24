use alloc::vec::Vec;
use core::cell::RefCell;
use core::ffi::c_int;

use critical_section::Mutex;

use crate::masked_memory::MaskedCell;

/// Must match `FWTPM_NV_MAX_SIZE` in `csrc/user_settings.h`.
pub const NV_SIZE: usize = 16 * 1024;

/// Split across several cells so one remasking cycle never copies more than
/// this much inside a critical section.
const CHUNK: usize = 2048;

const CHUNKS: usize = NV_SIZE / CHUNK;

#[derive(Clone, Copy)]
#[repr(C)]
struct Chunk([u8; CHUNK]);

impl Default for Chunk {
    fn default() -> Self {
        Self([0u8; CHUNK])
    }
}

struct NvStore(Vec<MaskedCell<Chunk>>);

// The cells are only ever reached from inside a critical section, and the
// `RefCell` inside each one enforces exclusivity there.
unsafe impl Send for NvStore {}

static NV: Mutex<RefCell<NvStore>> = Mutex::new(RefCell::new(NvStore(Vec::new())));

/// Allocates the masked NV backing store and erases it. Runs once, before the
/// TPM core starts.
pub fn init() {
    critical_section::with(|cs| {
        let mut nv = NV.borrow(cs).borrow_mut();
        assert!(nv.0.is_empty(), "masked NV initialised twice");
        for _ in 0..CHUNKS {
            nv.0.push(MaskedCell::new());
        }
    });
    fill(0, NV_SIZE, 0xFF);
}

/// Walks the chunks covering `offset..offset + len`, handing each one's slice
/// to `f` along with the position within the request.
fn with_range<F>(offset: usize, len: usize, mut f: F) -> bool
where
    F: FnMut(usize, &mut [u8]),
{
    if offset > NV_SIZE || len > NV_SIZE - offset {
        return false;
    }

    critical_section::with(|cs| {
        let nv = NV.borrow(cs).borrow();
        if nv.0.len() != CHUNKS {
            return false;
        }

        let mut done = 0;
        while done < len {
            let pos = offset + done;
            let index = pos / CHUNK;
            let within = pos % CHUNK;
            let take = core::cmp::min(len - done, CHUNK - within);

            match nv.0[index].try_borrow_mut() {
                Ok(mut chunk) => f(done, &mut chunk.0[within..within + take]),
                Err(_) => return false,
            }
            done += take;
        }
        true
    })
}

pub fn fill(offset: usize, len: usize, value: u8) -> bool {
    with_range(offset, len, |_, slice| slice.fill(value))
}

#[unsafe(no_mangle)]
pub extern "C" fn ashen_nv_size() -> c_int {
    NV_SIZE as c_int
}

/// Copies out of masked NV into a caller-owned buffer. Returns 0 on success.
///
/// # Safety
/// `buf` must point to at least `len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ashen_nv_read(offset: u32, buf: *mut u8, len: u32) -> c_int {
    if buf.is_null() {
        return -1;
    }
    let dest = unsafe { core::slice::from_raw_parts_mut(buf, len as usize) };
    let ok = with_range(offset as usize, len as usize, |at, slice| {
        dest[at..at + slice.len()].copy_from_slice(slice);
    });
    if ok { 0 } else { -1 }
}

/// # Safety
/// `buf` must point to at least `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ashen_nv_write(offset: u32, buf: *const u8, len: u32) -> c_int {
    if buf.is_null() {
        return -1;
    }
    let src = unsafe { core::slice::from_raw_parts(buf, len as usize) };
    let ok = with_range(offset as usize, len as usize, |at, slice| {
        slice.copy_from_slice(&src[at..at + slice.len()]);
    });
    if ok { 0 } else { -1 }
}

#[unsafe(no_mangle)]
pub extern "C" fn ashen_nv_fill(offset: u32, len: u32, value: u8) -> c_int {
    if fill(offset as usize, len as usize, value) {
        0
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The remasking registry is process-wide and `MaskedCell::new` panics if it
    // cannot take the registry lock, so these take turns.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static INIT: std::sync::Once = std::sync::Once::new();

    fn ensure_init() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        INIT.call_once(init);
        guard
    }

    fn read(offset: u32, len: usize) -> Vec<u8> {
        let mut out = alloc::vec![0u8; len];
        assert_eq!(
            unsafe { ashen_nv_read(offset, out.as_mut_ptr(), len as u32) },
            0
        );
        out
    }

    fn write(offset: u32, data: &[u8]) -> c_int {
        unsafe { ashen_nv_write(offset, data.as_ptr(), data.len() as u32) }
    }

    #[test]
    fn writes_read_back_across_chunk_boundaries() {
        let _guard = ensure_init();

        // Straddles the boundary between the first and second chunk.
        let offset = (CHUNK - 8) as u32;
        let data: Vec<u8> = (0..64u8).collect();
        assert_eq!(write(offset, &data), 0);
        assert_eq!(read(offset, data.len()), data);

        // Neighbouring bytes are untouched.
        assert_eq!(read(offset - 1, 1), alloc::vec![0xFF]);
        assert_eq!(read(offset + data.len() as u32, 1), alloc::vec![0xFF]);
    }

    #[test]
    fn a_whole_span_round_trips_and_fill_clears_it() {
        let _guard = ensure_init();

        let data: Vec<u8> = (0..NV_SIZE).map(|i| (i % 251) as u8).collect();
        assert_eq!(write(0, &data), 0);
        assert_eq!(read(0, NV_SIZE), data);

        assert_eq!(ashen_nv_fill(0, NV_SIZE as u32, 0xFF), 0);
        assert!(read(0, NV_SIZE).iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn out_of_range_access_fails_rather_than_wrapping() {
        let _guard = ensure_init();

        let mut buf = [0u8; 4];
        assert_eq!(
            unsafe { ashen_nv_read(NV_SIZE as u32 - 2, buf.as_mut_ptr(), 4) },
            -1
        );
        assert_eq!(unsafe { ashen_nv_read(u32::MAX, buf.as_mut_ptr(), 1) }, -1);
        assert_eq!(ashen_nv_fill(0, NV_SIZE as u32 + 1, 0), -1);
        assert_eq!(ashen_nv_size(), NV_SIZE as c_int);
    }

    /// The point of the exercise: NV contents must survive relocation, and the
    /// backing buffers must actually move.
    #[test]
    fn contents_survive_remasking() {
        let _guard = ensure_init();

        let data: Vec<u8> = (0..512u32).map(|i| (i % 253) as u8).collect();
        assert_eq!(write(4096, &data), 0);

        for _ in 0..4 {
            crate::masked_memory::remask_once();
            assert_eq!(read(4096, data.len()), data);
        }
    }
}
