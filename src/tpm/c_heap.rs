use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{CStr, c_char, c_int, c_uchar, c_ulong, c_void};
use core::ptr;

pub const C_HEAP_SIZE: usize = 64 * 1024;

const ALIGN: usize = 8;
const HEADER: usize = ALIGN;

static C_HEAP: emballoc::Allocator<C_HEAP_SIZE> = emballoc::Allocator::new();

fn layout(size: usize) -> Layout {
    Layout::from_size_align(size + HEADER, ALIGN).expect("C heap layout")
}

/// # Safety
/// `ptr` must be a pointer previously returned by [`ashen_c_malloc`].
unsafe fn payload_size(ptr: *mut u8) -> usize {
    unsafe { (ptr.sub(HEADER) as *const usize).read() }
}

#[unsafe(no_mangle)]
pub extern "C" fn ashen_c_malloc(size: c_ulong) -> *mut c_void {
    let size = size as usize;
    if size == 0 {
        return ptr::null_mut();
    }

    let block = unsafe { C_HEAP.alloc(layout(size)) };
    if block.is_null() {
        crate::error!("tpm: C heap exhausted requesting {} bytes", size);
        return ptr::null_mut();
    }

    unsafe {
        (block as *mut usize).write(size);
        block.add(HEADER) as *mut c_void
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ashen_c_free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let block = (ptr as *mut u8).sub(HEADER);
        let size = payload_size(ptr as *mut u8);
        ptr::write_bytes(ptr as *mut u8, 0, size);
        C_HEAP.dealloc(block, layout(size));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ashen_c_realloc(ptr: *mut c_void, size: c_ulong) -> *mut c_void {
    if ptr.is_null() {
        return ashen_c_malloc(size);
    }
    if size == 0 {
        ashen_c_free(ptr);
        return ptr::null_mut();
    }

    let old = unsafe { payload_size(ptr as *mut u8) };
    let new_size = size as usize;

    let fresh = ashen_c_malloc(size);
    if fresh.is_null() {
        return ptr::null_mut();
    }
    unsafe { ptr::copy_nonoverlapping(ptr as *const u8, fresh as *mut u8, old.min(new_size)) };
    ashen_c_free(ptr);
    fresh
}

#[unsafe(no_mangle)]
pub extern "C" fn ashen_log_write(buf: *const c_char, len: c_int) -> c_int {
    if buf.is_null() || len <= 0 {
        return 0;
    }
    let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };
    if let Ok(text) = core::str::from_utf8(bytes) {
        let text = text.trim_end();
        if !text.is_empty() {
            crate::info!("tpm: {}", text);
        }
    }
    len
}

#[unsafe(no_mangle)]
pub extern "C" fn ashen_c_panic(msg: *const c_char) -> ! {
    let text = if msg.is_null() {
        "TPM core aborted"
    } else {
        unsafe { CStr::from_ptr(msg) }
            .to_str()
            .unwrap_or("TPM core aborted")
    };
    panic!("{}", text);
}

#[unsafe(no_mangle)]
pub extern "C" fn ashen_rand_generate_seed(output: *mut c_uchar, sz: u32) -> c_int {
    if output.is_null() {
        return -1;
    }
    let dest = unsafe { core::slice::from_raw_parts_mut(output, sz as usize) };
    match crate::tpm::seed_entropy(dest) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_free_round_trips_and_reuses_space() {
        // A bump allocator would exhaust here; a free list must not.
        for _ in 0..512 {
            let p = ashen_c_malloc(1024);
            assert!(!p.is_null());
            unsafe { ptr::write_bytes(p as *mut u8, 0xAB, 1024) };
            ashen_c_free(p);
        }
    }

    #[test]
    fn realloc_preserves_contents_and_shrinks() {
        let p = ashen_c_malloc(64) as *mut u8;
        assert!(!p.is_null());
        for i in 0..64u8 {
            unsafe { p.add(i as usize).write(i) };
        }

        let grown = ashen_c_realloc(p as *mut c_void, 256) as *mut u8;
        assert!(!grown.is_null());
        for i in 0..64u8 {
            assert_eq!(unsafe { grown.add(i as usize).read() }, i);
        }

        let shrunk = ashen_c_realloc(grown as *mut c_void, 16) as *mut u8;
        assert!(!shrunk.is_null());
        for i in 0..16u8 {
            assert_eq!(unsafe { shrunk.add(i as usize).read() }, i);
        }
        ashen_c_free(shrunk as *mut c_void);
    }

    #[test]
    fn free_zeroizes_the_block() {
        let p = ashen_c_malloc(128) as *mut u8;
        unsafe { ptr::write_bytes(p, 0xFF, 128) };
        ashen_c_free(p as *mut c_void);

        // The freed payload must not still hold the secret pattern. Reading
        // freed memory is only sound here because the arena is a static
        // buffer that is never unmapped.
        let residue = unsafe { core::slice::from_raw_parts(p, 128) };
        assert!(residue.iter().all(|&b| b == 0));
    }

    #[test]
    fn exhaustion_returns_null_rather_than_panicking() {
        assert!(ashen_c_malloc((C_HEAP_SIZE * 2) as c_ulong).is_null());
        assert!(ashen_c_malloc(0).is_null());
        ashen_c_free(ptr::null_mut());
    }
}
