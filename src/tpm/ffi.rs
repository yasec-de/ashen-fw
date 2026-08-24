use alloc::vec::Vec;
use core::ffi::{CStr, c_char, c_int};

unsafe extern "C" {
    fn ashen_tpm_init() -> c_int;
    fn ashen_tpm_reinit() -> c_int;
    fn ashen_tpm_shutdown() -> c_int;
    fn ashen_tpm_reset_client();
    fn ashen_tpm_process(cmd: *const u8, cmd_len: c_int, rsp: *mut u8, rsp_len: *mut c_int)
    -> c_int;
    fn ashen_tpm_max_command_size() -> c_int;
    fn ashen_tpm_ctx_size() -> c_int;
    fn ashen_tpm_version() -> *const c_char;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NotInitialised,
    Rejected(c_int),
    Oversized,
}

pub fn max_command_size() -> usize {
    unsafe { ashen_tpm_max_command_size() as usize }
}

pub fn context_size() -> usize {
    unsafe { ashen_tpm_ctx_size() as usize }
}

pub fn version() -> &'static str {
    unsafe { CStr::from_ptr(ashen_tpm_version()) }
        .to_str()
        .unwrap_or("unknown")
}

/// Brings up the TPM. Hierarchy seeds are drawn from the RNG here and live
/// only in RAM, so this establishes a fresh TPM identity every time it runs.
pub fn init() -> Result<(), Error> {
    super::masked_nv::init();
    super::masked_slots::init();
    match unsafe { ashen_tpm_init() } {
        0 => Ok(()),
        rc => Err(Error::Rejected(rc)),
    }
}

/// Destroys the TPM identity and builds a new one. Used on `SessionEnd::Erased`
/// so that an erased device does not present its old endorsement key.
pub fn reinit() -> Result<(), Error> {
    super::masked_slots::zeroize_all();
    let rc = unsafe { ashen_tpm_reinit() };
    if rc != 0 {
        return Err(Error::Rejected(rc));
    }
    Ok(())
}

pub fn shutdown() {
    super::masked_slots::zeroize_all();
    unsafe { ashen_tpm_shutdown() };
}

/// Drops transient objects, sessions and hash sequences, so a peer that
/// reconnects cannot inherit the previous peer's handles. The TPM identity
/// survives.
pub fn reset_client() {
    unsafe { ashen_tpm_reset_client() }
}

/// Runs one TPM 2.0 command. `Ok` means the command was processed; a
/// TPM-level failure is encoded in the response body, not here.
pub fn process(cmd: &[u8]) -> Result<Vec<u8>, Error> {
    let max = max_command_size();
    if cmd.len() > max {
        return Err(Error::Oversized);
    }

    let mut rsp = alloc::vec![0u8; max];
    let mut rsp_len: c_int = max as c_int;

    let rc = unsafe {
        ashen_tpm_process(
            cmd.as_ptr(),
            cmd.len() as c_int,
            rsp.as_mut_ptr(),
            &mut rsp_len,
        )
    };
    if rc != 0 {
        return Err(Error::Rejected(rc));
    }
    if rsp_len < 0 || rsp_len as usize > max {
        return Err(Error::Oversized);
    }

    rsp.truncate(rsp_len as usize);
    Ok(rsp)
}
