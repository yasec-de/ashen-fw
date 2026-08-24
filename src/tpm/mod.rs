pub mod c_heap;
pub mod ffi;
pub mod masked_slots;

pub use ffi::{Error, init, max_command_size, process, reinit, reset_client, shutdown, version};

/// Runs one TPM command on behalf of a session.
///
/// On the firmware this hands the command to [`task`], which runs on the
/// low-priority thread-mode executor, and awaits the reply — so a
/// hundred-millisecond key generation cannot stall the link, the log pipe or
/// the heartbeat, which all live on a higher-priority executor. On the host
/// there is only one executor, so it calls straight through.
#[cfg(target_os = "none")]
pub async fn dispatch(cmd: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    channel::COMMANDS.send(cmd.into()).await;
    channel::RESPONSES.receive().await
}

#[cfg(not(target_os = "none"))]
pub async fn dispatch(cmd: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    process(cmd)
}

#[cfg(target_os = "none")]
mod channel {
    use alloc::vec::Vec;

    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::channel::Channel;

    use super::Error;

    pub(super) static COMMANDS: Channel<CriticalSectionRawMutex, Vec<u8>, 1> = Channel::new();
    pub(super) static RESPONSES: Channel<CriticalSectionRawMutex, Result<Vec<u8>, Error>, 1> =
        Channel::new();
}

/// Serves TPM commands. Spawn on the low-priority executor; the blocking C
/// call inside must be preemptible by the link tasks.
#[cfg(target_os = "none")]
#[embassy_executor::task]
pub async fn task() {
    loop {
        let cmd = channel::COMMANDS.receive().await;
        let result = process(&cmd);
        channel::RESPONSES.send(result).await;
    }
}

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn ashen_now_ms() -> u64 {
    embassy_time::Instant::now().as_millis()
}

#[cfg(not(target_os = "none"))]
#[unsafe(no_mangle)]
pub extern "C" fn ashen_now_ms() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static CLOCK: AtomicU64 = AtomicU64::new(0);
    CLOCK.fetch_add(1, Ordering::Relaxed)
}

#[cfg(target_os = "none")]
pub fn seed_entropy(dest: &mut [u8]) -> Result<(), ()> {
    crate::hw_rng::fill_bytes(dest);
    Ok(())
}

/// Host stand-in for the STM32 TRNG. Deterministic on purpose: the host build
/// exists to exercise the TPM command paths under `cargo test`, not to produce
/// keys anybody trusts.
#[cfg(not(target_os = "none"))]
pub fn seed_entropy(dest: &mut [u8]) -> Result<(), ()> {
    use core::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    for chunk in dest.chunks_mut(8) {
        let mut x = STATE.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        STATE.store(x, Ordering::Relaxed);
        let bytes = x.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    Ok(())
}
