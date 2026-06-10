//! Custom `defmt` global logger.
//!
//! Every encoded log frame is sent to two places:
//!
//! - The standard SEGGER RTT "defmt" up-channel, so `probe-rs`/`probe-run`
//!   keep working exactly as with [`defmt_rtt`](https://docs.rs/defmt-rtt).
//! - A fixed-size, in-memory [`LOG_QUEUE`], drained by
//!   [`SecureLink::run_session`](crate::noise_link::SecureLink::run_session)
//!   and forwarded to the host as [`LogMessage`](crate::protocol::LogMessage)
//!   envelopes whenever the link isn't otherwise busy.
//!
//! Both sinks are best-effort and lossy: if the RTT host isn't connected, or
//! the queue is full, data is silently dropped rather than blocking the
//! firmware.

use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

use crate::protocol::MAX_LOG_FRAME_LEN;

// ---------------------------------------------------------------------
// RTT up-channel (minimal reimplementation of `defmt-rtt`'s non-blocking
// SEGGER RTT control block, so this module can be the sole `defmt`
// global logger).
// ---------------------------------------------------------------------

const RTT_BUF_SIZE: usize = 1024;

const MODE_MASK: u32 = 0b11;
const MODE_BLOCK_IF_FULL: u32 = 2;

#[repr(C)]
struct RttChannel {
    name: *const u8,
    buffer: *mut u8,
    size: u32,
    write: AtomicU32,
    read: AtomicU32,
    flags: AtomicU32,
}

// SAFETY: all mutable state (`write`, `read`, `flags`) is accessed through
// atomics with appropriate ordering; `name` and `buffer` are read-only raw
// pointers to other `'static` data, set up once at construction.
unsafe impl Sync for RttChannel {}

impl RttChannel {
    fn write_all(&self, mut bytes: &[u8]) {
        let write = if self.host_is_connected() {
            Self::blocking_write
        } else {
            Self::nonblocking_write
        };

        while !bytes.is_empty() {
            let consumed = write(self, bytes);
            if consumed != 0 {
                bytes = &bytes[consumed..];
            } else if !self.host_is_connected() {
                // Non-blocking mode never makes progress on a full buffer;
                // drop the rest rather than spinning forever.
                break;
            }
        }
    }

    fn blocking_write(&self, bytes: &[u8]) -> usize {
        if bytes.is_empty() {
            return 0;
        }
        let read = self.read.load(Ordering::Relaxed) as usize;
        let write = self.write.load(Ordering::Acquire) as usize;
        let available = available_buffer_size(read, write);
        if available == 0 {
            return 0;
        }
        self.write_impl(bytes, write, available)
    }

    fn nonblocking_write(&self, bytes: &[u8]) -> usize {
        let write = self.write.load(Ordering::Acquire) as usize;
        self.write_impl(bytes, write, RTT_BUF_SIZE)
    }

    fn write_impl(&self, bytes: &[u8], cursor: usize, available: usize) -> usize {
        let len = bytes.len().min(available);
        unsafe {
            if cursor + len > RTT_BUF_SIZE {
                let pivot = RTT_BUF_SIZE - cursor;
                ptr::copy_nonoverlapping(bytes.as_ptr(), self.buffer.add(cursor), pivot);
                ptr::copy_nonoverlapping(bytes.as_ptr().add(pivot), self.buffer, len - pivot);
            } else {
                ptr::copy_nonoverlapping(bytes.as_ptr(), self.buffer.add(cursor), len);
            }
        }
        self.write.store(
            (cursor.wrapping_add(len) % RTT_BUF_SIZE) as u32,
            Ordering::Release,
        );
        len
    }

    fn flush(&self) {
        if !self.host_is_connected() {
            return;
        }
        while self.read.load(Ordering::Relaxed) != self.write.load(Ordering::Relaxed) {}
    }

    /// We assume a host is connected if RTT is in blocking mode, mirroring
    /// `defmt-rtt`/`probe-run`.
    fn host_is_connected(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & MODE_MASK == MODE_BLOCK_IF_FULL
    }
}

/// How much space is left in the buffer?
fn available_buffer_size(read_cursor: usize, write_cursor: usize) -> usize {
    if read_cursor > write_cursor {
        read_cursor - write_cursor - 1
    } else {
        RTT_BUF_SIZE - write_cursor - 1 + read_cursor
    }
}

#[repr(C)]
struct RttHeader {
    id: [u8; 16],
    max_up_channels: u32,
    max_down_channels: u32,
    up_channel: RttChannel,
}

// SAFETY: all fields besides `up_channel` are immutable after
// construction; `up_channel`'s `Sync` impl covers its own interior
// mutability.
unsafe impl Sync for RttHeader {}

struct RttBuffer(UnsafeCell<[u8; RTT_BUF_SIZE]>);

// SAFETY: the buffer is only ever accessed through `RttChannel::write_impl`,
// whose `cursor`/`available` bounds are derived from `RttChannel`'s atomic
// `read`/`write` cursors, which serialize access to each region of the
// buffer.
unsafe impl Sync for RttBuffer {}

impl RttBuffer {
    const fn new() -> Self {
        Self(UnsafeCell::new([0; RTT_BUF_SIZE]))
    }

    const fn ptr(&self) -> *mut u8 {
        self.0.get() as *mut u8
    }
}

#[unsafe(link_section = ".uninit.defmt-rtt.BUFFER")]
static RTT_BUFFER: RttBuffer = RttBuffer::new();

#[unsafe(link_section = ".data.defmt-rtt.NAME")]
static RTT_NAME: [u8; 6] = *b"defmt\0";

/// The RTT control block, read by `probe-rs`/`probe-run`. Mirrors the layout
/// `defmt-rtt` uses, so the same host tooling works unmodified.
#[unsafe(no_mangle)]
static _SEGGER_RTT: RttHeader = RttHeader {
    id: *b"SEGGER RTT\0\0\0\0\0\0",
    max_up_channels: 1,
    max_down_channels: 0,
    up_channel: RttChannel {
        name: RTT_NAME.as_ptr(),
        buffer: RTT_BUFFER.ptr(),
        size: RTT_BUF_SIZE as u32,
        write: AtomicU32::new(0),
        read: AtomicU32::new(0),
        flags: AtomicU32::new(0),
    },
};

// ---------------------------------------------------------------------
// Log queue: holds encoded defmt frames for `SecureLink::run_session` to
// forward to the host as `LogMessage` envelopes.
// ---------------------------------------------------------------------

const LOG_QUEUE_CAPACITY: usize = 16;

#[derive(Clone, Copy)]
struct LogFrame {
    len: usize,
    data: [u8; MAX_LOG_FRAME_LEN],
}

impl LogFrame {
    const EMPTY: Self = Self {
        len: 0,
        data: [0; MAX_LOG_FRAME_LEN],
    };
}

struct LogQueueInner {
    frames: [LogFrame; LOG_QUEUE_CAPACITY],
    /// Index of the oldest queued frame.
    head: usize,
    /// Number of queued frames.
    count: usize,
}

struct LogQueue(UnsafeCell<LogQueueInner>);

// SAFETY: all accesses to the inner `UnsafeCell` go through `push`/`pop`,
// both of which wrap their access in `critical_section::with`, so concurrent
// (including interrupt-context) accesses are mutually exclusive.
unsafe impl Sync for LogQueue {}

impl LogQueue {
    const fn new() -> Self {
        Self(UnsafeCell::new(LogQueueInner {
            frames: [LogFrame::EMPTY; LOG_QUEUE_CAPACITY],
            head: 0,
            count: 0,
        }))
    }

    /// Enqueues `data` as a new frame, evicting the oldest queued frame if
    /// the queue is full. Frames longer than [`MAX_LOG_FRAME_LEN`] are
    /// dropped.
    fn push(&self, data: &[u8]) {
        if data.is_empty() || data.len() > MAX_LOG_FRAME_LEN {
            return;
        }
        critical_section::with(|_| unsafe {
            let inner = &mut *self.0.get();
            if inner.count == LOG_QUEUE_CAPACITY {
                inner.head = (inner.head + 1) % LOG_QUEUE_CAPACITY;
                inner.count -= 1;
            }
            let tail = (inner.head + inner.count) % LOG_QUEUE_CAPACITY;
            let frame = &mut inner.frames[tail];
            frame.data[..data.len()].copy_from_slice(data);
            frame.len = data.len();
            inner.count += 1;
        });
        LOG_SIGNAL.signal(());
    }

    /// Pops the oldest queued frame into `out`, returning its length, or
    /// `None` if the queue is empty.
    fn pop(&self, out: &mut [u8]) -> Option<usize> {
        critical_section::with(|_| unsafe {
            let inner = &mut *self.0.get();
            if inner.count == 0 {
                return None;
            }
            let frame = &inner.frames[inner.head];
            let len = frame.len.min(out.len());
            out[..len].copy_from_slice(&frame.data[..len]);
            inner.head = (inner.head + 1) % LOG_QUEUE_CAPACITY;
            inner.count -= 1;
            Some(len)
        })
    }
}

static LOG_QUEUE: LogQueue = LogQueue::new();

/// Signaled whenever a new frame is pushed to [`LOG_QUEUE`], so
/// [`SecureLink::run_session`](crate::noise_link::SecureLink::run_session)
/// can wake up and flush the queue even while it is otherwise waiting to
/// receive a message from the host.
static LOG_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Pops the oldest queued log frame (if any) into `out`, returning its
/// length. Used by [`SecureLink::run_session`](crate::noise_link::SecureLink::run_session)
/// to forward queued log frames to the host.
pub fn pop_log_frame(out: &mut [u8]) -> Option<usize> {
    LOG_QUEUE.pop(out)
}

/// Resolves once a new log frame has been queued since the last call.
pub async fn wait_for_log_frame() {
    LOG_SIGNAL.wait().await;
}

// ---------------------------------------------------------------------
// The `defmt` global logger itself.
// ---------------------------------------------------------------------

/// State for the single in-flight log frame: accumulates the encoded bytes
/// so the complete frame can be pushed to [`LOG_QUEUE`] on
/// [`Logger::release`](defmt::Logger::release).
struct EncoderState {
    encoder: UnsafeCell<defmt::Encoder>,
    cs_restore: UnsafeCell<critical_section::RestoreState>,
    frame: UnsafeCell<LogFrame>,
    /// Set if the current frame overflowed [`MAX_LOG_FRAME_LEN`] and should
    /// not be queued.
    overflow: UnsafeCell<bool>,
}

// SAFETY: all fields are only accessed between matching `acquire`/`release`
// calls, which bracket access with a `critical_section` (see `acquire` and
// `release` below), so concurrent (including interrupt-context) accesses are
// mutually exclusive.
unsafe impl Sync for EncoderState {}

impl EncoderState {
    const fn new() -> Self {
        Self {
            encoder: UnsafeCell::new(defmt::Encoder::new()),
            cs_restore: UnsafeCell::new(critical_section::RestoreState::invalid()),
            frame: UnsafeCell::new(LogFrame::EMPTY),
            overflow: UnsafeCell::new(false),
        }
    }

    /// Writes `bytes` to the RTT channel and appends them to the
    /// in-progress frame buffer.
    fn sink(&self, bytes: &[u8]) {
        _SEGGER_RTT.up_channel.write_all(bytes);

        unsafe {
            let frame = &mut *self.frame.get();
            let overflow = &mut *self.overflow.get();
            if frame.len + bytes.len() <= frame.data.len() {
                frame.data[frame.len..frame.len + bytes.len()].copy_from_slice(bytes);
                frame.len += bytes.len();
            } else {
                *overflow = true;
            }
        }
    }

    fn acquire(&self) {
        // SAFETY: paired with `release` below.
        let restore = unsafe { critical_section::acquire() };

        unsafe {
            self.cs_restore.get().write(restore);
            *self.frame.get() = LogFrame::EMPTY;
            *self.overflow.get() = false;
            let encoder = &mut *self.encoder.get();
            encoder.start_frame(|b| self.sink(b));
        }
    }

    /// # Safety
    /// Must only be called between `acquire` and `release`.
    unsafe fn write(&self, bytes: &[u8]) {
        unsafe {
            let encoder = &mut *self.encoder.get();
            encoder.write(bytes, |b| self.sink(b));
        }
    }

    /// # Safety
    /// Must only be called between `acquire` and `release`.
    unsafe fn flush(&self) {
        _SEGGER_RTT.up_channel.flush();
    }

    /// # Safety
    /// Must only be called between `acquire` and `release`.
    unsafe fn release(&self) {
        unsafe {
            let encoder = &mut *self.encoder.get();
            encoder.end_frame(|b| self.sink(b));

            let frame = &*self.frame.get();
            if !*self.overflow.get() && frame.len > 0 {
                LOG_QUEUE.push(&frame.data[..frame.len]);
            }

            let restore = self.cs_restore.get().read();
            critical_section::release(restore);
        }
    }
}

static ENCODER_STATE: EncoderState = EncoderState::new();

#[defmt::global_logger]
struct Logger;

// SAFETY: `acquire`/`release` are correctly paired via `ENCODER_STATE`'s
// critical-section guard (see `EncoderState::acquire`/`release`), and
// `write`/`flush` are only called between matching `acquire`/`release`
// calls per `defmt::Logger`'s contract.
unsafe impl defmt::Logger for Logger {
    fn acquire() {
        ENCODER_STATE.acquire();
    }

    unsafe fn write(bytes: &[u8]) {
        unsafe { ENCODER_STATE.write(bytes) }
    }

    unsafe fn flush() {
        unsafe { ENCODER_STATE.flush() }
    }

    unsafe fn release() {
        unsafe { ENCODER_STATE.release() }
    }
}
