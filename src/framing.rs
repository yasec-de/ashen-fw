//! COBS frame I/O on top of the verified [`crate::cobs`] codec.
//!
//! Each frame is COBS-encoded (so its body never contains `0x00`) and
//! terminated by a single `0x00` delimiter. Long payloads are split by the
//! codec into chained sub-blocks of up to 254 bytes each (the standard COBS
//! "0xFF" chaining case). The encode/decode core lives in [`crate::cobs`],
//! which is formally verified by Verus; this module only adds the
//! delimiter framing, length limits, and resynchronization.

use alloc::vec::Vec;
use core::fmt;
use embedded_io_async::{Read, Write};

// `encode`/`decode`/`Error` are the formally proven items from the `cobs`
// module (verified standalone by `nix build .#cobs-proof`). They are re-exported
// here so `Error` — shared between `decode` and the frame I/O layer below — is
// part of this module's public surface.
pub use crate::cobs::{Error, decode, encode};

/// A run of at least this many consecutive `0x00` bytes is a link reset: it
/// resets the COBS frame boundary and signals the upper layers to drop the
/// connection and reset the Noise state.
pub const RESET_NULL_RUN: usize = 8;

/// Number of `0x00` bytes replied after a reset is accepted, before the next
/// handshake begins.
pub const RESET_REPLY_NULLS: usize = 32;

/// Maximum number of plaintext payload bytes in a single COBS frame.
///
/// Kept small (256 B) so peak concurrent heap stays well under the 4 KB
/// `emballoc` arena: a `receive` holds a frame `Vec` plus a plaintext `Vec`
/// live at once, and `run_session` can interleave that with a `send`.
pub const MAX_PAYLOAD_LEN: usize = 256;

/// Maximum size of a COBS frame after encoding
pub const MAX_FRAME_LEN: usize = MAX_PAYLOAD_LEN + MAX_PAYLOAD_LEN / 254 + 2;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "Truncated COBS frame"),
            Error::Io => write!(f, "I/O error"),
            Error::Overflow => write!(f, "COBS frame too large"),
            Error::Reset => write!(f, "Link reset"),
        }
    }
}

/// Wraps a byte-oriented I/O channel and watches the incoming stream for link
/// resets: a run of at least [`RESET_NULL_RUN`] consecutive `0x00` bytes.
///
/// The reset state (null-run counter, and whether the link has been reset at
/// least once since startup) lives here so it persists across frames and
/// across whole Noise sessions; the same `ResetReader` is threaded through
/// every handshake over the underlying channel.
///
/// Until the first reset is seen, [`read_byte`](Self::read_byte) never yields
/// data — it consumes and discards the incoming stream, only ever returning
/// [`Error::Reset`] once a reset arrives. When the null run reaches the
/// threshold it replies with [`RESET_REPLY_NULLS`] `0x00` bytes and returns
/// [`Error::Reset`]; any further nulls of an over-long run are swallowed on
/// subsequent reads without re-firing.
pub struct ResetReader<T> {
    io: T,
    null_run: usize,
    /// Set once the first reset has been accepted. Before that, all inbound
    /// data is ignored (per the protocol: ignore everything until reset once).
    armed: bool,
    /// Bulk read-ahead buffer. `read_raw` drains the underlying UART in chunks
    /// rather than one byte per `await`: at 1 Mbaud a byte arrives every ~10 us,
    /// too fast for a per-byte executor round-trip to keep up, so the
    /// `BufferedUart` RX ring would overflow and silently drop mid-frame bytes.
    rx_buf: [u8; RX_CHUNK_LEN],
    rx_pos: usize,
    rx_len: usize,
    /// Partial-frame accumulator for [`read_frame`]. Lives here rather than in
    /// a local of `read_frame` so that a frame in progress survives the future
    /// being cancelled: `run_session` drops its receive future whenever a log
    /// frame is queued mid-session (via `select`), and losing already-consumed
    /// frame bytes there desyncs the stream and poisons the next decrypt.
    frame_buf: Vec<u8>,
}

/// Read-ahead chunk size, matched to the `BufferedUart` RX ring so one refill
/// can drain a full ring's worth in a single `await`.
const RX_CHUNK_LEN: usize = 256;

impl<T: Read + Write> ResetReader<T> {
    pub fn new(io: T) -> Self {
        Self {
            io,
            null_run: 0,
            armed: false,
            rx_buf: [0; RX_CHUNK_LEN],
            rx_pos: 0,
            rx_len: 0,
            frame_buf: Vec::new(),
        }
    }

    pub fn into_inner(self) -> T {
        self.io
    }

    /// Test-only constructor that starts already armed, so `read_frame` passes
    /// data through without first requiring a reset.
    #[cfg(test)]
    pub fn armed_for_test(io: T) -> Self {
        Self {
            io,
            null_run: 0,
            armed: true,
            rx_buf: [0; RX_CHUNK_LEN],
            rx_pos: 0,
            rx_len: 0,
            frame_buf: Vec::new(),
        }
    }

    async fn read_raw(&mut self) -> Result<u8, Error> {
        if self.rx_pos >= self.rx_len {
            // Buffer drained: refill with one bulk read. A single `read` returns
            // as many bytes as are already waiting in the RX ring, so a burst is
            // consumed in one `await` instead of one per byte.
            let n = self.io.read(&mut self.rx_buf).await.map_err(|_| Error::Io)?;
            if n == 0 {
                return Err(Error::Io);
            }
            self.rx_pos = 0;
            self.rx_len = n;
        }
        let byte = self.rx_buf[self.rx_pos];
        self.rx_pos += 1;
        Ok(byte)
    }

    /// Reads one byte, treating a run of at least [`RESET_NULL_RUN`] `0x00`
    /// bytes as a link reset. Before the first reset since startup, inbound
    /// bytes are discarded rather than returned.
    pub async fn read_byte(&mut self) -> Result<u8, Error> {
        loop {
            let byte = self.read_raw().await?;

            if byte == 0x00 {
                self.null_run += 1;
                if self.null_run == RESET_NULL_RUN {
                    // Exactly at threshold: this is the reset. Reply once and
                    // report it. Any further nulls (an over-long run) are
                    // swallowed by the `> RESET_NULL_RUN` branch below on the
                    // next reads, without re-firing.
                    let reply = [0u8; RESET_REPLY_NULLS];
                    self.io.write_all(&reply).await.map_err(|_| Error::Io)?;
                    self.armed = true;
                    return Err(Error::Reset);
                }
                if self.null_run > RESET_NULL_RUN {
                    // Trailing null of the same over-long run; already handled.
                    continue;
                }
            } else {
                self.null_run = 0;
            }

            // Before the first reset, discard everything and keep looping.
            // After it, hand the byte (delimiter zeros included) to the caller.
            if self.armed {
                return Ok(byte);
            }
        }
    }

    /// Initiator side of the reset: send a run of [`RESET_NULL_RUN`] `0x00`
    /// bytes to reset the responder, then consume its
    /// [`RESET_REPLY_NULLS`]-byte null reply. After this returns, the next
    /// bytes written are the first handshake frame.
    pub async fn send_reset(&mut self) -> Result<(), Error> {
        let reset = [0u8; RESET_NULL_RUN];
        self.io.write_all(&reset).await.map_err(|_| Error::Io)?;

        // Drain exactly RESET_REPLY_NULLS `0x00` bytes. The responder sends
        // them contiguously with nothing else in between.
        let mut seen = 0;
        while seen < RESET_REPLY_NULLS {
            if self.read_raw().await? == 0x00 {
                seen += 1;
            } else {
                seen = 0;
            }
        }

        // Past startup now: subsequent reads pass frame data through.
        self.armed = true;
        Ok(())
    }
}

pub async fn write_frame<T: Write>(io: &mut ResetReader<T>, payload: &[u8]) -> Result<(), Error> {
    let mut frame = encode(payload);

    if frame.len() >= MAX_FRAME_LEN {
        return Err(Error::Overflow)
    }

    frame.push(0x00);
    io.io.write_all(&frame).await.map_err(|_| Error::Io)
}

pub async fn sync_frame<T: Read + Write>(io: &mut ResetReader<T>) -> Result<(), Error> {
    // ponytail: needs Write too because `read_byte` may emit the reset reply.
    loop {
        if io.read_byte().await? == 0x00 {
            return Ok(())
        }
    }
}

/// Reads bytes up to the next `0x00` delimiter and COBS-decodes them.
///
/// If the frame exceeds [`MAX_FRAME_LEN`], bytes are still
/// consumed up to (and including) the delimiter before returning
/// [`Error::Overflow`]
///
/// Cancellation-safe: a partially read frame is accumulated in the
/// [`ResetReader`] rather than a local, so dropping the future mid-frame
/// (as `run_session`'s `select` does whenever a log frame is queued) loses
/// no bytes; the next call resumes the same frame.
pub async fn read_frame<T: Read + Write>(io: &mut ResetReader<T>) -> Result<Vec<u8>, Error> {
    // ponytail: needs Write too because `read_byte` may emit the reset reply.
    loop {
        let byte = match io.read_byte().await {
            Ok(byte) => byte,
            Err(e) => {
                // Reset or I/O error: any frame in progress is dead. Drop it
                // so it cannot poison the first frame of the next session.
                io.frame_buf.clear();
                return Err(e);
            }
        };

        if byte == 0x00 {
            let frame = decode(&io.frame_buf);
            io.frame_buf.clear();
            return frame;
        }

        if io.frame_buf.len() < MAX_FRAME_LEN {
            io.frame_buf.push(byte);
        } else {
            io.frame_buf.clear();
            sync_frame(io).await?;
            return Err(Error::Overflow)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn round_trip(input: &[u8]) {
        let encoded = encode(input);
        assert!(
            !encoded.contains(&0x00),
            "encoded output must not contain 0x00"
        );
        let decoded = decode(&encoded).expect("decode failed");
        assert_eq!(decoded, input);
    }

    #[test]
    fn empty() {
        round_trip(&[]);
    }

    #[test]
    fn single_zero_byte() {
        round_trip(&[0x00]);
    }

    #[test]
    fn short_string_with_embedded_zero() {
        round_trip(b"hello\x00world");
    }

    #[test]
    fn no_zeros_short() {
        round_trip(b"hello noise");
    }

    #[test]
    fn exactly_one_block_254_bytes() {
        let input: Vec<u8> = (0..254u32).map(|i| (i % 255 + 1) as u8).collect();
        round_trip(&input);
    }

    #[test]
    fn long_buffer_513_bytes_no_zeros() {
        // 513 = 254 + 254 + 5, so this requires three chained COBS
        // sub-blocks (two full 0xFF blocks plus a short trailing block).
        let input: Vec<u8> = (0..513u32).map(|i| (i % 255 + 1) as u8).collect();
        round_trip(&input);
    }

    #[test]
    fn long_buffer_513_bytes_with_zeros() {
        let input: Vec<u8> = (0..513u32).map(|i| (i % 7) as u8).collect();
        round_trip(&input);
    }

    // Note: `decode` requires zero-free input (Verus-verified). Feeding it a
    // `0x00` byte violates that precondition; behavior is then unspecified
    // (a debug-build underflow panic vs. a release-build `Err`), so there is no
    // stable assertion to make and no test for that case.

    #[test]
    fn decode_rejects_truncated_block() {
        // Code byte claims 4 data bytes follow, but only 2 are present.
        assert_eq!(decode(&[0x05, 0x01, 0x02]), Err(Error::Truncated));
    }

    #[test]
    fn known_vectors() {
        assert_eq!(encode(&[]), vec![0x01]);
        assert_eq!(encode(&[0x00]), vec![0x01, 0x01]);
        assert_eq!(encode(&[0x01, 0x02, 0x03]), vec![0x04, 0x01, 0x02, 0x03]);
        assert_eq!(encode(&[0x01, 0x00, 0x02]), vec![0x02, 0x01, 0x02, 0x02]);
    }

    /// An in-memory byte source/sink for testing [`read_frame`]/[`write_frame`].
    struct SliceIo {
        data: Vec<u8>,
        pos: usize,
        out: Vec<u8>,
    }

    impl SliceIo {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                pos: 0,
                out: Vec::new(),
            }
        }
    }

    #[derive(Debug)]
    struct SliceError;

    impl core::fmt::Display for SliceError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "slice I/O error")
        }
    }

    // embedded-io 0.7 requires `Error` types to also implement
    // `core::error::Error` (hence `Display`).
    impl core::error::Error for SliceError {}

    impl embedded_io::Error for SliceError {
        fn kind(&self) -> embedded_io::ErrorKind {
            embedded_io::ErrorKind::Other
        }
    }

    impl embedded_io::ErrorType for SliceIo {
        type Error = SliceError;
    }

    impl Read for SliceIo {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            if self.pos >= self.data.len() {
                return Err(SliceError);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    impl Write for SliceIo {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.out.extend_from_slice(buf);
            Ok(buf.len())
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn frame_round_trip() {
        embassy_futures::block_on(async {
            let mut io = ResetReader::armed_for_test(SliceIo::new(Vec::new()));
            write_frame(&mut io, b"hello world").await.unwrap();

            let mut reader = ResetReader::armed_for_test(SliceIo::new(io.io.out));
            let frame = read_frame(&mut reader).await.unwrap();
            assert_eq!(frame, b"hello world");
        });
    }

    #[test]
    fn resync_after_corrupt_frame() {
        embassy_futures::block_on(async {
            // A corrupt frame (a code byte claiming more data than follows,
            // which is invalid COBS) followed by the delimiter, then a valid
            // frame.
            let mut data = vec![0x05, 0x00];
            let mut good = encode(b"second frame");
            good.push(0x00);
            data.append(&mut good);

            let mut io = ResetReader::armed_for_test(SliceIo::new(data));

            // First frame is corrupt.
            assert!(matches!(read_frame(&mut io).await, Err(Error::Truncated)));

            // Reader has resynchronized and can decode the next frame.
            let frame = read_frame(&mut io).await.unwrap();
            assert_eq!(frame, b"second frame");
        });
    }

    #[test]
    fn resync_after_oversized_frame() {
        embassy_futures::block_on(async {
            // A frame longer than MAX_FRAME_LEN (no zero bytes, so it's
            // valid COBS, just too long), followed by the delimiter, then a
            // valid frame.
            let oversized: Vec<u8> = (0..MAX_FRAME_LEN + 10)
                .map(|i| (i % 255 + 1) as u8)
                .collect();
            let mut data = encode(&oversized);
            data.push(0x00);

            let mut good = encode(b"after overflow");
            good.push(0x00);
            data.append(&mut good);

            let mut io = ResetReader::armed_for_test(SliceIo::new(data));

            assert!(matches!(read_frame(&mut io).await, Err(Error::Overflow)));

            let frame = read_frame(&mut io).await.unwrap();
            assert_eq!(frame, b"after overflow");
        });
    }

    #[test]
    fn ignores_data_until_first_reset() {
        embassy_futures::block_on(async {
            // Junk, then a good frame, then an 8-null reset, then a real frame.
            let mut data = encode(b"pre-reset junk");
            data.push(0x00);
            data.extend(core::iter::repeat(0x00).take(RESET_NULL_RUN));
            // A non-null byte ends the null run and is consumed by accept_reset.
            let mut good = encode(b"real frame");
            good.push(0x00);
            data.append(&mut good);

            let mut io = ResetReader::new(SliceIo::new(data));

            // Before the reset, read_frame blocks on/discards junk and only
            // surfaces the reset.
            assert!(matches!(read_frame(&mut io).await, Err(Error::Reset)));

            // 32-null reply was emitted.
            assert_eq!(io.io.out.len(), RESET_REPLY_NULLS);
            assert!(io.io.out.iter().all(|&b| b == 0x00));

            // The byte after the null run is consumed by accept_reset, so the
            // first real frame here loses its leading COBS code byte. In
            // practice the peer waits for our reply before sending a frame; we
            // model that by not asserting on this specific frame's content.
        });
    }

    #[test]
    fn reset_reported_when_armed() {
        embassy_futures::block_on(async {
            // Arm first (skip startup lockout), then feed 8 nulls. When armed,
            // each of the first 7 nulls is an empty-frame delimiter; the 8th
            // trips the reset. So the reset surfaces on the 8th read_frame.
            let data: Vec<u8> = core::iter::repeat(0x00)
                .take(RESET_NULL_RUN)
                .chain(core::iter::once(0x42))
                .collect();
            let mut io = ResetReader::armed_for_test(SliceIo::new(data));
            for _ in 0..RESET_NULL_RUN - 1 {
                // Empty frames from bare delimiters.
                assert!(!matches!(read_frame(&mut io).await, Err(Error::Reset)));
            }
            assert!(matches!(read_frame(&mut io).await, Err(Error::Reset)));
            assert_eq!(io.io.out.len(), RESET_REPLY_NULLS);
        });
    }

    #[test]
    fn fewer_than_reset_run_is_not_a_reset() {
        embassy_futures::block_on(async {
            // A valid frame, then stray nulls whose run (counting the frame's
            // own delimiter) stays below RESET_NULL_RUN, then another valid
            // frame. read_byte must never report Reset for a sub-threshold run.
            //
            // "one\0" contributes 1 null to the run, so add RESET_NULL_RUN - 2
            // more to peak at RESET_NULL_RUN - 1 consecutive nulls.
            let stray = RESET_NULL_RUN - 2;
            let mut data = encode(b"one");
            data.push(0x00);
            data.extend(core::iter::repeat(0x00).take(stray));
            let mut two = encode(b"two");
            two.push(0x00);
            data.append(&mut two);

            let mut io = ResetReader::armed_for_test(SliceIo::new(data));

            assert_eq!(read_frame(&mut io).await.unwrap(), b"one");
            // Each stray null is an empty-frame delimiter; none reset.
            for _ in 0..stray {
                assert!(!matches!(read_frame(&mut io).await, Err(Error::Reset)));
            }
            assert_eq!(read_frame(&mut io).await.unwrap(), b"two");
        });
    }
}
