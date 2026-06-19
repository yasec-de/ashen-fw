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

/// Maximum number of plaintext payload bytes in a single COBS frame
pub const MAX_PAYLOAD_LEN: usize = 1024;

/// Maximum size of a COBS frame after encoding
pub const MAX_FRAME_LEN: usize = MAX_PAYLOAD_LEN + MAX_PAYLOAD_LEN / 254 + 2;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "Truncated COBS frame"),
            Error::Io => write!(f, "I/O error"),
            Error::Overflow => write!(f, "COBS frame too large"),
        }
    }
}

pub async fn write_frame<T: Write>(io: &mut T, payload: &[u8]) -> Result<(), Error> {
    let mut frame = encode(payload);

    if frame.len() >= MAX_FRAME_LEN {
        return Err(Error::Overflow)
    }

    frame.push(0x00);
    io.write_all(&frame).await.map_err(|_| Error::Io)
}

pub async fn sync_frame<T: Read>(io: &mut T) -> Result<(), Error> {
    loop {
        let mut byte = [0u8; 1];
        io.read_exact(&mut byte).await.map_err(|_| Error::Io)?;

        if byte[0] == 0x00 {
            return Ok(())
        }
    }
}

/// Reads bytes up to the next `0x00` delimiter and COBS-decodes them.
///
/// If the frame exceeds [`MAX_FRAME_LEN`], bytes are still
/// consumed up to (and including) the delimiter before returning
/// [`Error::Overflow`]
pub async fn read_frame<T: Read>(io: &mut T) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        io.read_exact(&mut byte).await.map_err(|_| Error::Io)?;

        if byte[0] == 0x00 {
            return decode(&buf)
        }

        if buf.len() < MAX_FRAME_LEN {
            buf.push(byte[0]);
        } else {
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
            let mut io = SliceIo::new(Vec::new());
            write_frame(&mut io, b"hello world").await.unwrap();

            let mut reader = SliceIo::new(io.out);
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

            let mut io = SliceIo::new(data);

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

            let mut io = SliceIo::new(data);

            assert!(matches!(read_frame(&mut io).await, Err(Error::Overflow)));

            let frame = read_frame(&mut io).await.unwrap();
            assert_eq!(frame, b"after overflow");
        });
    }
}
