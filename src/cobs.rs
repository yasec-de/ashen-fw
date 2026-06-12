//! COBS (Consistent Overhead Byte Stuffing) implementation.
//! For details on COBS, see this paper: https://www.stuartcheshire.org/papers/COBSforToN.pdf
//!
//! Encodes an arbitrary byte slice (which may contain `0x00` bytes) into a
//! form that is guaranteed not to contain `0x00`, so that `0x00` can be used
//! as an unambiguous frame delimiter on a byte stream. Frames may be of any
//! length; long inputs are split into chained sub-blocks of up to 254 bytes
//! each (the standard COBS "0xFF" chaining case).

use alloc::vec::Vec;
use embedded_io_async::{Read, Write};
use core::fmt;


/// Maximum number of plaintext payload bytes in a single COBS frame
pub const MAX_PAYLOAD_LEN: usize = 1024;

/// Maximum size of a COBS frame after encoding
pub const MAX_FRAME_LEN: usize = MAX_PAYLOAD_LEN + MAX_PAYLOAD_LEN / 254 + 2;

/// Errors that can occur while decoding a COBS-encoded buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// During decoding, we ran out of input data while decoding
    Truncated,
    /// The underlying transport failed.
    Io,
    /// Maximum buffer size exceeded during decoding
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "Truncated COBS frame"),
            Error::Io => write!(f, "I/O error"),
            Error::Overflow => write!(f, "COBS frame too large"),
        }
    }
}

/// Encodes `input` into COBS form. The result never contains a `0x00` byte.
///
/// The caller is responsible for adding `0x00` frame delimiters as necessary.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 254 + 1);
    let mut code_pos = 0;
    let mut code = 1u8;
    out.push(0); // Reserve one spot for the code byte

    for &byte in input {
        if byte == 0 {
            out[code_pos] = code;
            code_pos = out.len();
            out.push(0);
            code = 1;

        } else {
            out.push(byte);
            code += 1;

            if code == 0xff {
                out[code_pos] = 0xff;
                code_pos = out.len();
                out.push(0);
                code = 1;
            }
        }
    }

    out[code_pos] = code;
    out
}

/// Decodes a COBS-encoded buffer (without leading or trailing `0x00` delimiters)
/// back into the original bytes.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let code = input[i] as usize;
        i += 1;

        if code == 0 {
            panic!("Caller passed buffer with embedded null bytes to cobs::decode");
        }
        
        let data_len = code - 1;
        if i + data_len > input.len() {
            return Err(Error::Truncated);
        }

        out.extend_from_slice(&input[i..i + data_len]);
        i += data_len;
        if code != 0xFF && i < input.len() {
            out.push(0);
        }
    }
    Ok(out)
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

    #[test]
    #[should_panic]
    fn decode_rejects_zero_code_byte() {
        let _ = decode(&[0x00]);
    }

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
