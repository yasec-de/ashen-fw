//! COBS frame I/O on top of the verified [`crate::cobs`] codec.

use alloc::vec::Vec;
use core::fmt;
use embedded_io_async::{Read, Write};

pub use crate::cobs::{Error, decode, encode};

pub const RESET_NULL_RUN: usize = 24;
pub const RESET_REPLY_NULLS: usize = 32;
pub const MAX_PAYLOAD_LEN: usize = 256;
pub const MAX_FRAME_LEN: usize = MAX_PAYLOAD_LEN + MAX_PAYLOAD_LEN / 254 + 2;
const RX_CHUNK_LEN: usize = 256;

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

pub struct ResetReader<T> {
    io: T,
    null_run: usize,
    sync: bool,
    rx_buf: [u8; RX_CHUNK_LEN],
    rx_pos: usize,
    rx_len: usize,
    frame_buf: Vec<u8>,
}

impl<T: Read + Write> ResetReader<T> {
    pub fn new(io: T) -> Self {
        Self {
            io,
            null_run: 0,
            sync: false,
            rx_buf: [0; RX_CHUNK_LEN],
            rx_pos: 0,
            rx_len: 0,
            frame_buf: Vec::new(),
        }
    }

    pub fn into_inner(self) -> T {
        self.io
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn start_synchronized(io: T) -> Self {
        Self {
            io,
            null_run: 0,
            sync: true,
            rx_buf: [0; RX_CHUNK_LEN],
            rx_pos: 0,
            rx_len: 0,
            frame_buf: Vec::new(),
        }
    }

    async fn read_raw(&mut self) -> Result<u8, Error> {
        if self.rx_pos >= self.rx_len {
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

    pub async fn read_byte(&mut self) -> Result<u8, Error> {
        loop {
            let byte = self.read_raw().await?;

            if byte == 0x00 {
                self.null_run += 1;
                if self.null_run == RESET_NULL_RUN {
                    let reply = [0u8; RESET_NULL_RUN];
                    self.io.write_all(&reply).await.map_err(|_| Error::Io)?;
                    self.sync = true;
                    return Err(Error::Reset);
                } else if self.null_run > RESET_NULL_RUN {
                    let reply = [0u8; 1];
                    self.io.write_all(&reply).await.map_err(|_| Error::Io)?;
                    return Ok(0x00);
                } if self.null_run == 1 {
                    return Ok(0x00);
                }
            } else {
                self.null_run = 0;
                if self.sync {
                    return Ok(byte);
                }
            }
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub async fn send_reset(&mut self) -> Result<(), Error> {
        let reset = [0u8; RESET_NULL_RUN];
        self.io.write_all(&reset).await.map_err(|_| Error::Io)?;

        let mut seen = 0;
        while seen < RESET_REPLY_NULLS {
            if self.read_raw().await? == 0x00 {
                seen += 1;
            } else {
                seen = 0;
            }
        }

        self.sync = true;
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
    loop {
        if io.read_byte().await? == 0x00 {
            return Ok(())
        }
    }
}

pub async fn read_frame<T: Read + Write>(io: &mut ResetReader<T>) -> Result<Vec<u8>, Error> {
    loop {
        let byte = match io.read_byte().await {
            Ok(byte) => byte,
            Err(e) => {
                io.frame_buf.clear();
                return Err(e);
            }
        };

        if byte == 0x00 {
            if io.frame_buf.len() == 0 {
                continue;
            }
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
            let mut io = ResetReader::start_synchronized(SliceIo::new(Vec::new()));
            write_frame(&mut io, b"hello world").await.unwrap();

            let mut reader = ResetReader::start_synchronized(SliceIo::new(io.io.out));
            let frame = read_frame(&mut reader).await.unwrap();
            assert_eq!(frame, b"hello world");
        });
    }

    #[test]
    fn resync_after_corrupt_frame() {
        embassy_futures::block_on(async {
            let mut data = vec![0x05, 0x00];
            let mut good = encode(b"second frame");
            good.push(0x00);
            data.append(&mut good);

            let mut io = ResetReader::start_synchronized(SliceIo::new(data));

            assert!(matches!(read_frame(&mut io).await, Err(Error::Truncated)));

            let frame = read_frame(&mut io).await.unwrap();
            assert_eq!(frame, b"second frame");
        });
    }

    #[test]
    fn resync_after_oversized_frame() {
        embassy_futures::block_on(async {
            let oversized: Vec<u8> = (0..MAX_FRAME_LEN + 10)
                .map(|i| (i % 255 + 1) as u8)
                .collect();
            let mut data = encode(&oversized);
            data.push(0x00);

            let mut good = encode(b"after overflow");
            good.push(0x00);
            data.append(&mut good);

            let mut io = ResetReader::start_synchronized(SliceIo::new(data));

            assert!(matches!(read_frame(&mut io).await, Err(Error::Overflow)));

            let frame = read_frame(&mut io).await.unwrap();
            assert_eq!(frame, b"after overflow");
        });
    }

    #[test]
    fn ignores_data_until_first_reset() {
        embassy_futures::block_on(async {
            let mut data = encode(b"pre-reset junk");
            data.push(0x00);
            data.extend(core::iter::repeat(0x00).take(RESET_NULL_RUN));
            let mut good = encode(b"real frame");
            good.push(0x00);
            data.append(&mut good);

            let mut io = ResetReader::new(SliceIo::new(data));

            assert!(matches!(read_frame(&mut io).await, Err(Error::Reset)));

            assert_eq!(io.io.out.len(), RESET_REPLY_NULLS);
            assert!(io.io.out.iter().all(|&b| b == 0x00));
        });
    }

    #[test]
    fn reset_reported_when_armed() {
        embassy_futures::block_on(async {
            let data: Vec<u8> = core::iter::repeat(0x00)
                .take(RESET_NULL_RUN)
                .chain(core::iter::once(0x42))
                .collect();
            let mut io = ResetReader::start_synchronized(SliceIo::new(data));
            assert!(!matches!(read_frame(&mut io).await, Err(Error::Reset)));
            assert!(matches!(read_frame(&mut io).await, Err(Error::Reset)));
            assert_eq!(io.io.out.len(), RESET_REPLY_NULLS);
        });
    }

    #[test]
    fn back_to_back_resets_all_fire() {
        embassy_futures::block_on(async {
            let data: Vec<u8> = core::iter::repeat(0x00).take(RESET_NULL_RUN * 3).collect();
            let mut io = ResetReader::start_synchronized(SliceIo::new(data));

            let mut resets = 0;
            for _ in 0..RESET_NULL_RUN * 3 {
                if matches!(read_frame(&mut io).await, Err(Error::Reset)) {
                    resets += 1;
                }
            }
            assert_eq!(resets, 3, "each contiguous reset run must fire");
            assert_eq!(io.io.out.len(), RESET_REPLY_NULLS * 3);
        });
    }

    #[test]
    fn fewer_than_reset_run_is_not_a_reset() {
        embassy_futures::block_on(async {
            let stray = RESET_NULL_RUN - 2;
            let mut data = encode(b"one");
            data.push(0x00);
            data.extend(core::iter::repeat(0x00).take(stray));
            let mut two = encode(b"two");
            two.push(0x00);
            data.append(&mut two);

            let mut io = ResetReader::start_synchronized(SliceIo::new(data));

            assert_eq!(read_frame(&mut io).await.unwrap(), b"one");
            assert_eq!(read_frame(&mut io).await.unwrap(), b"two");
        });
    }
}
