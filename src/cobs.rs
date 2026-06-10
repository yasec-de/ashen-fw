//! COBS (Consistent Overhead Byte Stuffing) implementation.
//! For details on COBS, see this paper: https://www.stuartcheshire.org/papers/COBSforToN.pdf
//!
//! Encodes an arbitrary byte slice (which may contain `0x00` bytes) into a
//! form that is guaranteed not to contain `0x00`, so that `0x00` can be used
//! as an unambiguous frame delimiter on a byte stream. Frames may be of any
//! length; long inputs are split into chained sub-blocks of up to 254 bytes
//! each (the standard COBS "0xFF" chaining case).

use alloc::vec::Vec;

/// Errors that can occur while decoding a COBS-encoded buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// A `0x00` byte appeared where a (non-zero) code byte was expected.
    ZeroInCode,
    /// The buffer ended in the middle of a data block.
    Truncated,
}

/// Encodes `input` into COBS form. The result never contains a `0x00` byte.
///
/// The caller is responsible for appending the `0x00` frame delimiter
/// afterwards.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 254 + 1);
    let mut code_pos = 0;
    out.push(0);
    let mut code = 1u8;
    for &byte in input {
        if byte == 0 {
            out[code_pos] = code;
            code_pos = out.len();
            out.push(0);
            code = 1;
        } else {
            out.push(byte);
            code += 1;
            if code == 0xFF {
                out[code_pos] = code;
                code_pos = out.len();
                out.push(0);
                code = 1;
            }
        }
    }
    out[code_pos] = code;
    out
}

/// Decodes a COBS-encoded buffer (without the trailing `0x00` delimiter)
/// back into the original bytes.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let code = input[i] as usize;
        if code == 0 {
            return Err(DecodeError::ZeroInCode);
        }
        i += 1;
        let data_len = code - 1;
        if i + data_len > input.len() {
            return Err(DecodeError::Truncated);
        }
        out.extend_from_slice(&input[i..i + data_len]);
        i += data_len;
        if code != 0xFF && i < input.len() {
            out.push(0);
        }
    }
    Ok(out)
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
    fn decode_rejects_zero_code_byte() {
        assert_eq!(decode(&[0x00]), Err(DecodeError::ZeroInCode));
    }

    #[test]
    fn decode_rejects_truncated_block() {
        // Code byte claims 4 data bytes follow, but only 2 are present.
        assert_eq!(decode(&[0x05, 0x01, 0x02]), Err(DecodeError::Truncated));
    }

    #[test]
    fn known_vectors() {
        assert_eq!(encode(&[]), vec![0x01]);
        assert_eq!(encode(&[0x00]), vec![0x01, 0x01]);
        assert_eq!(encode(&[0x01, 0x02, 0x03]), vec![0x04, 0x01, 0x02, 0x03]);
        assert_eq!(encode(&[0x01, 0x00, 0x02]), vec![0x02, 0x01, 0x02, 0x02]);
    }
}
