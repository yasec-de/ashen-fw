//! Host-side test suite for the COBS implementation in
//! [`ashen_fw::cobs`].
//!
//! Covers a range of message sizes (including chained-block boundaries
//! around 254/255-byte sub-blocks) and various placements of embedded
//! `0x00` bytes within the payload.

use ashen_fw::cobs::{decode, encode};

/// Encodes and decodes `input`, asserting that the encoded form contains no
/// `0x00` bytes and that decoding it reproduces the original input.
fn round_trip(input: &[u8]) {
    let encoded = encode(input);
    assert!(
        !encoded.contains(&0x00),
        "encoded output must not contain 0x00 (len={})",
        input.len()
    );
    let decoded = decode(&encoded).expect("decode failed");
    assert_eq!(decoded, input, "round trip mismatch (len={})", input.len());
}

/// Builds a buffer of `len` non-zero bytes, then sets the bytes at
/// `zero_positions` to `0x00`.
fn make_buf(len: usize, zero_positions: &[usize]) -> Vec<u8> {
    let mut buf: Vec<u8> = (0..len).map(|i| ((i % 255) + 1) as u8).collect();
    for &p in zero_positions {
        buf[p] = 0x00;
    }
    buf
}

fn zero_patterns(len: usize) -> Vec<Vec<usize>> {
    assert!(len >= 2);
    let mid = len / 2;
    vec![
        vec![],
        vec![0],
        vec![1],
        vec![len - 1],
        vec![len - 2],
        vec![mid],
        vec![0, 1],
        vec![0, 1, mid, len - 2, len - 1],
    ]
}

#[test]
fn sizes_0_to_5_bytes() {
    for len in 0..=5usize {
        if len < 2 {
            // Not enough room for the full set of zero-position patterns;
            // just test all-zero and no-zero variants.
            round_trip(&vec![0u8; len]);
            round_trip(&make_buf(len, &[]));
            continue;
        }
        for positions in zero_patterns(len) {
            round_trip(&make_buf(len, &positions));
        }
    }
}

#[test]
fn sizes_around_254_block_boundary() {
    for &len in &[253usize, 254, 255, 256] {
        for positions in zero_patterns(len) {
            round_trip(&make_buf(len, &positions));
        }
    }
}

#[test]
fn sizes_around_512_bytes() {
    for &len in &[510usize, 511, 513] {
        for positions in zero_patterns(len) {
            round_trip(&make_buf(len, &positions));
        }
    }
}

#[test]
fn sizes_around_768_bytes() {
    for &len in &[766usize, 767, 769] {
        for positions in zero_patterns(len) {
            round_trip(&make_buf(len, &positions));
        }
    }
}
