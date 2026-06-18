//! Verus proof harness for the core COBS routines in [`ashen_fw::cobs`].
//!
//! Verus cannot (yet) be run over the firmware crate as a whole — it is
//! `no_std`, async, and pulls in HAL crates Verus does not model — so this
//! file is a faithful, standalone port of `encode`/`decode` from
//! `src/cobs.rs`, annotated with the properties we care about. Keep it in
//! sync with the real implementation when either function changes.
//!
//! Verified properties:
//!
//!   * `encode` — the output never contains a `0x00` byte. This is the entire
//!     point of COBS: it lets `0x00` serve as an unambiguous frame delimiter.
//!
//!   * `decode` — on input that is free of `0x00` bytes (the contract upheld
//!     by `read_frame`, which reads up to a `0x00` delimiter), decoding never
//!     panics, never overflows, and never indexes out of bounds. `decode`
//!     runs on attacker-controlled bytes off the wire, so this memory-safety
//!     guarantee is the security-critical property.
//!
//! Run with: `verus verif/cobs.rs` (the `verus` binary is provided by the
//! `nix develop` shell), or `nix build .#cobs-proof`.

use vstd::prelude::*;
use vstd::slice::slice_subrange;

verus! {

/// Errors that can occur while decoding a COBS-encoded buffer. Mirrors the
/// `Truncated` variant of `cobs::Error`; the other variants belong to the I/O
/// layer and are not exercised by `decode`.
pub enum Error {
    Truncated,
}

/// Port of [`cobs::encode`]. Verified to never emit a `0x00` byte.
pub fn encode(input: &[u8]) -> (out: Vec<u8>)
    ensures
        forall|k: int| 0 <= k < out.len() ==> out[k] != 0,
{
    let mut out: Vec<u8> = Vec::new();
    let mut code_pos: usize = 0;
    let mut code: u8 = 1;
    out.push(0); // Reserve one spot for the code byte

    let mut j: usize = 0;
    while j < input.len()
        invariant
            // `code_pos` always points at a live, still-reserved code-byte
            // slot, which currently holds the placeholder `0x00`.
            code_pos < out.len(),
            1 <= code <= 0xfe,
            // Every byte written so far is non-zero, except the one reserved
            // code-byte slot — which is overwritten with a non-zero `code`
            // before (or as) it is left behind.
            forall|k: int| 0 <= k < out.len() && k != code_pos as int ==> out[k] != 0,
        decreases input.len() - j,
    {
        let byte = input[j];
        if byte == 0 {
            out.set(code_pos, code);
            code_pos = out.len();
            out.push(0);
            code = 1;
        } else {
            out.push(byte);
            code = code + 1;

            if code == 0xff {
                out.set(code_pos, 0xff);
                code_pos = out.len();
                out.push(0);
                code = 1;
            }
        }
        j += 1;
    }

    out.set(code_pos, code);
    out
}

/// Port of [`cobs::decode`]. With the no-`0x00` precondition that the framing
/// layer guarantees, Verus proves this is panic-free, overflow-free, and free
/// of out-of-bounds accesses.
///
/// One deliberate change from the source: the truncation check is written as
/// `data_len > input.len() - i` rather than the source's
/// `i + data_len > input.len()`. The two are equivalent, but the latter can
/// overflow `usize` for pathologically large inputs; the subtraction form
/// (with `i <= input.len()` from the loop invariant) cannot. In the firmware
/// `input` is bounded by `MAX_FRAME_LEN`, so the original never actually
/// overflows, but the verified form is unconditionally safe.
pub fn decode(input: &[u8]) -> (res: Result<Vec<u8>, Error>)
    requires
        forall|k: int| 0 <= k < input.len() ==> input[k] != 0,
{
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            forall|k: int| 0 <= k < input.len() ==> input[k] != 0,
        decreases input.len() - i,
    {
        let code = input[i] as usize;
        i += 1;

        if code == 0 {
            // The source `panic!`s here. Under the no-`0x00` precondition this
            // branch is unreachable, which Verus confirms.
            assert(false);
        }

        let data_len = code - 1;
        if data_len > input.len() - i {
            return Err(Error::Truncated);
        }

        out.extend_from_slice(slice_subrange(input, i, i + data_len));
        i += data_len;
        if code != 0xff && i < input.len() {
            out.push(0);
        }
    }
    Ok(out)
}

} // verus!

fn main() {}
