//! Formally verified COBS encode/decode routines
//! 
//! This file will be built for both verus verification, as well as as part of
//! the actual firmware image. To avoid a dependency mess, it has minimal
//! dependencies and the rest of the COBS framing code handling IO etc. is
//! fractored out into framing.rs
//!
//! Verified properties:
//!
//!   * `encode` — the output never contains a `0x00` byte
//!
//!   * `decode` — on input free of `0x00` bytes, decoding never
//!     panics, never overflows, and never indexes out of bounds
//!
//!   * round trip — `decode(encode(s)) == Ok(s)` for every input `s`
//!     (see `decode_encode_roundtrip`)

// `Vec` is in scope via the std prelude when Verus compiles this file
// standalone, but the firmware is `no_std`, so import it from `alloc`
// explicitly. `extern crate alloc` is redundant with the crate root in the
// firmware build and supplies the crate in the standalone verifier build.
extern crate alloc;
use alloc::vec::Vec;
use vstd::prelude::*;
use vstd::slice::slice_subrange;

verus! {

/// Errors that can occur while decoding a COBS-encoded buffer. `Io` and
/// `Overflow` belong to the frame I/O layer (see the `framing` module) and are
/// never produced by `decode` itself.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// During decoding, we ran out of input data while decoding
    Truncated,
    /// The underlying transport failed.
    Io,
    /// Maximum buffer size exceeded during decoding
    Overflow,
}

/// Pure model of [`decode`], used only for verification. Mirrors the executable
/// `decode` exactly: it consumes one COBS block from the front (a non-zero code
/// byte followed by `code - 1` data bytes), appends the implicit `0x00`
/// separator unless the block is a `0xFF` chaining block or the buffer ends, and
/// recurses on the remainder. Returns `None` for the truncated case (a code byte
/// claiming more data than is present) and for a `0x00` code byte (which the
/// executable `decode` rejects via its precondition).
pub open spec fn decode_spec(input: Seq<u8>) -> Option<Seq<u8>>
    decreases input.len(),
{
    if input.len() == 0 {
        Some(Seq::empty())
    } else {
        let code = input[0] as int;
        if code == 0 {
            None
        } else {
            let data_len = code - 1;
            if data_len > input.len() - 1 {
                None
            } else {
                let data = input.subrange(1, 1 + data_len);
                let rest = input.subrange(1 + data_len, input.len() as int);
                match decode_spec(rest) {
                    Some(tail) => {
                        if code != 0xff && rest.len() > 0 {
                            Some(data + seq![0u8] + tail)
                        } else {
                            Some(data + tail)
                        }
                    }
                    None => None,
                }
            }
        }
    }
}

/// Whether the final COBS block of a (decodable) buffer is a `0xFF` chaining
/// block — i.e. one that carries no implicit trailing `0x00`. Used by the
/// framing lemma below to decide whether concatenating more data introduces a
/// separator zero.
spec fn last_is_ff(c: Seq<u8>) -> bool
    decreases c.len(),
{
    if c.len() == 0 {
        false
    } else {
        let code = c[0] as int;
        if code == 0 {
            false
        } else {
            let data_len = code - 1;
            if data_len > c.len() - 1 {
                false
            } else {
                let rest = c.subrange(1 + data_len, c.len() as int);
                if rest.len() == 0 {
                    code == 0xff
                } else {
                    last_is_ff(rest)
                }
            }
        }
    }
}

/// Separator inserted between the decodings of `c` and `t` when the buffers are
/// concatenated: the last block of `c` gains its implicit `0x00` exactly when
/// `c` is non-empty, ends in a non-`0xFF` block, and is followed by more data.
spec fn concat_sep(c: Seq<u8>, t: Seq<u8>) -> Seq<u8> {
    if c.len() == 0 || t.len() == 0 || last_is_ff(c) {
        Seq::<u8>::empty()
    } else {
        seq![0u8]
    }
}

/// Framing lemma: `decode_spec` is front-recursive, but `encode` grows the
/// *last* block. This relates decoding a concatenation to decoding the parts, so
/// extending the tail can be reasoned about locally. When `c` decodes
/// (`decode_spec(c)` is `Some`), decoding `c + t` is `decode_spec(c)` followed by
/// the separator and `decode_spec(t)` (or `None` when `t` itself truncates).
proof fn lemma_decode_concat(c: Seq<u8>, t: Seq<u8>)
    requires
        decode_spec(c) is Some,
    ensures
        decode_spec(t) is Some ==> decode_spec(c + t) == Some(
            decode_spec(c)->Some_0 + concat_sep(c, t) + decode_spec(t)->Some_0,
        ),
        decode_spec(t) is None ==> decode_spec(c + t) is None,
    decreases c.len(),
{
    if c.len() == 0 {
        assert(c + t =~= t);
        if decode_spec(t) is Some {
            assert(decode_spec(c)->Some_0 + concat_sep(c, t) + decode_spec(t)->Some_0
                =~= decode_spec(t)->Some_0);
        }
    } else {
        let code = c[0] as int;
        let data_len = code - 1;
        let rest_c = c.subrange(1 + data_len, c.len() as int);
        // First block of `c + t` is the first block of `c`.
        assert((c + t)[0] == c[0]);
        assert((c + t).subrange(1, 1 + data_len) =~= c.subrange(1, 1 + data_len));
        assert((c + t).subrange(1 + data_len, (c + t).len() as int) =~= rest_c + t);
        // `decode_spec(c)` is Some, so its first block is well-formed and
        // `decode_spec(rest_c)` is Some; recurse on the shorter `rest_c`.
        lemma_decode_concat(rest_c, t);
    }
}

/// A single COBS block `[code] ++ data` (with exactly `code - 1` data bytes)
/// decodes to its data bytes. Covers both short blocks (`code <= 0xfe`) and a
/// full `0xFF` chaining block.
proof fn lemma_decode_single_block(code: u8, data: Seq<u8>)
    requires
        code >= 1,
        data.len() == code - 1,
    ensures
        decode_spec(seq![code] + data) == Some(data),
{
    let b = seq![code] + data;
    assert(b.len() == code);
    assert(b[0] == code);
    assert(b.subrange(1, 1 + (code - 1)) =~= data);
    assert(b.subrange(1 + (code - 1), b.len() as int) =~= Seq::<u8>::empty());
    reveal_with_fuel(decode_spec, 2);
    assert(data + Seq::<u8>::empty() =~= data);
}

/// Companion to [`lemma_decode_concat`]: when `c` decodes and `t` is non-empty,
/// the last block of `c + t` is the last block of `t`.
proof fn lemma_last_is_ff_concat(c: Seq<u8>, t: Seq<u8>)
    requires
        decode_spec(c) is Some,
        t.len() > 0,
    ensures
        last_is_ff(c + t) == last_is_ff(t),
    decreases c.len(),
{
    if c.len() == 0 {
        assert(c + t =~= t);
    } else {
        let code = c[0] as int;
        let data_len = code - 1;
        let rest_c = c.subrange(1 + data_len, c.len() as int);
        assert((c + t)[0] == c[0]);
        assert((c + t).subrange(1 + data_len, (c + t).len() as int) =~= rest_c + t);
        lemma_last_is_ff_concat(rest_c, t);
    }
}

/// Encodes `input` into COBS form. The result never contains a `0x00` byte.
///
/// The caller is responsible for adding `0x00` frame delimiters as necessary.
///
/// Verified: the returned buffer never contains a `0x00` byte, and it decodes
/// back to `input` exactly (`decode_spec(out@) == Some(input@)`), which —
/// combined with `decode`'s refinement of `decode_spec` — gives the round-trip
/// `decode(encode(s)) == Ok(s)` (see [`decode_encode_roundtrip`]).
pub fn encode(input: &[u8]) -> (out: Vec<u8>)
    ensures
        forall|k: int| 0 <= k < out.len() ==> out[k] != 0,
        decode_spec(out@) == Some(input@),
{
    let mut out: Vec<u8> = Vec::new();
    let mut code_pos: usize = 0;
    let mut code: u8 = 1;
    out.push(0); // Reserve one spot for the code byte
    proof {
        lemma_decode_single_block(1u8, Seq::<u8>::empty());
        assert(seq![1u8] + Seq::<u8>::empty() =~= seq![1u8]);
        assert(out@.update(0, 1u8) =~= seq![1u8]);
        assert(out@.subrange(0, 0) =~= Seq::<u8>::empty());
        assert(input@.subrange(0, 0) =~= Seq::<u8>::empty());
    }

    let mut j: usize = 0;
    while j < input.len()
        invariant
            // `code_pos` always points at a live, still-reserved code-byte slot.
            code_pos < out.len(),
            // The current (open) block spans `[code_pos, out.len())`: its code
            // byte plus `code - 1` data bytes.
            out@.len() == code_pos + code,
            1 <= code <= 0xfe,
            j <= input.len(),
            // Every byte written so far is non-zero, except the reserved
            // code-byte slot — overwritten with a non-zero `code` before it is
            // left behind.
            forall|k: int| 0 <= k < out.len() && k != code_pos as int ==> out[k] != 0,
            // The committed blocks (everything before the current code byte)
            // form a valid, fully-decodable buffer.
            decode_spec(out@.subrange(0, code_pos as int)) is Some,
            // Closing the current block (writing `code` into its code-byte slot)
            // yields a buffer that decodes to exactly the input seen so far.
            decode_spec(out@.update(code_pos as int, code)) == Some(input@.subrange(0, j as int)),
        decreases input.len() - j,
    {
        let ghost out_pre = out@;
        let ghost cp = code_pos as int;
        let ghost c_pre = out_pre.subrange(0, cp);
        let ghost data = out_pre.subrange(cp + 1, out_pre.len() as int);
        let ghost b_pre = seq![code] + data;
        let ghost patched_pre = out_pre.update(cp, code);
        proof {
            // `patched_pre` splits into the committed prefix `c_pre` and the
            // closed current block `b_pre = [code] ++ data` (which has `code - 1`
            // data bytes), so a lone `b_pre` decodes to `data`.
            assert(data.len() == code - 1);
            assert(patched_pre.subrange(cp, out_pre.len() as int) =~= b_pre);
            assert(patched_pre =~= c_pre + b_pre);
            lemma_decode_single_block(code, data);
            // Re-express the invariant via the framing lemma.
            lemma_decode_concat(c_pre, b_pre);
        }

        let byte = input[j];
        if byte == 0 {
            out.set(code_pos, code);
            code_pos = out.len();
            out.push(0);
            code = 1;
            proof {
                // New committed prefix is exactly `patched_pre`; the new open
                // block is the empty `[1]`. The closed short block is not a
                // `0xFF` block, so concatenating gains the implicit separator
                // `0x00` — which is exactly the input's zero byte at `j`.
                lemma_last_is_ff_concat(c_pre, b_pre);
                lemma_decode_single_block(1u8, Seq::<u8>::empty());
                assert(seq![1u8] + Seq::<u8>::empty() =~= seq![1u8]);
                assert(out@.subrange(0, code_pos as int) =~= patched_pre);
                assert(out@.update(code_pos as int, 1u8) =~= patched_pre + seq![1u8]);
                lemma_decode_concat(patched_pre, seq![1u8]);
                assert(input@.subrange(0, j as int) + seq![0u8] =~= input@.subrange(0, j + 1));
            }
        } else {
            out.push(byte);
            code = code + 1;

            if code == 0xff {
                out.set(code_pos, 0xff);
                code_pos = out.len();
                out.push(0);
                code = 1;
                proof {
                    // The current block fills up into a `0xFF` chaining block of
                    // 254 data bytes, then a fresh empty `[1]` block opens. A
                    // `0xFF` block carries no implicit separator, so the new
                    // empty block adds nothing.
                    let b_closed = seq![0xffu8] + (data + seq![byte]);
                    assert((data + seq![byte]).len() == 0xffu8 - 1);
                    lemma_decode_single_block(0xffu8, data + seq![byte]);
                    assert(out@.subrange(0, code_pos as int) =~= c_pre + b_closed);
                    lemma_decode_concat(c_pre, b_closed);
                    lemma_last_is_ff_concat(c_pre, b_closed);
                    lemma_decode_single_block(1u8, Seq::<u8>::empty());
                    assert(seq![1u8] + Seq::<u8>::empty() =~= seq![1u8]);
                    assert(out@.update(code_pos as int, 1u8) =~= (c_pre + b_closed) + seq![1u8]);
                    lemma_decode_concat(c_pre + b_closed, seq![1u8]);
                    assert(last_is_ff(b_closed));
                    assert(data + seq![byte] =~= b_pre.subrange(1, b_pre.len() as int) + seq![byte]);
                    assert(input@.subrange(0, j as int) + seq![byte] =~= input@.subrange(0, j + 1));
                }
            } else {
                proof {
                    // The current block just grows by one data byte; `code_pos`
                    // is unchanged, so the committed prefix and its separator are
                    // unchanged.
                    let b_post = seq![code] + (data + seq![byte]);
                    assert((data + seq![byte]).len() == code - 1);
                    lemma_decode_single_block(code, data + seq![byte]);
                    // `code_pos` is unchanged, so the committed prefix is too.
                    assert(out@.subrange(0, cp) =~= c_pre);
                    assert(out@.update(cp, code) =~= c_pre + b_post);
                    lemma_decode_concat(c_pre, b_post);
                    assert(input@.subrange(0, j as int) + seq![byte] =~= input@.subrange(0, j + 1));
                }
            }
        }
        j += 1;
    }

    out.set(code_pos, code);
    proof {
        assert(input@.subrange(0, input@.len() as int) =~= input@);
    }
    out
}

/// Decodes a COBS-encoded buffer (without leading or trailing `0x00` delimiters)
/// back into the original bytes.
///
/// The caller must pass a buffer free of embedded `0x00` bytes.
///
/// Verified: the result matches the pure model [`decode_spec`] — `Ok(v)` exactly
/// when the model yields `Some(v)`, and `Err(Truncated)` exactly when it yields
/// `None`.
pub fn decode(input: &[u8]) -> (res: Result<Vec<u8>, Error>)
    requires
        forall|k: int| 0 <= k < input.len() ==> input[k] != 0,
    ensures
        match res {
            Ok(v) => decode_spec(input@) == Some(v@),
            Err(e) => e == Error::Truncated && decode_spec(input@) == None::<Seq<u8>>,
        },
{
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    proof {
        // Establish the invariant at entry: `subrange(0, len) == input@` and,
        // since `out` is empty, `Seq::empty() + tail == tail`.
        assert(input@.subrange(0, input@.len() as int) =~= input@);
        if let Some(tail) = decode_spec(input@) {
            assert(Seq::<u8>::empty() + tail =~= tail);
        }
    }
    while i < input.len()
        invariant
            i <= input.len(),
            forall|k: int| 0 <= k < input.len() ==> input[k] != 0,
            decode_spec(input@) == match decode_spec(input@.subrange(i as int, input@.len() as int)) {
                Some(tail) => Some(out@ + tail),
                None => None::<Seq<u8>>,
            },
        decreases input.len() - i,
    {
        let ghost start = i as int;
        let ghost sub = input@.subrange(start, input@.len() as int);
        let ghost out_old = out@;
        assert(sub[0] == input@[start]);

        let code = input[i] as usize;
        i += 1;

        assert(code != 0);

        let data_len = code - 1;
        // Overflow-safe form of `i + data_len > input.len()`: with `i <=
        // input.len()` from the loop invariant, this subtraction cannot wrap.
        if data_len > input.len() - i {
            // `decode_spec(sub)` truncates here too: same code byte, same
            // `data_len > sub.len() - 1` check.
            assert(decode_spec(sub) == None::<Seq<u8>>);
            return Err(Error::Truncated);
        }

        let ghost data = input@.subrange(i as int, i as int + data_len as int);
        let ghost tail_in = input@.subrange(i as int + data_len as int, input@.len() as int);

        out.extend_from_slice(slice_subrange(input, i, i + data_len));
        i += data_len;
        if code != 0xff && i < input.len() {
            out.push(0);
        }

        proof {
            // The data bytes and remaining suffix of `sub`, expressed as
            // subranges of `input@`.
            assert(sub.subrange(1, 1 + data_len as int) =~= data);
            assert(sub.subrange(1 + data_len as int, sub.len() as int) =~= tail_in);
            assert(tail_in =~= input@.subrange(i as int, input@.len() as int));
            // `decode_spec(sub)` unfolds (fuel 1) to `Some(data (+ [0]) + tail)`
            // where `tail == decode_spec(tail_in)`. The exec code appended
            // exactly `data (+ [0])` to `out`. With the old invariant
            // `decode_spec(input@) == map(decode_spec(sub), out_old + _)` and
            // associativity of `+`, the invariant holds for the new `out`/`i`.
            let tail = decode_spec(tail_in);
            if code != 0xff && tail_in.len() > 0 {
                assert(out@ =~= out_old + data + seq![0u8]);
                assert(decode_spec(sub) matches Some(s) ==> s =~= data + seq![0u8] + tail->Some_0);
            } else {
                assert(out@ =~= out_old + data);
            }
        }
    }
    assert(input@.subrange(i as int, input@.len() as int) =~= Seq::<u8>::empty());
    Ok(out)
}

/// The round-trip theorem, stated so Verus checks it end to end: for any `s`,
/// `decode(encode(s)) == Ok(s)`. `encode`'s post-condition gives
/// `decode_spec(encode(s)@) == Some(s@)` (so `encode`'s output is zero-free and
/// non-truncating, satisfying `decode`'s precondition and ruling out its `Err`
/// branch), and `decode`'s refinement of `decode_spec` then forces the result to
/// be `Ok(s)` — which the post-condition `r@ == s@` and the proven-safe `unwrap`
/// witness. Compiled only during verification.
#[cfg(verus_keep_ghost)]
fn decode_encode_roundtrip(s: &[u8]) -> (r: Vec<u8>)
    ensures
        r@ == s@,
{
    let encoded = encode(s);
    let result = decode(&encoded);
    assert(decode_spec(encoded@) == Some(s@));
    result.unwrap()
}

} // verus!
