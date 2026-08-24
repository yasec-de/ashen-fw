# Task: a Python host utility that drives the ashen-fw TPM over the Noise link

Write a self-contained Python 3 tool that talks to the `ashen-fw` firmware over
its Noise-protected serial link and exercises the TPM 2.0 core running inside
it. Put it in `tools/` (create the directory). Nothing in `src/` needs to
change; this is a host-side client for a protocol the firmware already speaks.

The firmware side of every detail below lives in
[src/framing.rs](src/framing.rs), [src/noise_link.rs](src/noise_link.rs) and
[src/protocol.rs](src/protocol.rs). `tests/common/mod.rs` plus
`src/test_util.rs::initiator_handshake` are the reference implementation of the
client half — read them before writing anything, and treat them as normative
where this document is ambiguous.

## Connecting

[forward-uart.sh](forward-uart.sh) bridges the device UART to a local TCP
socket via `adb`: it stops `arduino-router` on the QRB2210, holds the boot GPIO,
and runs `socat TCP-LISTEN:$PORT … FILE:$DEV,raw,b$BAUD,echo=0`. Defaults are
`PORT=7600`, `DEV=/dev/ttyHS1`, `BAUD=4000000`.

So the utility connects to `127.0.0.1:7600` over plain TCP. Make host, port and
timeout command-line options. Do **not** open a serial device directly and do
not shell out to `adb`; the operator runs `forward-uart.sh` separately.

## Wire format, outermost first

### 1. COBS framing

Consistent Overhead Byte Stuffing, standard encoding, with `0x00` as the frame
delimiter written *after* each encoded frame. `MAX_PAYLOAD_LEN` is 512 and
`MAX_FRAME_LEN` is `512 + 512/254 + 2`; a frame at or above that length is a
protocol error. Empty frames (a delimiter with nothing before it) are skipped,
not delivered.

### 2. Link reset

The firmware's reader ignores all input until it has seen a reset, so the
utility must reset the link before handshaking:

- Send `RESET_REPLY_NULLS` = **32** zero bytes.
- The device replies with `RESET_NULL_RUN` = **24** zero bytes and marks itself
  synchronised. Read until 24 consecutive nulls have arrived, then proceed.
- Note the asymmetry: nulls beyond the 24th in a run are echoed back one for
  one, so do not assume the reply length equals what you sent.

Mirror `ResetReader::send_reset` in [src/framing.rs](src/framing.rs).

### 3. Noise handshake

`Noise_XX_25519_ChaChaPoly_SHA256`. The utility is the **initiator**, the
firmware the responder. Three messages, each its own COBS frame, all with empty
payloads:

```
-> e
<- e, ee, s, es
-> s, se
```

Use the `noise-protocol`/`dissononce` package or `cryptography` primitives —
your choice, but pin it in a `requirements.txt` and keep the dependency set
small. The initiator's static key is the utility's identity: persist it to a
file (path configurable, default `~/.config/ashen/identity.key`, mode 0600) so
that re-runs present the same key and stay paired.

After the handshake, every message is `transport.write_message(plaintext)` into
one COBS frame, and every received frame is `transport.read_message(...)`. The
ChaCha20-Poly1305 tag is 16 bytes, so a 512-byte frame carries at most 496
bytes of plaintext.

### 4. Protocol messages

First plaintext byte is the type; the rest is the payload. Big-endian
throughout.

| Type | Name | Payload |
|---|---|---|
| 1 | `Log` | log bytes (device → host, may arrive at any time) |
| 2 | `Erase` | none |
| 3 | `PairRequest` | none |
| 4 | `PairResponse` | `u8 success` |
| 5 | `StatusRequest` | none |
| 6 | `StatusResponse` | `u8 peer_trusted`, `u8 is_keyed` |
| 7 | `Disconnect` | none |
| 8 | `EchoRequest` | `u64 value` |
| 9 | `EchoResponse` | `u64 value` |
| 10 | `TpmCommand` | `u8 flags`, then chunk bytes |
| 11 | `TpmResponse` | `u8 flags`, then chunk bytes |

`Log` messages are interleaved with replies whenever the device has output
buffered. **Every receive path must step over them**, and the utility should
print them to stderr with a prefix so the operator can see firmware logs live.
`tests/protocol.rs::receive_skipping_logs` is the model.

### 5. TPM fragmentation

A TPM packet is up to 8192 bytes, far more than one Noise message holds, so it
is split across `TpmCommand` / `TpmResponse` fragments.

- `flags` bit 0 (`FLAG_MORE`, `0x01`) is set on every fragment but the last.
  All other bits are reserved and must be zero.
- Chunk size is `TPM_CHUNK_LEN` = `MAX_PAYLOAD_LEN - 16 - 2` = **494** bytes.
- A zero-length packet is still one fragment, with `more` clear.
- Reassembly is simple concatenation, in order, with no length prefix — the TPM
  header's own size field is the only length information.

The device caps a reassembled command at `FWTPM_MAX_COMMAND_SIZE` = 8192. Going
over that gets an **empty** `TpmResponse` and the partial packet is discarded.
An empty response is also what an unpaired peer gets, and what a TPM-level
dispatch failure produces. Treat "empty TPM response" as an error condition and
report it distinctly from a TPM response carrying a non-zero response code.

Any non-`TpmCommand` message the device receives mid-sequence abandons the
partial packet, so never interleave other requests inside a fragment sequence.

## Pairing and trust

The TPM is gated on the peer being paired. A freshly-erased device is *unkeyed*
and trusts nobody; a peer that completes the Noise handshake is **not**
automatically trusted.

Flow the utility must implement:

1. Send `StatusRequest`, read `StatusResponse`.
2. If `peer_trusted` is set, go straight to the TPM.
3. If `is_keyed` is clear, send `PairRequest` and expect
   `PairResponse { success: 1 }`. The device commits the utility's static key
   (TOFU) and the session becomes trusted immediately — no reconnect needed.
4. If `is_keyed` is set but `peer_trusted` is clear, the device is paired with
   a *different* key. Fail with a clear message telling the operator to run
   `--erase` first. Do not erase implicitly.

Provide an explicit `--erase` subcommand that sends `Erase`. The device then
ends the session, wipes its keystore, rotates its own static identity **and
re-manufactures the TPM**, so the endorsement key changes. The link goes down;
the utility should say so and exit rather than trying to continue.

## TPM commands to exercise

Build the packets by hand — no `tpm2-pytss`, no TSS dependency; a few `struct`
calls are clearer and keep this runnable anywhere.
`tests/tpm.rs` and `tests/tpm_lifecycle.rs` already construct all of the
templates and session structures below in Rust; port them.

Header is `u16 tag`, `u32 size`, `u32 commandCode`. `TPM_ST_NO_SESSIONS` is
`0x8001`, `TPM_ST_SESSIONS` is `0x8002`. Responses are `u16 tag`, `u32 size`,
`u32 responseCode`, then the body; check `size` against the reassembled length.

In order:

1. **`TPM2_Startup(SU_CLEAR)`** — `0x00000144`. Succeeds once per power-up;
   `TPM_RC_INITIALIZE` (`0x100`) on a repeat is expected and not an error.
2. **`TPM2_SelfTest(fullTest=NO)`** — `0x00000143`.
3. **`TPM2_GetCapability(TPM_CAP_COMMANDS, 0x11F, 64)`** — `0x0000017A`. Print
   the number of implemented commands.
4. **`TPM2_GetRandom(32)`** — `0x0000017B`. Call twice, assert the two
   `TPM2B_DIGEST`s differ.
5. **`TPM2_CreatePrimary`** on `TPM_RH_ENDORSEMENT` (`0x4000000B`) —
   `0x00000131`, ECC P-256 ECDSA/SHA-256, empty auth, password session
   (`TPM_RS_PW` = `0x40000009`). Print the public area's digest so the operator
   can compare EKs across runs. Call it twice and assert the public areas match
   — derivation is deterministic per seed.
6. **`TPM2_PCR_Extend`** on PCR 0 in the SHA-256 bank, then **`TPM2_PCR_Read`**
   to confirm the digest changed as expected.
7. **`TPM2_Quote`** over PCR 0 using the primary from step 5, with a
   caller-supplied nonce. Print the signature; verifying it is out of scope for
   now, but structure the code so a verifier can be added.
8. **A fragmentation exercise**: send a command padded to exactly 8192 bytes
   and confirm a well-formed error response comes back rather than a hang or an
   empty frame. Then send one padded to 8193 and confirm the empty-response
   refusal. This is the transport test, not a TPM test.

`wolftpm-examples/STM32/fwtpm-stm32h5/test_uart_tpm.py` upstream is a useful
reference for packet construction, but it speaks raw UART with no Noise layer,
so only the TPM-structure half of it transfers.

## Shape of the tool

- Single file is fine if it stays readable; split if it does not.
- Subcommands: `run` (the sequence above), `status`, `pair`, `erase`,
  `raw <hex>` (send one hand-written TPM packet and print the response hex).
- `--verbose` dumps every frame in both directions as hex, which is what the
  operator will want the first time something does not work.
- Exit non-zero on any failed step, with the failing step named.
- No hidden retries. A timeout is a failure and should say what it was waiting
  for.

## Pass criteria

- `forward-uart.sh` running, board freshly flashed and never paired:
  `tools/<name> run` pairs, walks steps 1–8, and exits 0.
- A second `run` reuses the stored identity, reports `peer_trusted=1`, skips
  pairing, and reports the **same** endorsement key digest as the first run.
- `erase` followed by `run` re-pairs and reports a **different** endorsement key
  digest.
- Firmware log lines appear on stderr throughout, including during the ECC key
  generation in step 5 — that is the visible proof that the executor split is
  working and the link is not stalled behind the TPM.

## Things that will bite you

- The device only ever acts as responder and only ever re-handshakes after a
  session ends. If the utility desynchronises, the fix is a fresh reset burst
  and a new handshake, not a retry of the failed frame.
- `Log` messages can arrive between any two frames, including in the middle of
  a TPM fragment sequence. They do not abandon the sequence — only a non-`Log`,
  non-`TpmCommand` message does.
- Nonces are per-direction and monotonic. Dropping or reordering a frame breaks
  the session permanently; there is no rekey.
