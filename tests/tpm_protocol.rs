//! End-to-end tests for the TPM-over-Noise transport: fragment assembly, the
//! trust gate, and the cap on reassembled packet length.

use std::thread;

use ashen_fw::framing::ResetReader;
use ashen_fw::noise_link::{KeyStore, NoiseLink, generate_keypair};
use ashen_fw::protocol::{Message, SessionEnd, TPM_CHUNK_LEN, max_tpm_packet_len};
use ashen_fw::test_util::TestKeyStore;
use ashen_fw::tpm;

mod common;
use common::{ChannelIo, WriteGate, duplex_pair, duplex_pair_gated, rng, secret_keys};

const ST_NO_SESSIONS: u16 = 0x8001;
const CC_STARTUP: u32 = 0x0000_0144;
const CC_GET_RANDOM: u32 = 0x0000_017B;
const CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
const CC_NV_WRITE: u32 = 0x0000_0137;
const CC_NV_READ: u32 = 0x0000_014E;
const ST_SESSIONS: u16 = 0x8002;
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RS_PW: u32 = 0x4000_0009;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPMA_NV_AUTHWRITE: u32 = 1 << 2;
const TPMA_NV_AUTHREAD: u32 = 1 << 18;
const TPMA_NV_NO_DA: u32 = 1 << 25;
const RC_NV_DEFINED: u32 = 0x0000_014C;
const NV_INDEX: u32 = 0x0150_0A5E;
const NV_SIZE: u16 = 512;
const CC_UNKNOWN: u32 = 0x0000_FFFF;
const SU_CLEAR: u16 = 0x0000;
const RC_SUCCESS: u32 = 0x0000_0000;

/// The TPM core is a process-wide singleton with no internal locking, so tests
/// that drive it take turns.
static TPM_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn boot() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    let guard = TPM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    ONCE.call_once(|| tpm::init().expect("fwTPM failed to initialise"));
    guard
}

fn command(cc: u32, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + params.len());
    out.extend_from_slice(&ST_NO_SESSIONS.to_be_bytes());
    out.extend_from_slice(&((10 + params.len()) as u32).to_be_bytes());
    out.extend_from_slice(&cc.to_be_bytes());
    out.extend_from_slice(params);
    out
}

fn pw_command(cc: u32, handles: &[u32], params: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for handle in handles {
        body.extend_from_slice(&handle.to_be_bytes());
    }
    body.extend_from_slice(&9u32.to_be_bytes());
    body.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(params);

    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(&ST_SESSIONS.to_be_bytes());
    out.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(&cc.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn nv_fill(client: &mut NoiseLink<ChannelIo>) {
    let mut public = Vec::new();
    public.extend_from_slice(&NV_INDEX.to_be_bytes());
    public.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    public.extend_from_slice(
        &(TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA).to_be_bytes(),
    );
    public.extend_from_slice(&0u16.to_be_bytes());
    public.extend_from_slice(&NV_SIZE.to_be_bytes());
    let mut params = Vec::new();
    params.extend_from_slice(&0u16.to_be_bytes());
    params.extend_from_slice(&(public.len() as u16).to_be_bytes());
    params.extend_from_slice(&public);
    let rsp = exchange(client, &pw_command(CC_NV_DEFINE_SPACE, &[TPM_RH_OWNER], &params));
    let code = response_code(&rsp);
    assert!(
        code == RC_SUCCESS || code == RC_NV_DEFINED,
        "TPM2_NV_DefineSpace failed with 0x{code:08X}"
    );

    let mut params = Vec::new();
    params.extend_from_slice(&NV_SIZE.to_be_bytes());
    params.extend((0..NV_SIZE).map(|i| i as u8));
    params.extend_from_slice(&0u16.to_be_bytes());
    let rsp = exchange(client, &pw_command(CC_NV_WRITE, &[NV_INDEX, NV_INDEX], &params));
    let code = response_code(&rsp);
    assert_eq!(code, RC_SUCCESS, "TPM2_NV_Write failed with 0x{code:08X}");
}

/// A command padded out to exactly `len` bytes. The TPM will reject the trailing
/// garbage, which is fine: these tests are about the transport, and a rejection
/// still produces a full response packet.
fn padded_command(len: usize) -> Vec<u8> {
    assert!(len >= 10);
    let mut out = command(CC_UNKNOWN, &[]);
    out.resize(len, 0xA5);
    out[2..6].copy_from_slice(&(len as u32).to_be_bytes());
    out
}

fn response_code(rsp: &[u8]) -> u32 {
    assert!(rsp.len() >= 10, "response shorter than a TPM header: {rsp:?}");
    assert_eq!(
        u32::from_be_bytes(rsp[2..6].try_into().unwrap()) as usize,
        rsp.len(),
        "header size disagrees with the reassembled length"
    );
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

/// Runs a device-side `run_session` against a client, with the device already
/// paired to that client unless `paired` is false. Returns once both sides are
/// done; the closure drives the client.
fn with_session<F>(seed: u64, paired: bool, client_body: F)
where
    F: FnOnce(&mut NoiseLink<ChannelIo>),
{
    with_gated_session(seed, paired, |client, _| client_body(client));
}

fn with_gated_session<F>(seed: u64, paired: bool, client_body: F)
where
    F: FnOnce(&mut NoiseLink<ChannelIo>, &WriteGate),
{
    let _serial = boot();
    let server_keys = generate_keypair(rng(seed)).unwrap();
    let client_keys = generate_keypair(rng(seed ^ 0x5555_5555_5555)).unwrap();
    let client_public: [u8; 32] = client_keys.public.clone().try_into().unwrap();

    let (client_io, server_io, gate) = duplex_pair_gated();
    let client_secrets = secret_keys(&client_keys.private);
    let server_static = server_keys.private.clone();

    let server_thread = thread::spawn(move || {
        embassy_futures::block_on(async move {
            let mut keystore = TestKeyStore::default();
            if paired {
                keystore.trust(client_public);
            }
            let mut link = NoiseLink::responder_handshake_retry(
                ResetReader::new(server_io),
                secret_keys(&server_static),
                || rng(seed ^ 0x00C0_FFEE),
                &mut keystore,
            )
            .await;
            assert_eq!(link.is_peer_trusted(), paired);

            match link.run_session(&mut keystore).await {
                SessionEnd::Disconnected => {}
                other => panic!("expected SessionEnd::Disconnected, got {other:?}"),
            }
        });
    });

    let mut client = embassy_futures::block_on(NoiseLink::initiator_handshake(
        client_io,
        client_secrets,
        rng(seed ^ 0xDEAD_BEEF),
    ))
    .expect("client handshake failed");

    client_body(&mut client, &gate);
    embassy_futures::block_on(client.send_disconnect()).expect("send disconnect");

    server_thread.join().expect("server thread panicked");
}

/// Sends a TPM command and reassembles the reply, blocking the caller.
fn exchange(client: &mut NoiseLink<ChannelIo>, packet: &[u8]) -> Vec<u8> {
    embassy_futures::block_on(async {
        client.send_tpm_command(packet).await.expect("send command");
        client.receive_tpm_packet().await.expect("receive response")
    })
}

fn startup(client: &mut NoiseLink<ChannelIo>) {
    let rsp = exchange(client, &command(CC_STARTUP, &SU_CLEAR.to_be_bytes()));
    let code = response_code(&rsp);
    // The TPM core is a process-wide singleton shared with the other tests in
    // this binary, so it may already have been started.
    assert!(
        code == RC_SUCCESS || code == 0x0000_0100,
        "TPM2_Startup failed with 0x{code:08X}"
    );
}

#[test]
fn a_single_fragment_command_round_trips() {
    with_session(0x1111_0001, true, |client| {
        startup(client);
        let rsp = exchange(client, &command(CC_GET_RANDOM, &16u16.to_be_bytes()));
        assert_eq!(response_code(&rsp), RC_SUCCESS);
        // TPM2B_DIGEST of 16 bytes on top of the 10-byte header.
        assert_eq!(rsp.len(), 10 + 2 + 16);
    });
}

#[test]
fn a_command_of_exactly_one_chunk_round_trips() {
    with_session(0x1111_0002, true, |client| {
        startup(client);
        let rsp = exchange(client, &padded_command(TPM_CHUNK_LEN));
        assert_ne!(response_code(&rsp), RC_SUCCESS);
    });
}

#[test]
fn a_command_one_byte_past_a_chunk_boundary_round_trips() {
    with_session(0x1111_0003, true, |client| {
        startup(client);
        let rsp = exchange(client, &padded_command(TPM_CHUNK_LEN + 1));
        assert_ne!(response_code(&rsp), RC_SUCCESS);
    });
}

#[test]
fn a_command_filling_the_cap_exactly_is_accepted() {
    with_session(0x1111_0004, true, |client| {
        startup(client);
        let max = max_tpm_packet_len();
        assert!(max > TPM_CHUNK_LEN, "the cap must need fragmenting at all");
        let rsp = exchange(client, &padded_command(max));
        // Accepted by the transport, rejected by the TPM: a real response, not
        // the empty refusal frame.
        assert!(!rsp.is_empty(), "the maximum-size command was refused");
        assert_ne!(response_code(&rsp), RC_SUCCESS);
    });
}

#[test]
fn a_command_one_byte_over_the_cap_is_refused_and_the_link_survives() {
    with_session(0x1111_0005, true, |client| {
        startup(client);
        let rsp = exchange(client, &padded_command(max_tpm_packet_len() + 1));
        assert!(rsp.is_empty(), "oversized command was not refused");

        // The refusal must not have left a partial packet behind.
        let rsp = exchange(client, &command(CC_GET_RANDOM, &8u16.to_be_bytes()));
        assert_eq!(response_code(&rsp), RC_SUCCESS);
        assert_eq!(rsp.len(), 10 + 2 + 8);
    });
}

#[test]
fn a_control_message_inside_a_fragment_sequence_does_not_break_it() {
    with_session(0x1111_0006, true, |client| {
        startup(client);
        let cmd = command(CC_GET_RANDOM, &8u16.to_be_bytes());
        let (head, tail) = cmd.split_at(6);
        let rsp = embassy_futures::block_on(async {
            client
                .send_msg(&Message::TpmCommand {
                    more: true,
                    chunk: head.into(),
                })
                .await
                .expect("send first fragment");
            client
                .send_msg(&Message::StatusRequest)
                .await
                .expect("send status request");
            client
                .send_msg(&Message::TpmCommand {
                    more: false,
                    chunk: tail.into(),
                })
                .await
                .expect("send last fragment");

            loop {
                match client.receive_msg().await.expect("receive") {
                    Message::Log(_) => continue,
                    Message::StatusResponse { peer_trusted, .. } => {
                        assert!(peer_trusted);
                        break;
                    }
                    other => panic!("expected a status response, got {other:?}"),
                }
            }
            client.receive_tpm_packet().await.expect("receive response")
        });

        assert_eq!(response_code(&rsp), RC_SUCCESS);
        assert_eq!(rsp.len(), 10 + 2 + 8);
    });
}

#[test]
fn a_heartbeat_preempts_a_multi_fragment_response() {
    with_gated_session(0x1111_0009, true, |client, gate| {
        startup(client);
        nv_fill(client);
        let mut params = Vec::new();
        params.extend_from_slice(&NV_SIZE.to_be_bytes());
        params.extend_from_slice(&0u16.to_be_bytes());
        let cmd = pw_command(CC_NV_READ, &[NV_INDEX, NV_INDEX], &params);

        embassy_futures::block_on(async {
            gate.close();
            client.send_tpm_command(&cmd).await.expect("send command");
            gate.wait_for_blocked_writer();
            client
                .send_msg(&Message::EchoRequest { value: 41 })
                .await
                .expect("send heartbeat");
            gate.open();

            let mut fragments = 0;
            let mut echoed_after = None;
            let mut packet = Vec::new();
            loop {
                match client.receive_msg().await.expect("receive") {
                    Message::Log(_) => {}
                    Message::EchoResponse { value } => {
                        assert_eq!(value, 42);
                        echoed_after = Some(fragments);
                    }
                    Message::TpmResponse { more, chunk } => {
                        fragments += 1;
                        packet.extend_from_slice(&chunk);
                        if !more {
                            break;
                        }
                    }
                    other => panic!("unexpected message: {other:?}"),
                }
            }

            assert!(fragments >= 2, "response fit in {fragments} fragment(s)");
            assert_eq!(response_code(&packet), RC_SUCCESS);
            match echoed_after {
                Some(n) if n > 0 && n < fragments => {}
                other => panic!(
                    "echo answered after fragment {other:?} of {fragments}, \
                     expected strictly inside the response"
                ),
            }
        });
    });
}

/// The heartbeat is a periodic `EchoRequest`, so it must not queue behind a
/// TPM command. `run_session` races the link against the TPM's answer rather
/// than awaiting the answer inline; this is the test that says so.
#[test]
fn a_heartbeat_is_answered_while_a_tpm_command_is_outstanding() {
    with_session(0x1111_0008, true, |client| {
        startup(client);
        embassy_futures::block_on(async {
            client
                .send_tpm_command(&command(CC_GET_RANDOM, &16u16.to_be_bytes()))
                .await
                .expect("send command");
            client
                .send_msg(&Message::EchoRequest { value: 41 })
                .await
                .expect("send heartbeat");

            let mut echoed = false;
            let mut answer: Option<Vec<u8>> = None;
            let mut packet = Vec::new();

            while !echoed || answer.is_none() {
                match client.receive_msg().await.expect("receive") {
                    Message::Log(_) => {}
                    Message::EchoResponse { value } => {
                        assert_eq!(value, 42);
                        echoed = true;
                    }
                    Message::TpmResponse { more, chunk } => {
                        packet.extend_from_slice(&chunk);
                        if !more {
                            answer = Some(std::mem::take(&mut packet));
                        }
                    }
                    other => panic!("unexpected message: {other:?}"),
                }
            }

            assert_eq!(response_code(&answer.unwrap()), RC_SUCCESS);
        });
    });
}

#[test]
fn an_unpaired_peer_cannot_drive_the_tpm() {
    with_session(0x1111_0007, false, |client| {
        let rsp = exchange(client, &command(CC_GET_RANDOM, &16u16.to_be_bytes()));
        assert!(rsp.is_empty(), "an unpaired peer got a TPM response");
    });
}

/// Fragmentation and reassembly are inverses over the whole length range,
/// tested directly on the transport rather than through the TPM so that
/// arbitrary packet lengths are reachable.
#[test]
fn fragmentation_round_trips_over_the_whole_length_range() {
    let server_keys = generate_keypair(rng(0x2222_0001)).unwrap();
    let client_keys = generate_keypair(rng(0x2222_0002)).unwrap();

    let (client_io, server_io) = duplex_pair();
    let client_secrets = secret_keys(&client_keys.private);
    let server_static = server_keys.private.clone();

    let max = tpm::max_command_size();
    let mut lengths: Vec<usize> = vec![
        0,
        1,
        TPM_CHUNK_LEN - 1,
        TPM_CHUNK_LEN,
        TPM_CHUNK_LEN + 1,
        2 * TPM_CHUNK_LEN,
        max - 1,
        max,
    ];
    let mut state = 0x243F_6A88_85A3_08D3u64;
    for _ in 0..24 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        lengths.push((state as usize) % (max + 1));
    }
    let expected = lengths.clone();

    let server_thread = thread::spawn(move || {
        embassy_futures::block_on(async move {
            let mut keystore = TestKeyStore::default();
            let mut link = NoiseLink::responder_handshake_retry(
                ResetReader::new(server_io),
                secret_keys(&server_static),
                || rng(0x2222_0003),
                &mut keystore,
            )
            .await;
            for len in lengths {
                let packet: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                link.send_tpm_response(&packet).await.expect("send packet");
            }
        });
    });

    embassy_futures::block_on(async move {
        let mut client =
            NoiseLink::initiator_handshake(client_io, client_secrets, rng(0x2222_0004))
                .await
                .expect("client handshake failed");
        for len in expected {
            let packet = client.receive_tpm_packet().await.expect("receive packet");
            assert_eq!(packet.len(), len, "reassembled length differs");
            assert!(
                packet.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8),
                "reassembled {len}-byte packet has wrong contents"
            );
        }
    });

    server_thread.join().expect("server thread panicked");
}
