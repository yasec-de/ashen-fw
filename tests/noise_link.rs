//! Host-side test for the Noise_XX/COBS secure link in
//! [`ashen_fw::noise_link`].
//!
//! Builds the link implementation for the host architecture, wires up two
//! in-process, in-memory transports (one per direction) to emulate a
//! USART, and runs a full handshake plus two echo round trips.

use std::thread;

use ashen_fw::noise_link::{KeyStore, MemoryKeyStore, SecureLink, generate_keypair};
use ashen_fw::protocol::{EchoRequest, Envelope, Msg, SessionEnd};

mod common;
use common::{duplex_pair, rng};

#[test]
fn handshake_and_echo_round_trips() {
    let server_keys = generate_keypair(rng(0x1234_5678)).unwrap();
    let client_keys = generate_keypair(rng(0x9876_5432_1234)).unwrap();
    let client_public: [u8; 32] = client_keys.public.clone().try_into().unwrap();

    let (client_io, server_io) = duplex_pair();

    let server_static = server_keys.private.clone();
    let server_thread = thread::spawn(move || {
        embassy_futures::block_on(async move {
            let mut keystore = MemoryKeyStore::default();
            let mut link =
                SecureLink::responder_handshake(server_io, &server_static, rng(0x00C0_FFEE), &mut keystore)
                    .await
                    .expect("server handshake failed");

            // TOFU: the server should have learned and trusted the client's
            // static public key from this first handshake.
            assert_eq!(keystore.trusted_key(), Some(client_public));
            assert_eq!(link.remote_static, client_public);

            // Handle three echo requests, then exit when the client disconnects.
            match link.run_session().await {
                SessionEnd::Disconnected => {}
                SessionEnd::Error(e) => panic!("unexpected session error: {e:?}"),
            }
        });
    });

    embassy_futures::block_on(async move {
        let mut client_keystore = MemoryKeyStore::default();
        let mut client = SecureLink::initiator_handshake(
            client_io,
            &client_keys.private,
            rng(0xDEAD_BEEF),
            &mut client_keystore,
        )
        .await
        .expect("client handshake failed");

        let server_public: [u8; 32] = server_keys.public.clone().try_into().unwrap();
        assert_eq!(client_keystore.trusted_key(), Some(server_public));
        assert_eq!(client.remote_static, server_public);

        // Three echo round trips.
        for value in [41, 99, 1000] {
            client
                .send_envelope(&Envelope {
                    r#msg: Some(Msg::EchoRequest(EchoRequest { r#value: value })),
                })
                .await
                .expect("send echo request failed");

            let response = client.receive_envelope().await.expect("receive echo response");
            match response {
                Envelope {
                    r#msg: Some(Msg::EchoResponse(echo)),
                } => assert_eq!(echo.r#value, value + 1),
                other => panic!("expected echo response, got {other:?}"),
            }
        }

        client.send_disconnect().await.expect("send disconnect failed");
    });

    server_thread.join().expect("server thread panicked");
}

#[test]
fn run_session_returns_error_on_disconnect() {
    let server_keys = generate_keypair(rng(0x1111_1111)).unwrap();
    let client_keys = generate_keypair(rng(0x2222_2222_2222)).unwrap();

    let (client_io, server_io) = duplex_pair();

    let server_static = server_keys.private.clone();
    let server_thread = thread::spawn(move || {
        embassy_futures::block_on(async move {
            let mut keystore = MemoryKeyStore::default();
            let mut link =
                SecureLink::responder_handshake(server_io, &server_static, rng(0xAAAA_AAAA), &mut keystore)
                    .await
                    .expect("server handshake failed");

            // The client sends one echo request, then drops its end of the
            // transport; the server's next read fails with an Io error.
            match link.run_session().await {
                SessionEnd::Error(_) => {}
                SessionEnd::Disconnected => panic!("expected an error, got a clean disconnect"),
            }
        });
    });

    embassy_futures::block_on(async move {
        let mut client_keystore = MemoryKeyStore::default();
        let mut client = SecureLink::initiator_handshake(
            client_io,
            &client_keys.private,
            rng(0xBBBB_BBBB),
            &mut client_keystore,
        )
        .await
        .expect("client handshake failed");

        client
            .send_envelope(&Envelope {
                r#msg: Some(Msg::EchoRequest(EchoRequest { r#value: 41 })),
            })
            .await
            .expect("send echo request failed");

        let response = client.receive_envelope().await.expect("receive echo response");
        match response {
            Envelope {
                r#msg: Some(Msg::EchoResponse(echo)),
            } => assert_eq!(echo.r#value, 42),
            other => panic!("expected echo response, got {other:?}"),
        }

        // Drop the client's transport, closing the channel and causing the
        // server's next read to fail.
        drop(client);
    });

    server_thread.join().expect("server thread panicked");
}
