//! Host-side tests for the byte protocol in [`ashen_fw::protocol`].

use std::thread;

use ashen_fw::noise_link::{KeyStore, NoiseLink, generate_keypair};
use ashen_fw::test_util::TestKeyStore;
use ashen_fw::protocol::{Message, SessionEnd};

mod common;
use common::{duplex_pair, rng};

#[test]
fn echo_request_replies_with_value_plus_one() {
    let server_keys = generate_keypair(rng(0x1234_5678)).unwrap();
    let client_keys = generate_keypair(rng(0x9876_5432_1234)).unwrap();

    let (client_io, server_io) = duplex_pair();

    let server_static = server_keys.private.clone();
    let server_thread = thread::spawn(move || {
        embassy_futures::block_on(async move {
            let mut keystore = TestKeyStore::default();
            let mut link =
                NoiseLink::responder_handshake(server_io, &server_static, rng(0x00C0_FFEE), &mut keystore)
                    .await
                    .expect("server handshake failed");

            match link.run_session(&mut keystore).await {
                SessionEnd::Disconnected => {}
                SessionEnd::Erased => panic!("unexpected SessionEnd::Erased"),
                SessionEnd::Error(e) => panic!("unexpected session error: {e:?}"),
            }
        });
    });

    embassy_futures::block_on(async move {
        let mut client = NoiseLink::initiator_handshake(
            client_io,
            &client_keys.private,
            rng(0xDEAD_BEEF),
        )
        .await
        .expect("client handshake failed");

        client
            .send_msg(&Message::EchoRequest { value: 41 })
            .await
            .expect("send echo request failed");

        let response = client.receive_msg().await.expect("receive echo response");
        match response {
            Message::EchoResponse { value } => assert_eq!(value, 42),
            other => panic!("expected echo response, got {other:?}"),
        }

        client.send_disconnect().await.expect("send disconnect failed");
    });

    server_thread.join().expect("server thread panicked");
}

#[test]
fn send_log_message_round_trips() {
    let server_keys = generate_keypair(rng(0x3333_3333)).unwrap();
    let client_keys = generate_keypair(rng(0x4444_4444_4444)).unwrap();

    let (client_io, server_io) = duplex_pair();

    let server_static = server_keys.private.clone();
    let server_thread = thread::spawn(move || {
        embassy_futures::block_on(async move {
            let mut keystore = TestKeyStore::default();
            let mut link =
                NoiseLink::responder_handshake(server_io, &server_static, rng(0xC0DE_C0DE), &mut keystore)
                    .await
                    .expect("server handshake failed");

            link.send_log_message(b"defmt frame bytes")
                .await
                .expect("send log message failed");

            match link.run_session(&mut keystore).await {
                SessionEnd::Disconnected => {}
                SessionEnd::Erased => panic!("unexpected SessionEnd::Erased"),
                SessionEnd::Error(e) => panic!("unexpected session error: {e:?}"),
            }
        });
    });

    embassy_futures::block_on(async move {
        let mut client = NoiseLink::initiator_handshake(
            client_io,
            &client_keys.private,
            rng(0xFEED_FACE),
        )
        .await
        .expect("client handshake failed");

        let response = client.receive_msg().await.expect("receive log message");
        match response {
            Message::Log(data) => {
                assert_eq!(data, b"defmt frame bytes");
            }
            other => panic!("expected log message, got {other:?}"),
        }

        client.send_disconnect().await.expect("send disconnect failed");
    });

    server_thread.join().expect("server thread panicked");
}

/// An [`Erase`](ashen_fw::protocol::Message::Erase) message ends the session
/// like a [`Disconnect`](ashen_fw::protocol::Message::Disconnect), but the
/// responder additionally has to erase its TOFU keystore (forgetting the
/// previously-trusted remote static key).
#[test]
fn erase_request_ends_session_and_clears_keystore() {
    let server_keys = generate_keypair(rng(0x1234_5678)).unwrap();
    let client_keys = generate_keypair(rng(0x9876_5432_1234)).unwrap();
    let client_public: [u8; 32] = client_keys.public.clone().try_into().unwrap();

    let (client_io, server_io) = duplex_pair();

    let server_static = server_keys.private.clone();
    let server_thread = thread::spawn(move || {
        embassy_futures::block_on(async move {
            // Simulate a device that was previously paired with this client:
            // its static key is already committed to the keystore.
            let mut keystore = TestKeyStore::default();
            keystore.trust(client_public);

            let mut link =
                NoiseLink::responder_handshake(server_io, &server_static, rng(0x00C0_FFEE), &mut keystore)
                    .await
                    .expect("server handshake failed");

            // The presented key matches the trusted one, so the peer is trusted.
            assert_eq!(keystore.trusted_key(), Some(client_public));
            assert!(link.is_peer_trusted());

            match link.run_session(&mut keystore).await {
                SessionEnd::Erased => {}
                other => panic!("expected SessionEnd::Erased, got {other:?}"),
            }

            // The session handler itself doesn't erase the keystore; that's
            // the caller's responsibility upon seeing `SessionEnd::Erased`
            // (see `ashen_fw::main`'s session loop).
            keystore.erase();
            assert_eq!(keystore.trusted_key(), None);
        });
    });

    embassy_futures::block_on(async move {
        let mut client = NoiseLink::initiator_handshake(
            client_io,
            &client_keys.private,
            rng(0xDEAD_BEEF),
        )
        .await
        .expect("client handshake failed");

        client.send_erase().await.expect("send erase failed");
    });

    server_thread.join().expect("server thread panicked");
}

#[test]
fn echo_request_overflow_panics() {
    let server_keys = generate_keypair(rng(0x1111_1111)).unwrap();
    let client_keys = generate_keypair(rng(0x2222_2222_2222)).unwrap();

    let (client_io, server_io) = duplex_pair();

    let server_static = server_keys.private.clone();
    let server_thread = thread::spawn(move || {
        embassy_futures::block_on(async move {
            let mut keystore = TestKeyStore::default();
            let mut link =
                NoiseLink::responder_handshake(server_io, &server_static, rng(0xAAAA_AAAA), &mut keystore)
                    .await
                    .expect("server handshake failed");

            // Should panic on overflow rather than wrap or return an error.
            link.run_session(&mut keystore).await;
        });
    });

    embassy_futures::block_on(async move {
        let mut client = NoiseLink::initiator_handshake(
            client_io,
            &client_keys.private,
            rng(0xBBBB_BBBB),
        )
        .await
        .expect("client handshake failed");

        client
            .send_msg(&Message::EchoRequest { value: u64::MAX })
            .await
            .expect("send echo request failed");
    });

    let result = server_thread.join();
    assert!(result.is_err(), "server thread should have panicked");
}
