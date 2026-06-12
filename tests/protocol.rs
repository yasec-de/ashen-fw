//! Host-side tests for the protobuf protocol in [`ashen_fw::protocol`].

use std::thread;

use ashen_fw::noise_link::{KeyStore, NoiseLink, generate_keypair};
use ashen_fw::test_util::TestKeyStore;
use ashen_fw::protocol::{EchoRequest, Envelope, Msg, SessionEnd};

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

            match link.run_session().await {
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

            match link.run_session().await {
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

        let response = client.receive_envelope().await.expect("receive log message");
        match response {
            Envelope {
                r#msg: Some(Msg::Log(log)),
            } => {
                assert_eq!(log.r#data, b"defmt frame bytes");
            }
            other => panic!("expected log message, got {other:?}"),
        }

        client.send_disconnect().await.expect("send disconnect failed");
    });

    server_thread.join().expect("server thread panicked");
}

/// An [`Erase`](ashen_fw::protocol::Erase) message ends the session like a
/// [`Disconnect`], but the responder additionally has to erase its TOFU
/// keystore (forgetting the previously-trusted remote static key).
#[test]
fn erase_request_ends_session_and_clears_keystore() {
    let server_keys = generate_keypair(rng(0x1234_5678)).unwrap();
    let client_keys = generate_keypair(rng(0x9876_5432_1234)).unwrap();
    let client_public: [u8; 32] = client_keys.public.clone().try_into().unwrap();

    let (client_io, server_io) = duplex_pair();

    let server_static = server_keys.private.clone();
    let server_thread = thread::spawn(move || {
        embassy_futures::block_on(async move {
            let mut keystore = TestKeyStore::default();
            let mut link =
                NoiseLink::responder_handshake(server_io, &server_static, rng(0x00C0_FFEE), &mut keystore)
                    .await
                    .expect("server handshake failed");

            // TOFU: the server learned the client's static key on this
            // first handshake.
            assert_eq!(keystore.trusted_key(), Some(client_public));

            match link.run_session().await {
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
            link.run_session().await;
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
            .send_envelope(&Envelope {
                r#msg: Some(Msg::EchoRequest(EchoRequest { r#value: u64::MAX })),
            })
            .await
            .expect("send echo request failed");
    });

    let result = server_thread.join();
    assert!(result.is_err(), "server thread should have panicked");
}
