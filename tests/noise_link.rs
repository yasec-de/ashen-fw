//! Host-side test for the Noise_XX/COBS secure link in

use std::thread;

use ashen_fw::framing::ResetReader;
use ashen_fw::noise_link::{KeyStore, NoiseLink, generate_keypair};
use ashen_fw::test_util::TestKeyStore;
use ashen_fw::protocol::{Message, SessionEnd};

mod common;
use common::{duplex_pair, rng, secret_keys};

#[test]
fn handshake_and_echo_round_trips() {
    let server_keys = generate_keypair(rng(0x1234_5678)).unwrap();
    let client_keys = generate_keypair(rng(0x9876_5432_1234)).unwrap();
    let client_public: [u8; 32] = client_keys.public.clone().try_into().unwrap();

    let (client_io, server_io) = duplex_pair();

    let client_secrets = secret_keys(&client_keys.private);

    let server_static = server_keys.private.clone();
    let server_thread = thread::spawn(move || {
        embassy_futures::block_on(async move {
            let server_secrets = secret_keys(&server_static);
            let mut keystore = TestKeyStore::default();
            let mut link =
                NoiseLink::responder_handshake_retry(ResetReader::new(server_io), server_secrets, || rng(0x00C0_FFEE), &mut keystore)
                    .await;

            assert_eq!(keystore.trusted_key(), None);
            assert!(!link.is_peer_trusted());
            assert_eq!(link.peer_key(), client_public);

            // Handle three echo requests, then exit when the client disconnects.
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
            client_secrets,
            rng(0xDEAD_BEEF),
        )
        .await
        .expect("client handshake failed");

        let server_public: [u8; 32] = server_keys.public.clone().try_into().unwrap();
        assert_eq!(client.peer_key(), server_public);

        // Three echo round trips.
        for value in [41, 99, 1000] {
            client
                .send_msg(&Message::EchoRequest { value })
                .await
                .expect("send echo request failed");

            let response = client.receive_msg().await.expect("receive echo response");
            match response {
                Message::EchoResponse { value: got } => assert_eq!(got, value + 1),
                other => panic!("expected echo response, got {other:?}"),
            }
        }

        client.send_disconnect().await.expect("send disconnect failed");
    });

    server_thread.join().expect("server thread panicked");
}

#[test]
fn handshake_rejects_mismatched_remote_static_key() {
    let server_keys = generate_keypair(rng(0x1234_5678)).unwrap();
    let client_a_keys = generate_keypair(rng(0x9876_5432_1234)).unwrap();
    let client_b_keys = generate_keypair(rng(0x5555_5555_5555)).unwrap();

    // The server's TOFU keystore persists across both connections.
    let mut server_keystore = TestKeyStore::default();
    let server_secrets = secret_keys(&server_keys.private);

    // First connection: client A explicitly pairs, so the server commits and
    // trusts client A's static key.
    {
        let (client_io, server_io) = duplex_pair();
        let client_a_static = client_a_keys.private.clone();
        let client_thread = thread::spawn(move || {
            embassy_futures::block_on(async move {
                let mut client = NoiseLink::initiator_handshake(
                    client_io,
                    secret_keys(&client_a_static),
                    rng(0xDEAD_BEEF),
                )
                .await
                .expect("client A handshake failed");

                client.send_pair_request().await.expect("pair request failed");
                let response = client.receive_msg().await.expect("receive pair response");
                match response {
                    Message::PairResponse { success } => {
                        assert!(success, "pairing should succeed on an unkeyed device")
                    }
                    other => panic!("expected pair response, got {other:?}"),
                }

                client.send_disconnect().await.expect("send disconnect failed");
            });
        });

        embassy_futures::block_on(async {
            let mut link = NoiseLink::responder_handshake_retry(
                ResetReader::new(server_io),
                server_secrets,
                || rng(0x00C0_FFEE),
                &mut server_keystore,
            )
            .await;

            // A bare handshake does not trust the peer; pairing does.
            assert!(!link.is_peer_trusted(), "peer must not be trusted before pairing");
            match link.run_session(&mut server_keystore).await {
                SessionEnd::Disconnected => {}
                other => panic!("expected SessionEnd::Disconnected, got {other:?}"),
            }
            assert!(link.is_peer_trusted(), "peer should be trusted after pairing");
        });

        client_thread.join().expect("client A thread panicked");
    }

    let client_a_public: [u8; 32] = client_a_keys.public.clone().try_into().unwrap();
    assert_eq!(server_keystore.trusted_key(), Some(client_a_public));

    // Second connection: a different peer (client B) presents a different
    // static key. The handshake still completes, but the server must refuse
    // to trust it, leaving the original trust record intact.
    {
        let (client_io, server_io) = duplex_pair();
        let client_b_static = client_b_keys.private.clone();
        let client_thread = thread::spawn(move || {
            embassy_futures::block_on(async move {
                let _ = NoiseLink::initiator_handshake(
                    client_io,
                    secret_keys(&client_b_static),
                    rng(0x2468_ACE0),
                )
                .await;
            });
        });

        embassy_futures::block_on(async {
            let link = NoiseLink::responder_handshake_retry(
                ResetReader::new(server_io),
                server_secrets,
                || rng(0x1357_9BDF),
                &mut server_keystore,
            )
            .await;

            if link.is_peer_trusted() {
                panic!("Peer trusted despite incorrect key");
            }
        });

        client_thread.join().expect("client B thread panicked");
    }

    // The original trusted key must be unchanged.
    assert_eq!(server_keystore.trusted_key(), Some(client_a_public));
}

#[test]
fn run_session_returns_error_on_disconnect() {
    let server_keys = generate_keypair(rng(0x1111_1111)).unwrap();
    let client_keys = generate_keypair(rng(0x2222_2222)).unwrap();

    let (client_io, server_io) = duplex_pair();

    let client_secrets = secret_keys(&client_keys.private);

    let server_static = server_keys.private.clone();
    let server_thread = thread::spawn(move || {
        embassy_futures::block_on(async move {
            let server_secrets = secret_keys(&server_static);
            let mut keystore = TestKeyStore::default();
            let mut link =
                NoiseLink::responder_handshake_retry(ResetReader::new(server_io), server_secrets, || rng(0xAAAA_AAAA), &mut keystore)
                    .await;

            // The client sends one echo request, then drops its end of the
            // transport; the server's next read fails with an Io error.
            match link.run_session(&mut keystore).await {
                SessionEnd::Error(_) => {}
                SessionEnd::Disconnected => panic!("expected an error, got a clean disconnect"),
                SessionEnd::Erased => panic!("expected an error, got SessionEnd::Erased"),
            }
        });
    });

    embassy_futures::block_on(async move {
        let mut client = NoiseLink::initiator_handshake(
            client_io,
            client_secrets,
            rng(0xBBBB_BBBB),
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

        // Drop the client's transport, closing the channel and causing the
        // server's next read to fail.
        drop(client);
    });

    server_thread.join().expect("server thread panicked");
}
