//! Protobuf-encoded messages exchanged between host and device over a
//! [`NoiseLink`](crate::noise_link::NoiseLink).
//!
//! Each [`NoiseLink::send`](crate::noise_link::NoiseLink::send)/
//! [`receive`](crate::noise_link::NoiseLink::receive) call carries exactly
//! one protobuf-encoded [`Envelope`]. Status updates and error reports are
//! sent as `defmt`-encoded [`LogMessage`] frames (see
//! [`crate::defmt_link`]); host-to-device commands and their responses will
//! be added as additional `Envelope` fields.

use alloc::vec::Vec;

use embassy_futures::select::{Either, select};
use embedded_io_async::{Read, Write};
use micropb::{MessageDecode, MessageEncode, PbEncoder};

use crate::noise_link::{Error, KeyStore, NoiseLink};

#[allow(nonstandard_style, unused, irrefutable_let_patterns, clippy::all)]
mod device_pb {
    include!(concat!(env!("OUT_DIR"), "/device.rs"));
}

pub use device_pb::ashen_;
pub use device_pb::ashen_::{
    Disconnect, EchoRequest, EchoResponse, Envelope, Envelope_::Msg, Erase, LogMessage,
    PairRequest, PairResponse, StatusResponse,
};

/// Maximum size, in bytes, of a single encoded `defmt` log frame forwarded
/// to the host as a [`LogMessage`]. Longer frames are dropped by
/// [`crate::defmt_link`].
pub const MAX_LOG_FRAME_LEN: usize = 128;

#[cfg(target_os = "none")]
fn pop_log_frame(out: &mut [u8]) -> Option<usize> {
    crate::defmt_link::pop_log_frame(out)
}

#[cfg(not(target_os = "none"))]
fn pop_log_frame(_out: &mut [u8]) -> Option<usize> {
    None
}

#[cfg(target_os = "none")]
async fn wait_for_log_frame() {
    crate::defmt_link::wait_for_log_frame().await
}

#[cfg(not(target_os = "none"))]
async fn wait_for_log_frame() {
    core::future::pending().await
}

#[derive(Debug)]
pub enum SessionEnd {
    Disconnected,
    Erased,
    Error(Error),
}

impl<T: Read + Write> NoiseLink<T> {
    /// Encodes `envelope` as protobuf and sends it as a single transport
    /// message.
    pub async fn send_envelope(&mut self, envelope: &Envelope) -> Result<(), Error> {
        let mut encoder = PbEncoder::new(Vec::new());
        envelope.encode(&mut encoder).map_err(|_| Error::Protocol)?;
        self.send(encoder.as_writer()).await
    }

    /// Receives a single transport message and decodes it as protobuf.
    pub async fn receive_envelope(&mut self) -> Result<Envelope, Error> {
        let payload = self.receive().await?;
        let mut envelope = Envelope::default();
        envelope
            .decode_from_bytes(&payload)
            .map_err(|_| Error::Protocol)?;
        Ok(envelope)
    }

    /// Sends `data` (a single encoded `defmt` log frame) as a
    /// [`LogMessage`].
    pub async fn send_log_message(&mut self, data: &[u8]) -> Result<(), Error> {
        self.send_envelope(&Envelope {
            r#msg: Some(Msg::Log(LogMessage { r#data: data.into() })),
        })
        .await
    }

    /// Sends any `defmt` log frames queued by [`crate::defmt_link`] as
    /// [`LogMessage`] envelopes.
    pub(crate) async fn flush_log_queue(&mut self) -> Result<(), Error> {
        let mut buf = [0u8; MAX_LOG_FRAME_LEN];
        while let Some(len) = pop_log_frame(&mut buf) {
            self.send_log_message(&buf[..len]).await?;
        }
        Ok(())
    }

    async fn handle_envelope<K: KeyStore>(
        &mut self,
        keystore: &mut K,
        envelope: Envelope,
    ) -> Result<Option<SessionEnd>, Error> {
        match envelope.r#msg {
            Some(Msg::EchoRequest(request)) => {
                let value = request
                    .r#value
                    .checked_add(1)
                    .expect("EchoRequest overflow");
                self.send_envelope(&Envelope {
                    r#msg: Some(Msg::EchoResponse(EchoResponse { r#value: value })),
                })
                .await?;
                Ok(None)
            }
            Some(Msg::Disconnect(_)) => {
                // Courtesy acknowledgement (see the `Disconnect` proto doc).
                // The peer that asked to disconnect may already have dropped
                // the link, so a failed send here is not a session error: we
                // are ending the session regardless.
                let _ = self
                    .send_envelope(&Envelope {
                        r#msg: Some(Msg::Disconnect(Disconnect {})),
                    })
                    .await;
                Ok(Some(SessionEnd::Disconnected))
            }
            Some(Msg::Erase(_)) => {
                // The caller erases the keystore and rotates the identity key
                // upon seeing `SessionEnd::Erased` (see `crate::main`).
                Ok(Some(SessionEnd::Erased))
            }
            Some(Msg::PairRequest(_)) => {
                if keystore.trusted_key().is_some() {
                    #[cfg(target_os = "none")]
                    defmt::error!("Cannot pair while keyed, must be erased first");
                    self.send_envelope(&Envelope {
                        r#msg: Some(Msg::PairResponse(PairResponse { r#success: false })),
                    })
                    .await?;
                } else {
                    self.trust(keystore).expect("Bug!");
                    self.send_envelope(&Envelope {
                        r#msg: Some(Msg::PairResponse(PairResponse { r#success: true })),
                    })
                    .await?;
                }
                Ok(None)
            }
            Some(Msg::StatusRequest(_)) => {
                self.send_envelope(&Envelope {
                    r#msg: Some(Msg::StatusResponse(StatusResponse {
                        r#peer_trusted: self.is_peer_trusted(),
                        r#is_keyed: keystore.trusted_key().is_some(),
                    })),
                })
                .await?;
                Ok(None)
            }
            _ => {
                #[cfg(target_os = "none")]
                defmt::warn!("Unknown command received");
                Ok(None)
            }
        }
    }

    pub async fn run_session<K: KeyStore>(&mut self, keystore: &mut K) -> SessionEnd {
        loop {
            if let Err(e) = self.flush_log_queue().await {
                return SessionEnd::Error(e);
            }

            match select(self.receive_envelope(), wait_for_log_frame()).await {
                Either::First(result) => {
                    let result = match result {
                        Ok(envelope) => self.handle_envelope(keystore, envelope).await,
                        Err(e) => Err(e),
                    };
                    match result {
                        Ok(Some(end)) => return end,
                        Ok(None) => {}
                        Err(e) => {
                            return SessionEnd::Error(e);
                        }
                    }
                }

                // A new log frame was queued; loop back around to flush it.
                Either::Second(()) => {}
            }
        }
    }
}
