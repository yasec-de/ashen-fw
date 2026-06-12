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

use crate::noise_link::{Error, NoiseLink};

#[allow(nonstandard_style, unused, irrefutable_let_patterns, clippy::all)]
mod device_pb {
    include!(concat!(env!("OUT_DIR"), "/device.rs"));
}

pub use device_pb::ashen_::{Disconnect, EchoRequest, EchoResponse, Envelope, Envelope_::Msg, Erase, LogMessage};

/// Maximum size, in bytes, of a single encoded `defmt` log frame forwarded
/// to the host as a [`LogMessage`]. Longer frames are dropped by
/// [`crate::defmt_link`].
pub const MAX_LOG_FRAME_LEN: usize = 128;

/// Pops the oldest queued `defmt` log frame (if any) into `out`, returning
/// its length.
#[cfg(target_os = "none")]
fn pop_log_frame(out: &mut [u8]) -> Option<usize> {
    crate::defmt_link::pop_log_frame(out)
}

#[cfg(not(target_os = "none"))]
fn pop_log_frame(_out: &mut [u8]) -> Option<usize> {
    None
}

/// Resolves once a new `defmt` log frame has been queued since the last
/// call. On the host (where no log frames are ever queued), this never
/// resolves.
#[cfg(target_os = "none")]
async fn wait_for_log_frame() {
    crate::defmt_link::wait_for_log_frame().await
}

#[cfg(not(target_os = "none"))]
async fn wait_for_log_frame() {
    core::future::pending().await
}

/// Why [`NoiseLink::run_session`] returned.
#[derive(Debug)]
pub enum SessionEnd {
    /// The peer sent a [`Disconnect`] message.
    Disconnected,
    /// The peer sent an [`Erase`] message. The TOFU keystore should be
    /// erased (see [`crate::noise_link::KeyStore::erase`]) and the device's
    /// static identity key regenerated before the link is restarted with a
    /// fresh handshake.
    Erased,
    /// A transport or protocol error occurred. The link should be
    /// restarted (see
    /// [`NoiseLink::restart_responder`](crate::noise_link::NoiseLink::restart_responder))
    /// with a fresh handshake.
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

    /// Sends a [`Disconnect`] message, telling the peer to end the session.
    pub async fn send_disconnect(&mut self) -> Result<(), Error> {
        self.send_envelope(&Envelope {
            r#msg: Some(Msg::Disconnect(Disconnect::default())),
        })
        .await
    }

    /// Sends an [`Erase`] message, telling the peer to end the session,
    /// erase its TOFU keystore, and regenerate its static identity key.
    pub async fn send_erase(&mut self) -> Result<(), Error> {
        self.send_envelope(&Envelope {
            r#msg: Some(Msg::Erase(Erase::default())),
        })
        .await
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

    /// Handles a single received `envelope`. Replies to [`EchoRequest`]s
    /// with an [`EchoResponse`] containing `value + 1`. Returns the
    /// [`SessionEnd`] the caller should stop the session with, if
    /// `envelope` was a [`Disconnect`] or [`Erase`] message; other envelope
    /// types are ignored and return `None`.
    ///
    /// # Panics
    ///
    /// Panics if `value + 1` overflows a `u64`. The host is expected not to
    /// send `u64::MAX`; if it does, this is treated as a fatal protocol
    /// error.
    async fn handle_envelope(&mut self, envelope: Envelope) -> Result<Option<SessionEnd>, Error> {
        match envelope.r#msg {
            Some(Msg::EchoRequest(request)) => {
                let value = request
                    .r#value
                    .checked_add(1)
                    .expect("EchoRequest value overflowed on +1");
                self.send_envelope(&Envelope {
                    r#msg: Some(Msg::EchoResponse(EchoResponse { r#value: value })),
                })
                .await?;
                Ok(None)
            }
            Some(Msg::Disconnect(_)) => Ok(Some(SessionEnd::Disconnected)),
            Some(Msg::Erase(_)) => Ok(Some(SessionEnd::Erased)),
            _ => Ok(None),
        }
    }

    /// Receives and handles envelopes (see
    /// [`NoiseLink::handle_envelope`](Self::handle_envelope)) until the
    /// peer sends a [`Disconnect`] message or an error occurs.
    ///
    /// Draining the `defmt` log queue (forwarded to the host as
    /// [`LogMessage`] envelopes, see [`NoiseLink::flush_log_queue`]) and
    /// receiving protocol messages from the host both run concurrently:
    /// while waiting to receive the next envelope, a newly queued log frame
    /// wakes this loop so it can be flushed without waiting for the next
    /// message from the host.
    pub async fn run_session(&mut self) -> SessionEnd {
        loop {
            if let Err(e) = self.flush_log_queue().await {
                return SessionEnd::Error(e);
            }

            match select(self.receive_envelope(), wait_for_log_frame()).await {
                Either::First(result) => {
                    let result = match result {
                        Ok(envelope) => self.handle_envelope(envelope).await,
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
