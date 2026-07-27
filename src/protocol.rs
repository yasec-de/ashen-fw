//! Byte-oriented messages exchanged between host and device over a
//! [`NoiseLink`](crate::noise_link::NoiseLink).
//!
//! Each [`NoiseLink::send`](crate::noise_link::NoiseLink::send)/
//! [`receive`](crate::noise_link::NoiseLink::receive) call carries exactly one
//! message. The wire format is deliberately minimal: the first byte is the
//! message type (see [`MsgType`]); any payload follows in a fixed, `#[packed]`
//! layout. Multi-byte integers are big-endian. This mirrors the C definitions:
//!
//! ```c
//! enum ashen_msg_type { ASHEN_MSG_NONE = 0, ASHEN_MSG_LOG = 1, ... };
//! struct ashen_msg_log            { u8 type; u8 data[]; };
//! struct ashen_msg_pair_response  { u8 type; u8 success; };
//! struct ashen_msg_status_response{ u8 type; u8 peer_trusted; u8 is_keyed; };
//! struct ashen_msg_echo           { u8 type; __be64 value; };
//! ```
//!
//! Bare commands (`Erase`, `PairRequest`, `StatusRequest`, `Disconnect`) are a
//! single type byte with no payload.

use alloc::vec::Vec;

use embassy_futures::select::{Either, select};
use embedded_io_async::{Read, Write};

use crate::noise_link::{Error, KeyStore, NoiseLink};

/// Maximum size, in bytes, of a single encoded `defmt` log frame forwarded
/// to the host as a [`MsgType::Log`] message. Longer frames are dropped by
/// [`crate::defmt_link`].
pub const MAX_LOG_FRAME_LEN: usize = 128;

/// Wire message type. The discriminant is the on-wire first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    None = 0,
    Log = 1,
    Erase = 2,
    PairRequest = 3,
    PairResponse = 4,
    StatusRequest = 5,
    StatusResponse = 6,
    Disconnect = 7,
    EchoRequest = 8,
    EchoResponse = 9,
}

impl MsgType {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::Log,
            2 => Self::Erase,
            3 => Self::PairRequest,
            4 => Self::PairResponse,
            5 => Self::StatusRequest,
            6 => Self::StatusResponse,
            7 => Self::Disconnect,
            8 => Self::EchoRequest,
            9 => Self::EchoResponse,
            _ => return None,
        })
    }
}

/// A decoded protocol message. Payload-carrying variants own their data; bare
/// commands carry none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A single defmt-encoded log frame (`ASHEN_MSG_LOG`).
    Log(Vec<u8>),
    Erase,
    PairRequest,
    PairResponse { success: bool },
    StatusRequest,
    StatusResponse { peer_trusted: bool, is_keyed: bool },
    Disconnect,
    EchoRequest { value: u64 },
    EchoResponse { value: u64 },
}

impl Message {
    /// Serializes into the wire format described in the module docs.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Message::Log(data) => {
                out.push(MsgType::Log as u8);
                out.extend_from_slice(data);
            }
            Message::Erase => out.push(MsgType::Erase as u8),
            Message::PairRequest => out.push(MsgType::PairRequest as u8),
            Message::PairResponse { success } => {
                out.push(MsgType::PairResponse as u8);
                out.push(*success as u8);
            }
            Message::StatusRequest => out.push(MsgType::StatusRequest as u8),
            Message::StatusResponse {
                peer_trusted,
                is_keyed,
            } => {
                out.push(MsgType::StatusResponse as u8);
                out.push(*peer_trusted as u8);
                out.push(*is_keyed as u8);
            }
            Message::Disconnect => out.push(MsgType::Disconnect as u8),
            Message::EchoRequest { value } => {
                out.push(MsgType::EchoRequest as u8);
                out.extend_from_slice(&value.to_be_bytes());
            }
            Message::EchoResponse { value } => {
                out.push(MsgType::EchoResponse as u8);
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
        out
    }

    /// Parses a wire message. Returns [`Error::Protocol`] on an unknown type,
    /// an unexpected `None`, or a payload that is too short for its type.
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (&type_byte, payload) = bytes.split_first().ok_or(Error::Protocol)?;
        let ty = MsgType::from_u8(type_byte).ok_or(Error::Protocol)?;
        Ok(match ty {
            MsgType::None => return Err(Error::Protocol),
            MsgType::Log => Message::Log(payload.into()),
            MsgType::Erase => Message::Erase,
            MsgType::PairRequest => Message::PairRequest,
            MsgType::PairResponse => Message::PairResponse {
                success: *payload.first().ok_or(Error::Protocol)? != 0,
            },
            MsgType::StatusRequest => Message::StatusRequest,
            MsgType::StatusResponse => Message::StatusResponse {
                peer_trusted: *payload.first().ok_or(Error::Protocol)? != 0,
                is_keyed: *payload.get(1).ok_or(Error::Protocol)? != 0,
            },
            MsgType::Disconnect => Message::Disconnect,
            MsgType::EchoRequest => Message::EchoRequest {
                value: read_be64(payload)?,
            },
            MsgType::EchoResponse => Message::EchoResponse {
                value: read_be64(payload)?,
            },
        })
    }
}

/// Reads a big-endian u64 from the start of `payload`, erroring if short.
fn read_be64(payload: &[u8]) -> Result<u64, Error> {
    let bytes: [u8; 8] = payload.get(..8).ok_or(Error::Protocol)?.try_into().unwrap();
    Ok(u64::from_be_bytes(bytes))
}

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
    pub async fn send_msg(&mut self, msg: &Message) -> Result<(), Error> {
        self.send(&msg.encode()).await
    }

    pub async fn receive_msg(&mut self) -> Result<Message, Error> {
        let payload = self.receive().await?;
        Message::decode(&payload)
    }

    pub async fn send_log_message(&mut self, data: &[u8]) -> Result<(), Error> {
        self.send_msg(&Message::Log(data.into())).await
    }

    pub(crate) async fn flush_one_log(&mut self) -> Result<bool, Error> {
        let mut buf = [0u8; MAX_LOG_FRAME_LEN];
        match pop_log_frame(&mut buf) {
            Some(len) => {
                self.send_log_message(&buf[..len]).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub(crate) async fn drain_log_queue(&mut self) -> Result<(), Error> {
        while self.flush_one_log().await? {}
        Ok(())
    }

    async fn handle_message<K: KeyStore>(
        &mut self,
        keystore: &mut K,
        msg: Message,
    ) -> Result<Option<SessionEnd>, Error> {
        match msg {
            Message::EchoRequest { value } => {
                let value = value.checked_add(1).expect("EchoRequest overflow");
                self.send_msg(&Message::EchoResponse { value }).await?;
                Ok(None)
            }
            Message::Disconnect => {
                let _ = self.send_msg(&Message::Disconnect).await;
                Ok(Some(SessionEnd::Disconnected))
            }
            Message::Erase => {
                // The caller erases the keystore and rotates the identity key
                // upon seeing `SessionEnd::Erased` (see `crate::main`).
                Ok(Some(SessionEnd::Erased))
            }
            Message::PairRequest => {
                if keystore.trusted_key().is_some() {
                    #[cfg(target_os = "none")]
                    defmt::error!("Cannot pair while keyed, must be erased first");
                    self.send_msg(&Message::PairResponse { success: false })
                        .await?;
                } else {
                    self.trust(keystore).expect("Bug!");
                    self.send_msg(&Message::PairResponse { success: true })
                        .await?;
                }
                Ok(None)
            }
            Message::StatusRequest => {
                self.send_msg(&Message::StatusResponse {
                    peer_trusted: self.is_peer_trusted(),
                    is_keyed: keystore.trusted_key().is_some(),
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
            // Real protocol messages always win: race an inbound message
            // against "a log frame is available". Logs are only ever sent in
            // the gaps when nothing is being received, and one frame at a time,
            // so a message queued mid-log-burst is serviced right after the
            // current frame rather than behind the whole backlog.
            match select(self.receive_msg(), wait_for_log_frame()).await {
                Either::First(result) => {
                    let result = match result {
                        Ok(msg) => self.handle_message(keystore, msg).await,
                        Err(e) => Err(e),
                    };
                    match result {
                        Ok(Some(end)) => return end,
                        Ok(None) => {}
                        Err(e) => return SessionEnd::Error(e),
                    }
                }

                // No message pending and a log frame is queued: send exactly
                // one, then loop back so a freshly-arrived message preempts the
                // rest of the backlog.
                Either::Second(()) => match self.flush_one_log().await {
                    Ok(_) => {}
                    Err(e) => return SessionEnd::Error(e),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ponytail: one round-trip check that the byte layout is stable and every
    // variant decodes back to itself.
    #[test]
    fn encode_decode_round_trips() {
        let cases = [
            Message::Log(b"frame".to_vec()),
            Message::Erase,
            Message::PairRequest,
            Message::PairResponse { success: true },
            Message::StatusRequest,
            Message::StatusResponse { peer_trusted: true, is_keyed: false },
            Message::Disconnect,
            Message::EchoRequest { value: 0x0102_0304_0506_0708 },
            Message::EchoResponse { value: u64::MAX },
        ];
        for msg in cases {
            assert_eq!(Message::decode(&msg.encode()).unwrap(), msg);
        }

        // Big-endian on the wire: type byte then 8 MSB-first value bytes.
        assert_eq!(
            Message::EchoRequest { value: 1 }.encode(),
            [8, 0, 0, 0, 0, 0, 0, 0, 1]
        );

        // Bad inputs are rejected, not panicked on.
        assert!(Message::decode(&[]).is_err()); // empty
        assert!(Message::decode(&[0]).is_err()); // NONE
        assert!(Message::decode(&[99]).is_err()); // unknown type
        assert!(Message::decode(&[8, 0, 0]).is_err()); // echo, short value
    }
}
