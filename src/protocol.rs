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

use embassy_futures::select::{Either4, select4};
use embedded_io_async::{Read, Write};

use crate::noise_link::{Error, KeyStore, NoiseLink};

/// Maximum number of log bytes carried by a single [`MsgType::Log`] message.
/// Log output is a byte stream (see [`crate::log`]), so it is chunked into
/// messages of at most this size; chunk boundaries carry no meaning.
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
    TpmCommand = 10,
    TpmResponse = 11,
}

/// Largest TPM packet that can be reassembled from a fragment sequence.
/// Matches the TPM core's own command buffer, so a peer cannot make the
/// device buffer more than the TPM would ever accept.
pub fn max_tpm_packet_len() -> usize {
    crate::tpm::max_command_size()
}

/// Payload bytes carried by one TPM fragment: a Noise message minus its tag,
/// minus the two-byte fragment header.
pub const TPM_CHUNK_LEN: usize = crate::framing::MAX_PAYLOAD_LEN - 16 - 2;

/// Set in a fragment's flag byte while more fragments follow.
const FLAG_MORE: u8 = 0x01;

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
            10 => Self::TpmCommand,
            11 => Self::TpmResponse,
            _ => return None,
        })
    }
}

/// A decoded protocol message. Payload-carrying variants own their data; bare
/// commands carry none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A chunk of log output (`ASHEN_MSG_LOG`).
    Log(Vec<u8>),
    Erase,
    PairRequest,
    PairResponse { success: bool },
    StatusRequest,
    StatusResponse { peer_trusted: bool, is_keyed: bool },
    Disconnect,
    EchoRequest { value: u64 },
    EchoResponse { value: u64 },
    /// One fragment of a TPM 2.0 command packet. `more` is set on every
    /// fragment but the last.
    TpmCommand { more: bool, chunk: Vec<u8> },
    /// One fragment of a TPM 2.0 response packet.
    TpmResponse { more: bool, chunk: Vec<u8> },
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
            Message::TpmCommand { more, chunk } => {
                out.push(MsgType::TpmCommand as u8);
                out.push(if *more { FLAG_MORE } else { 0 });
                out.extend_from_slice(chunk);
            }
            Message::TpmResponse { more, chunk } => {
                out.push(MsgType::TpmResponse as u8);
                out.push(if *more { FLAG_MORE } else { 0 });
                out.extend_from_slice(chunk);
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
            MsgType::TpmCommand => {
                let (&flags, chunk) = payload.split_first().ok_or(Error::Protocol)?;
                Message::TpmCommand {
                    more: flags & FLAG_MORE != 0,
                    chunk: chunk.into(),
                }
            }
            MsgType::TpmResponse => {
                let (&flags, chunk) = payload.split_first().ok_or(Error::Protocol)?;
                Message::TpmResponse {
                    more: flags & FLAG_MORE != 0,
                    chunk: chunk.into(),
                }
            }
        })
    }
}

/// Reads a big-endian u64 from the start of `payload`, erroring if short.
fn read_be64(payload: &[u8]) -> Result<u64, Error> {
    let bytes: [u8; 8] = payload.get(..8).ok_or(Error::Protocol)?.try_into().unwrap();
    Ok(u64::from_be_bytes(bytes))
}

/// Per-session TPM transport state: the fragments of a command still being
/// reassembled, and whether one has been handed to the TPM and not yet
/// answered.
#[derive(Default)]
struct TpmState {
    pending: Vec<u8>,
    refused: bool,
    in_flight: bool,
    outgoing: Option<(Vec<u8>, usize)>,
}

fn next_fragment(packet: &[u8], pos: usize) -> (&[u8], bool) {
    let end = packet.len().min(pos + TPM_CHUNK_LEN);
    (&packet[pos..end], end < packet.len())
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

    /// Forwards up to [`MAX_LOG_FRAME_LEN`] bytes of buffered log output to
    /// the host, if any is pending. Does not wait for more: the caller has
    /// already established readiness via [`crate::log::wait_readable`], and
    /// reading without waiting keeps this safe to use as a cancellable
    /// `select` arm.
    pub(crate) async fn flush_one_log(&mut self) -> Result<(), Error> {
        let mut buf = [0u8; MAX_LOG_FRAME_LEN];
        let len = crate::log::try_read(&mut buf);
        if len > 0 {
            self.send_log_message(&buf[..len]).await?;
        }
        Ok(())
    }

    /// Forwards all log bytes buffered right now, without waiting for more.
    /// Used by the panic handler, where the executor may no longer be able to
    /// make progress on a pending read.
    pub(crate) async fn drain_log_queue(&mut self) -> Result<(), Error> {
        let mut buf = [0u8; MAX_LOG_FRAME_LEN];
        loop {
            let len = crate::log::try_read(&mut buf);
            if len == 0 {
                return Ok(());
            }
            self.send_log_message(&buf[..len]).await?;
        }
    }

    /// Sends a TPM packet as a fragment sequence. A zero-length packet still
    /// yields one fragment, so the peer always sees a reply.
    async fn send_tpm_fragments(&mut self, packet: &[u8], command: bool) -> Result<(), Error> {
        let mut pos = 0;
        loop {
            let (chunk, more) = next_fragment(packet, pos);
            pos += chunk.len();
            let chunk: Vec<u8> = chunk.into();
            let msg = if command {
                Message::TpmCommand { more, chunk }
            } else {
                Message::TpmResponse { more, chunk }
            };
            self.send_msg(&msg).await?;
            if !more {
                return Ok(());
            }
        }
    }

    async fn send_next_response_fragment(&mut self, tpm: &mut TpmState) -> Result<(), Error> {
        let Some((packet, pos)) = tpm.outgoing.as_mut() else {
            return Ok(());
        };
        let (chunk, more) = next_fragment(packet, *pos);
        *pos += chunk.len();
        let msg = Message::TpmResponse {
            more,
            chunk: chunk.into(),
        };
        if !more {
            tpm.outgoing = None;
        }
        self.send_msg(&msg).await
    }

    /// Host side of the TPM transport: sends a raw TPM 2.0 command packet.
    pub async fn send_tpm_command(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.send_tpm_fragments(packet, true).await
    }

    /// Device side of the TPM transport: sends a raw TPM 2.0 response packet.
    pub async fn send_tpm_response(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.send_tpm_fragments(packet, false).await
    }

    /// Reassembles one TPM packet, stepping over interleaved log output.
    /// Errors on any other message type, which would mean the peer abandoned
    /// the sequence.
    pub async fn receive_tpm_packet(&mut self) -> Result<Vec<u8>, Error> {
        let mut packet: Vec<u8> = Vec::new();
        loop {
            let (more, chunk) = match self.receive_msg().await? {
                Message::Log(_) => continue,
                Message::TpmResponse { more, chunk } => (more, chunk),
                Message::TpmCommand { more, chunk } => (more, chunk),
                _ => return Err(Error::Protocol),
            };
            packet.extend_from_slice(&chunk);
            if !more {
                return Ok(packet);
            }
        }
    }

    async fn handle_tpm_fragment(
        &mut self,
        tpm: &mut TpmState,
        more: bool,
        chunk: Vec<u8>,
    ) -> Result<(), Error> {
        if !tpm.refused {
            if !self.is_peer_trusted() {
                crate::error!("TPM access refused: peer is not paired");
                tpm.refused = true;
            } else if tpm.in_flight || tpm.outgoing.is_some() {
                crate::error!("TPM command refused: one is already running");
                tpm.refused = true;
            } else if tpm.pending.len() + chunk.len() > max_tpm_packet_len() {
                crate::error!("TPM command exceeds the maximum packet length");
                tpm.refused = true;
            }
        }

        if tpm.refused {
            tpm.pending.clear();
            if more {
                return Ok(());
            }
            tpm.refused = false;
            return self.send_tpm_response(&[]).await;
        }
        tpm.pending.extend_from_slice(&chunk);

        if more {
            return Ok(());
        }

        // Hand it off and go back to servicing the link. The answer arrives as
        // the second arm of `run_session`'s select.
        let packet = core::mem::take(&mut tpm.pending);
        crate::tpm::submit(&packet).await;
        tpm.in_flight = true;
        Ok(())
    }

    async fn handle_message<K: KeyStore>(
        &mut self,
        keystore: &mut K,
        tpm: &mut TpmState,
        msg: Message,
    ) -> Result<Option<SessionEnd>, Error> {
        match msg {
            Message::TpmCommand { more, chunk } => {
                self.handle_tpm_fragment(tpm, more, chunk).await?;
                Ok(None)
            }
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
                    crate::error!("Cannot pair while keyed, must be erased first");
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
                crate::warn!("Unknown command received");
                Ok(None)
            }
        }
    }

    pub async fn run_session<K: KeyStore>(&mut self, keystore: &mut K) -> SessionEnd {
        let mut tpm = TpmState::default();

        let end = loop {
            // Real protocol messages always win: race an inbound message
            // against "log output is available". Backlogged logs are sent one
            // chunk at a time in the gaps when nothing is being received, so a
            // message queued mid-log-burst is serviced right after the current
            // chunk rather than behind the whole backlog.
            //
            // The second arm is the TPM's answer to a command already handed
            // off. It only exists while one is in flight; otherwise it is a
            // future that never completes, so the other arms race as before.
            // This is what keeps the heartbeat and the log pipe serviced
            // during a key generation that takes hundreds of milliseconds.
            let tpm_answer = async {
                if tpm.in_flight {
                    crate::tpm::take_response().await
                } else {
                    core::future::pending().await
                }
            };
            let tpm_output = async {
                if tpm.outgoing.is_none() {
                    core::future::pending::<()>().await
                }
            };

            match select4(
                self.receive_msg(),
                tpm_answer,
                tpm_output,
                crate::log::wait_readable(),
            )
            .await
            {
                Either4::First(result) => {
                    let result = match result {
                        Ok(msg) => self.handle_message(keystore, &mut tpm, msg).await,
                        Err(e) => Err(e),
                    };
                    match result {
                        Ok(Some(end)) => break end,
                        Ok(None) => {}
                        Err(e) => break SessionEnd::Error(e),
                    }
                    // Flush whatever the handler just logged before looping.
                    // `select` polls the receive arm first, so a host that
                    // pipelines its requests would otherwise win the race on
                    // every iteration and starve the pipe indefinitely.
                    if let Err(e) = self.flush_one_log().await {
                        break SessionEnd::Error(e);
                    }
                }

                Either4::Second(answer) => {
                    tpm.in_flight = false;
                    let packet = match answer {
                        Ok(response) => response,
                        Err(e) => {
                            crate::error!("TPM rejected a command: {:?}", e);
                            Vec::new()
                        }
                    };
                    tpm.outgoing = Some((packet, 0));
                }

                Either4::Third(()) => {
                    if let Err(e) = self.send_next_response_fragment(&mut tpm).await {
                        break SessionEnd::Error(e);
                    }
                }

                // No message pending and log output is buffered: send exactly
                // one chunk, then loop back so a freshly-arrived message
                // preempts the rest of the backlog.
                Either4::Fourth(()) => {
                    if let Err(e) = self.flush_one_log().await {
                        break SessionEnd::Error(e);
                    }
                }
            }
        };

        // The TPM owes exactly one answer per command and cannot be cancelled
        // mid-call, so wait for it rather than leaving it to be delivered into
        // the next peer's session.
        if tpm.in_flight {
            let _ = crate::tpm::take_response().await;
        }
        crate::tpm::discard_response();

        end
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
