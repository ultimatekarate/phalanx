// crates/phalanx-transport/src/adapters/quic/wire.rs
//
// Wire protocol types and length-prefixed framing for the QUIC transport.

use phalanx_proto::retrieval::{RecordingRequest, RecordingResponse};
use phalanx_proto::wire::WireBound;
use phalanx_proto::MAX_PAYLOAD_SIZE;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── Wire Protocol ────────────────────────────────────────────────────────

/// Messages exchanged over QUIC bidirectional streams.
/// Each message is a length-prefixed postcard frame (4-byte LE length + payload).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum QuicWireMessage {
    /// Client identifies itself to the server on the first stream.
    /// Includes a timestamp to prevent replay of captured Identify frames.
    Identify {
        network_id: String,
        timestamp_ms: u64,
    },
    /// Publish data on a topic (broadcast to all connected peers).
    Publish { topic: String, data: Vec<u8> },
    /// Recording retrieval request.
    Request {
        channel_id: String,
        request: RecordingRequest,
    },
    /// Recording retrieval response.
    Response {
        channel_id: String,
        response: RecordingResponse,
    },
}

// ── Error Type ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Codec error: {0}")]
    Codec(String),
}

// ── Framing ──────────────────────────────────────────────────────────────

/// Write a length-prefixed postcard frame to a stream.
///
/// Format: [4-byte LE length][postcard payload]
///
/// Mirrors the framing pattern in `codec.rs` (`PhalanxRetrievalProtocol`).
#[allow(clippy::arithmetic_side_effects)]
pub(crate) async fn write_frame(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    msg: &QuicWireMessage,
) -> Result<(), QuicError> {
    let payload = postcard::to_allocvec(msg).map_err(|e| QuicError::Codec(e.to_string()))?;

    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(QuicError::Codec(format!(
            "Payload {} bytes exceeds MAX_PAYLOAD_SIZE {}",
            payload.len(),
            MAX_PAYLOAD_SIZE
        )));
    }

    #[allow(clippy::cast_possible_truncation)]
    // Payload size checked against MAX_PAYLOAD_SIZE (< u32::MAX) above
    let len_bytes = (payload.len() as u32).to_le_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

/// Read a length-prefixed postcard frame from a stream.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) async fn read_frame(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<QuicWireMessage, QuicError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(QuicError::Codec(format!(
            "Incoming payload {} bytes exceeds MAX_PAYLOAD_SIZE {}",
            payload_len, MAX_PAYLOAD_SIZE
        )));
    }

    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    let mut msg: QuicWireMessage =
        postcard::from_bytes(&payload).map_err(|e| QuicError::Codec(e.to_string()))?;

    // H3 FIX: Enforce wire bounds on inbound request/response payloads.
    match &mut msg {
        QuicWireMessage::Request { request, .. } => request.enforce_wire_bounds(),
        QuicWireMessage::Response { response, .. } => response.enforce_wire_bounds(),
        _ => {}
    }

    Ok(msg)
}
