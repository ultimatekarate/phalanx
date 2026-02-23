use crate::primitives::identity::Did;
use crate::primitives::shards::{VolleyId, WitnessEnvelope};
use crate::security::grant::SealedLocator;
use serde::{Deserialize, Serialize};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{self};
use libp2p::StreamProtocol;

use std::io;

use crate::security::locator::PhalanxLocator;

// --- DATA TRANSFER OBJECTS ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolleyRequest {
    pub target_did: Did,
    pub volley_id: VolleyId,
    pub locator: PhalanxLocator,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VolleyResponse {
    Success(Vec<WitnessEnvelope>),
    Throttled,
    NotFound,
    Unauthorized,
}

// --- CODEC IMPLEMENTATION ---

#[derive(Clone, Default)]
pub struct PhalanxRetrievalProtocol;

#[async_trait]
impl request_response::Codec for PhalanxRetrievalProtocol {
    type Protocol = StreamProtocol;
    type Request = VolleyRequest;
    type Response = VolleyResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let payload = read_length_prefixed(io).await?;
        postcard::from_bytes(&payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let payload = read_length_prefixed(io).await?;
        postcard::from_bytes(&payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let payload = postcard::to_allocvec(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_length_prefixed(io, &payload).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let payload = postcard::to_allocvec(&res)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_length_prefixed(io, &payload).await
    }
}

// --- I/O UTILITIES ---

/// Reads a u32 length prefix, then reads the exact payload bytes.
async fn read_length_prefixed<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;

    // Hard limit: 10MB per payload to prevent memory exhaustion attacks
    if len > 10_000_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Payload exceeds protocol limit",
        ));
    }

    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Writes a u32 length prefix, followed by the payload bytes.
async fn write_length_prefixed<T>(io: &mut T, payload: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    let len = payload.len() as u32;
    io.write_all(&len.to_le_bytes()).await?;
    io.write_all(payload).await?;
    io.flush().await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievalRequest {
    pub target_did: crate::primitives::identity::Did, // The owner of the forensic data
    pub volley_id: VolleyId,                          // Specific collection identifier
    pub locator: SealedLocator,                       // Forensic grant
    pub signature: Vec<u8>,                           // Proof of requester identity
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetrievalResponse {
    Success(Vec<WitnessEnvelope>),
    Busy,         // Resource-based shedding
    NotFound,     // Data missing from local Guardian
    Unauthorized, // Cryptographic proof failed
}
