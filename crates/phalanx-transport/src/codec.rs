use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use libp2p::swarm::StreamProtocol;
use phalanx_proto::archive::{ArchiveReceipt, ArchiveRequest};
use phalanx_proto::wire::WireBound;
use phalanx_proto::{MAX_PAYLOAD_SIZE, RecordingRequest, RecordingResponse};
use std::io;

/// Reads a 4-byte little-endian length prefix then that many payload bytes,
/// rejecting anything over `MAX_PAYLOAD_SIZE`. Shared by both protocol codecs.
async fn read_length_prefixed<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Payload exceeds protocol limit",
        ));
    }

    let mut payload = vec![0u8; payload_len];
    io.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_length_prefixed<T>(io: &mut T, payload: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    #[allow(clippy::cast_possible_truncation)]
    // Payload size bounded by MAX_PAYLOAD_SIZE (< u32::MAX)
    let payload_len = payload.len() as u32;
    io.write_all(&payload_len.to_le_bytes()).await?;
    io.write_all(payload).await?;
    io.flush().await?;
    Ok(())
}

/// Codec for the directed archive PUSH protocol (`/phalanx/archive/1.0.0`).
/// The request carries the shards; the response is a custody receipt.
#[derive(Clone, Default)]
pub struct PhalanxArchiveProtocol;

#[async_trait]
impl request_response::Codec for PhalanxArchiveProtocol {
    type Protocol = StreamProtocol;
    type Request = ArchiveRequest;
    type Response = ArchiveReceipt;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let payload = read_length_prefixed(io).await?;
        let mut request: ArchiveRequest = postcard::from_bytes(&payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        request.enforce_wire_bounds();
        Ok(request)
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
        let mut response: ArchiveReceipt = postcard::from_bytes(&payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        response.enforce_wire_bounds();
        Ok(response)
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
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
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
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        write_length_prefixed(io, &payload).await
    }
}

#[derive(Clone, Default)]
pub struct PhalanxRetrievalProtocol;

#[async_trait]
impl request_response::Codec for PhalanxRetrievalProtocol {
    type Protocol = StreamProtocol;
    type Request = RecordingRequest;
    type Response = RecordingResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let payload = self.read_length_prefixed(io).await?;
        // H3 FIX: Enforce wire bounds on inbound requests (matches read_response pattern).
        let mut request: RecordingRequest = postcard::from_bytes(&payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        request.enforce_wire_bounds();
        Ok(request)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let payload = self.read_length_prefixed(io).await?;
        let mut response: RecordingResponse = postcard::from_bytes(&payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        response.enforce_wire_bounds();
        Ok(response)
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
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        self.write_length_prefixed(io, &payload).await
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
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        self.write_length_prefixed(io, &payload).await
    }
}

impl PhalanxRetrievalProtocol {
    async fn read_length_prefixed<T>(&self, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let payload_len = u32::from_le_bytes(len_buf) as usize;

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Payload exceeds protocol limit",
            ));
        }

        let mut payload = vec![0u8; payload_len];
        io.read_exact(&mut payload).await?;
        Ok(payload)
    }

    async fn write_length_prefixed<T>(&self, io: &mut T, payload: &[u8]) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        #[allow(clippy::cast_possible_truncation)]
        // Payload size bounded by MAX_PAYLOAD_SIZE (< u32::MAX)
        let payload_len = payload.len() as u32;
        io.write_all(&payload_len.to_le_bytes()).await?;
        io.write_all(payload).await?;
        io.flush().await?;
        Ok(())
    }
}
