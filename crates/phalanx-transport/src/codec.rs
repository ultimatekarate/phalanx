use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use libp2p::swarm::StreamProtocol;
use phalanx_proto::{VolleyRequest, VolleyResponse, MAX_PAYLOAD_SIZE};
use std::io;

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
        let payload = self.read_length_prefixed(io).await?;
        postcard::from_bytes(&payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
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
        postcard::from_bytes(&payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
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
        let payload_len = payload.len() as u32;
        io.write_all(&payload_len.to_le_bytes()).await?;
        io.write_all(payload).await?;
        io.flush().await?;
        Ok(())
    }
}
