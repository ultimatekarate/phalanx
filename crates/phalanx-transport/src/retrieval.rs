use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use libp2p::request_response;
use libp2p::swarm::StreamProtocol;
use phalanx_proto::retrieval::VolleyRequest;
use phalanx_proto::retrieval::VolleyResponse;
use std::io;
#[derive(Clone, Default)]
pub struct PhalanxRetrievalCodec;

#[async_trait]
impl request_response::Codec for PhalanxRetrievalCodec {
    type Protocol = StreamProtocol;
    type Request = VolleyRequest;
    type Response = VolleyResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let payload = self.read_packet(io).await?;
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
        let payload = self.read_packet(io).await?;
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
        self.write_packet(io, &payload).await
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
        self.write_packet(io, &payload).await
    }
}
