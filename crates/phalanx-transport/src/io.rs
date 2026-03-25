// crates/phalanx-transport/src/io.rs
use phalanx_proto::prelude::RECORDING_SIZE_THRESHOLD;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Reads a u32 length prefix, validates against MAX_PAYLOAD_SIZE,
/// and retrieves the exact payload bytes from the stream.
pub async fn read_length_prefixed_payload<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut length_buffer = [0u8; 4];
    io.read_exact(&mut length_buffer).await?;
    let payload_length = u32::from_le_bytes(length_buffer) as usize;

    if payload_length > RECORDING_SIZE_THRESHOLD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Payload length {} exceeds protocol limit of {}",
                payload_length, RECORDING_SIZE_THRESHOLD
            ),
        ));
    }

    let mut payload_bytes = vec![0u8; payload_length];
    io.read_exact(&mut payload_bytes).await?;
    Ok(payload_bytes)
}

/// Prepends a u32 length prefix to the payload and writes it to the stream,
/// followed by an explicit flush.
pub async fn write_length_prefixed_payload<T>(io: &mut T, payload: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    #[allow(clippy::cast_possible_truncation)]
    // Payload size bounded by RECORDING_SIZE_THRESHOLD (< u32::MAX)
    let payload_length = payload.len() as u32;
    io.write_all(&payload_length.to_le_bytes()).await?;
    io.write_all(payload).await?;
    io.flush().await?;
    Ok(())
}
