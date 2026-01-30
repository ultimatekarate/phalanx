use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
use nokhwa::pixel_format::RgbFormat;
use nokhwa::Camera;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use crate::vid::{self, VideoShard, Shredder};


pub trait FrameProvider: 'static {
    fn capture_frame(&mut self) -> Result<Vec<u8>, String>;
    fn dimensions(&self) -> (u32, u32);
}


// Desktop Camera implementation
pub struct HardwareCamera {
    camera: Camera,
}

impl HardwareCamera {
    pub fn new(index: usize) -> Result<Self, String> {
        let mut camera = Camera::new(
            CameraIndex::Index(index as u32),
            RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate),
        ).map_err(|e| e.to_string())?;

        camera.open_stream().map_err(|e| e.to_string())?;
        Ok(Self { camera })
    }
}

impl FrameProvider for HardwareCamera {
    fn capture_frame(&mut self) -> Result<Vec<u8>, String> {
        let frame = self.camera.frame().map_err(|e| e.to_string())?;
        let decoded = frame.decode_image::<RgbFormat>().map_err(|e| e.to_string())?;
        Ok(decoded.into_raw())
    }

    fn dimensions(&self) -> (u32, u32) {
        let res = self.camera.resolution();
        (res.width(), res.height())
    }
}

// MockCamera is for Testing and Mobile simulation
pub struct MockCamera {
    width: u32,
    height: u32,
}

impl MockCamera {
    pub fn new() -> Self {
        Self { width: 640, height: 480 }
    }
}

impl FrameProvider for MockCamera {
    fn capture_frame(&mut self) -> Result<Vec<u8>, String> {
        // Return a dummy "test pattern" (gray frame)
        Ok(vec![128u8; (self.width * self.height * 3) as usize])
    }

    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

pub struct PhalanxCameraThread {
    pub fps: u32,
}

impl PhalanxCameraThread {
    pub fn spawn(self, index: Option<usize>, tx: Sender<VideoShard>) {
        let frame_duration = Duration::from_millis(1000 / self.fps as u64);

        std::thread::spawn(move || {
            let mut provider: Box<dyn FrameProvider> = match index {
                Some(idx) => match HardwareCamera::new(idx) {
                    Ok(cam) => Box::new(cam),
                    Err(e) => {
                        eprintln!("Hardware Error: {}. Falling back to Mock.", e);
                        Box::new(MockCamera::new())
                    }
                },
                None => Box::new(MockCamera::new()), // Explicitly requested Mock
            };

            let mut shredder = Shredder::new();
            let mut frames = Vec::new();
            let (width, height) = provider.dimensions();

            println!("Camera Thread: Provider online.");

            loop {
                if let Ok(raw_data) = provider.capture_frame() {
                    if let Ok(jpeg) = vid::compress_frame(raw_data, width, height) {
                        frames.push(jpeg);
                    }
                }

                if frames.len() >= self.fps as usize {
                    let shard = shredder.create_shard(frames.split_off(0));
                    if tx.blocking_send(shard).is_err() { break; }
                }

                std::thread::sleep(frame_duration);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn test_mock_camera_dimensions() {
        let mock = MockCamera::new();
        let (w, h) = mock.dimensions();
        assert_eq!(w, 640);
        assert_eq!(h, 480);
    }

    #[test]
    fn test_mock_camera_frame_size() {
        let mut mock = MockCamera::new();
        let frame = mock.capture_frame().expect("Should capture mock frame");
        // RGB frame should be width * height * 3 bytes
        assert_eq!(frame.len(), (640 * 480 * 3) as usize);
        // Verify mock data (gray pattern)
        assert_eq!(frame[0], 128u8);
    }

    #[tokio::test]
    async fn test_camera_thread_shard_production() {
        // We use a small FPS for a quick test
        let fps = 2;
        let (tx, mut rx) = mpsc::channel(10);
        let camera_thread = PhalanxCameraThread { fps };

        // Spawn using None to force MockCamera
        camera_thread.spawn(None, tx);

        // Wait for the first shard to be produced
        // At 2 FPS, this should take roughly 1 second
        let shard = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Timeout waiting for shard")
            .expect("Channel closed unexpectedly");

        // Verify the shard structure
        assert!(!shard.frames.is_empty(), "Shard should contain JPEG data");
        // Since we have 2 FPS, the shard should contain 2 frames
        // Note: The shredder logic might vary, but we verify data exists
    }
}