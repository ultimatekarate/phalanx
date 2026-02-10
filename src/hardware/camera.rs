use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
use nokhwa::pixel_format::RgbFormat;
use nokhwa::Camera;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use crate::protocol::shards::{self, StorageSequence, VideoShard}; 
use crate::core::config::HardwareConfig;

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

// MockCamera for simulation
pub struct MockCamera {
    width: u32,
    height: u32,
}

impl Default for MockCamera {
    fn default() -> Self {
        Self::new()
    }
}

impl MockCamera {
    pub fn new() -> Self {
        Self { width: 640, height: 480 }
    }
}

impl FrameProvider for MockCamera {
    fn capture_frame(&mut self) -> Result<Vec<u8>, String> {
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
    /// Spawns the camera capture thread using values from the HardwareConfig.
    pub fn spawn(self, 
        index: Option<usize>, 
        tx: Sender<VideoShard>, 
        config: HardwareConfig, 
        volley_id: String,
        secret_key: Option<[u8; 32]>
    ) {
        let fps = config.camera_fps as u8;
        let frame_duration = Duration::from_millis(1000 / fps as u64);

        std::thread::spawn(move || {
            let mut provider: Box<dyn FrameProvider> = match index {
                Some(i) => match HardwareCamera::new(i) {
                    Ok(cam) => Box::new(cam),
                    Err(e) => {
                        eprintln!("Hardware Error: {}. Falling back to Mock.", e);
                        Box::new(MockCamera::new())
                    }
                },
                None => Box::new(MockCamera::new()),
            };

            let mut frames = Vec::new();
            let mut sequence_id: StorageSequence = StorageSequence(0);
            let (width, height) = provider.dimensions();

            loop {
                if let Ok(raw_data) = provider.capture_frame() {
                    if let Ok(jpeg) = shards::compress_frame(raw_data, width, height) {
                        frames.push(jpeg);
                    }
                }

                if frames.len() >= fps as usize {

                    let mut shard = shards::create_video_shard(
                        frames.split_off(0), 
                        sequence_id, 
                        fps,
                        volley_id.clone()
                    );
                    
                    if let Some(key) = secret_key {
                        if let Err(e) = shard.encrypt(&key) {
                            eprintln!("[Camera] Encryption failed for seq {}: {}", sequence_id, e);
                            // Secure Default: Do not send unencrypted frames if key was provided.
                            // Continue to next loop without sending.
                            continue; 
                        }
                    }

                    if tx.blocking_send(shard).is_err() { break; }
                    sequence_id += 1;
                }

                std::thread::sleep(frame_duration);
            }
        });
    }
}

pub fn test_hardware_connection(index: usize) -> Result<usize, String> {
    let mut camera = HardwareCamera::new(index)?;
    let raw_frame = camera.capture_frame()?;
    Ok(raw_frame.len())
}