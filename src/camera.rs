use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
use nokhwa::pixel_format::RgbFormat;
use nokhwa::Camera;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use crate::vid::{self, VideoShard, Shredder};

pub struct PhalanxCamera {
    pub index: usize,
    pub fps: u32,
}

impl PhalanxCamera {
    pub fn new(index: usize, fps: u32) -> Self {
        Self { index, fps }
    }

    /// Spawns the hardware thread and returns a handle or simply runs until the channel closes.
    pub fn spawn_thread(&self, tx: Sender<VideoShard>) {
        let index = self.index;
        let fps = self.fps;
        let frame_duration = Duration::from_millis(1000 / fps as u64);

        std::thread::spawn(move || {
            let mut shredder = Shredder::new();
            
            // Initialize hardware
            let mut camera = Camera::new(
                CameraIndex::Index(index as u32), 
                RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate)
            ).expect("CRITICAL: Hardware camera not found");

            camera.open_stream().expect("CRITICAL: Camera stream lock failed");

            let mut frames = Vec::new();
            println!("📸 Camera Thread: Hardware online at index {}", index);

            loop {
                if let Ok(frame) = camera.frame() {
                    if let Ok(img_buf) = frame.decode_image::<RgbFormat>() {
                        let width = img_buf.width();
                        let height = img_buf.height();
                        let raw_data = img_buf.into_raw();

                        if let Ok(jpeg) = vid::compress_frame(raw_data, width, height) {
                            frames.push(jpeg);
                        }
                    }
                }

                // If we've collected enough frames for 1 second of footage
                if frames.len() >= fps as usize {
                    let shard = shredder.create_shard(frames.split_off(0));
                    
                    // Use blocking_send because we are in a standard thread, not an async task
                    if tx.blocking_send(shard).is_err() {
                        println!("Camera thread exiting: Receiver dropped.");
                        break;
                    }
                }

                std::thread::sleep(frame_duration);
            }
        });
    }
}