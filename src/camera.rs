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
            println!("Camera Thread: Hardware online at index {}", index);

            loop {
                match camera.frame() {
                    Ok(f) => {
                        if let Ok(d) = f.decode_image::<RgbFormat>() {
                            let (w, h) = (d.width(), d.height());
                            match vid::compress_frame(d.into_raw(), w, h) {
                                Ok(jpeg) => {
                                    frames.push(jpeg);
                                    // DEBUG: Print every 5 frames captured
                                    if frames.len() % 5 == 0 {
                                        println!("Camera: Captured {}/{}", frames.len(), fps);
                                    }
                                },
                                Err(e) => eprintln!("Compression error: {}", e),
                            }
                        }
                    }
                    Err(e) => eprintln!("Frame error: {}", e),
                }

                if frames.len() >= fps as usize {
                    println!("Camera: Packaging Shard #{}...", shredder.current_id());
                    let shard = shredder.create_shard(frames.split_off(0));
                    
                    if let Err(e) = tx.blocking_send(shard) {
                        eprintln!("Send Error: Main loop is not listening! {}", e);
                        break; 
                    }
                    println!("Camera: Shard handed to Network.");
                }
                std::thread::sleep(frame_duration);
            }
            
        });
    }
}