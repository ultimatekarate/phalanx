use opencv::{
    core,
    highgui,
    imgcodecs,
    videoio,
    prelude::*,
};
use std::path::Path;


// Video reconstructor logic
pub fn assemble_evidence_video(peer_id: &str) -> opencv::Result<()> {
    let input_dir = format!("./recovered/{}/", peer_id);
    let output_file = format!("./recovered/{}_evidence.mp4", peer_id);

    // Collect all recovered JPEGs
    let mut entries: Vec<_> = std::fs::read_dir(input_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    
    // Sort chronologically by filename
    entries.sort_by_key(|e| e.path());

    if entries.is_empty() {
        println!("⚠️ No frames found to assemble.");
        return Ok(());
    }

    // Initialize VideoWriter
    // 'avc1' is the FourCC code for H.264
    let fourcc = videoio::VideoWriter::fourcc('a', 'v', 'c', '1')?; 
    let mut writer = videoio::VideoWriter::new(
        &output_file,
        fourcc,
        15.0, // Match your Phalanx 15 FPS
        core::Size::new(1920, 1080),
        true,
    )?;

    println!("Assembling {} frames into video...", entries.len());

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("jpg") {
            // Load the JPEG frame
            let frame = imgcodecs::imread(path.to_str().unwrap(), imgcodecs::IMREAD_COLOR)?;
            
            if !frame.empty() {
                writer.write(&frame)?;
            }
        }
    }

    println!("Evidence Video Created: {}", output_file);
    Ok(())
}