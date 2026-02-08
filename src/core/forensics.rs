use rustfft::{FftPlanner, num_complex::Complex};
use image::{GrayImage, imageops::FilterType};

/// Returns a score from 0.0 (Natural) to 1.0 (Screen/Moiré)
pub fn detect_moire(img: &DynamicImage) -> f32 {
    // 1. Downsample aggressively (This is the performance savior)
    // We use Nearest Neighbor for speed; Linear might smooth out the artifacts we want to find.
    let thumb = img.resize_exact(512, 512, FilterType::Nearest);
    let gray = thumb.to_luma8();

    // 2. Prepare FFT buffer
    let mut planner = FftPlanner::new();
    let fft = planner.plan_fft_forward(512);

    // Convert pixels to Complex<f32>
    let mut buffer: Vec<Complex<f32>> = gray.pixels()
        .map(|p| Complex { re: p[0] as f32, im: 0.0 })
        .collect();

    // 3. Execute FFT (Rows then Columns for 2D)
    // Process Rows
    fft.process(&mut buffer); 
    // Transpose and Process Columns (Pseudo-code for brevity)
    // transpose(&mut buffer, 512);
    // fft.process(&mut buffer);

    // 4. Analyze the Spectrum
    // Natural images have energy concentrated at the center (Low Freq).
    // Screens have energy "spikes" in the corners/edges (High Freq Grid).
    let score = calculate_high_freq_ratio(&buffer);
    
    score
}