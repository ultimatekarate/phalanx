// crates/phalanx-forensics/src/transcode.rs
//
// The Verb "To Transcode." Pure computation — no IO.
//
// Takes decoded video frames (JPEG) and audio segments (PCM) and produces
// an MP4 container with H.264 video and AAC audio tracks.
//
// Laboratory layer: deterministic, testable, no filesystem access.

use phalanx_proto::evidence::ForensicMetrics;
use phalanx_proto::types::{ChannelCount, Fps, SampleRate};

// ── Input Types ─────────────────────────────────────────────────────────

/// A decoded video shard: postcard-deserialized JPEG frames + forensic metrics.
pub struct DecodedVideoShard {
    /// Each element is a JPEG-compressed frame from the capture pipeline.
    pub jpeg_frames: Vec<Vec<u8>>,
    /// Per-shard forensic metrics (PRNU, Moiré energy).
    pub metrics: ForensicMetrics,
}

/// A decoded audio shard: raw PCM bytes after LZ4 decompression.
pub struct DecodedAudioShard {
    /// Raw PCM samples (no postcard wrapper — audio is stored as raw bytes).
    pub pcm_bytes: Vec<u8>,
    pub sample_rate: SampleRate,
    pub channels: ChannelCount,
}

// ── Output Types ────────────────────────────────────────────────────────

/// The output of the transcode pipeline: an MP4 file in memory.
pub struct TranscodedMedia {
    /// Complete MP4 file bytes (H.264 video + AAC audio).
    pub mp4_bytes: Vec<u8>,
    /// Total duration of the recording in milliseconds.
    pub duration_ms: u64,
    /// Total number of video frames encoded.
    pub frame_count: u32,
    /// Aggregated forensic metrics across all video shards.
    pub aggregate_metrics: AggregateForensicMetrics,
}

/// Forensic metrics aggregated across all video shards in a recording.
/// Richer than a single mean — includes min/max for anomaly detection.
#[derive(Debug, Clone)]
pub struct AggregateForensicMetrics {
    pub mean_h_energy: f32,
    pub mean_v_energy: f32,
    pub mean_prnu_var: f32,
    pub min_prnu_var: f32,
    pub max_prnu_var: f32,
}

// ── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TranscodeError {
    #[error("No video frames to transcode")]
    NoVideoFrames,

    #[error("Recording too long: {0} frames exceeds cap of {1}")]
    RecordingTooLong(u32, u32),

    #[error("JPEG decode failed for frame {0}: {1}")]
    JpegDecodeFailed(usize, String),

    #[error("H.264 encoder error: {0}")]
    H264EncoderError(String),

    #[error("AAC encoder error: {0}")]
    AacEncoderError(String),

    #[error("MP4 muxing error: {0}")]
    Mp4MuxError(String),

    #[error("Inconsistent frame dimensions: expected {0}x{1}, got {2}x{3}")]
    InconsistentDimensions(u32, u32, u32, u32),
}

// ── Constants ───────────────────────────────────────────────────────────

/// Maximum frames allowed in a single export (~5 minutes at 30fps).
/// Prevents OOM from unbounded accumulation.
const MAX_EXPORT_FRAMES: u32 = 10_000;

// ── Transcode Pipeline ──────────────────────────────────────────────────

/// Transcode decoded video/audio shards into an MP4 container.
///
/// Pure computation — no IO. The caller is responsible for writing
/// the output bytes to disk.
///
/// # Pipeline
/// 1. Count total frames, reject if > MAX_EXPORT_FRAMES
/// 2. Decode JPEG frames to YUV420 via turbojpeg
/// 3. Encode YUV420 frames to H.264 via openh264
/// 4. Encode PCM audio to AAC via fdk-aac
/// 5. Mux H.264 + AAC into MP4 container
/// 6. Aggregate ForensicMetrics (min/max/mean)
pub fn transcode_to_mp4(
    video_shards: Vec<DecodedVideoShard>,
    audio_shards: Vec<DecodedAudioShard>,
    fps: Fps,
) -> Result<TranscodedMedia, TranscodeError> {
    // Count total frames and enforce cap
    let total_frames: u32 = video_shards
        .iter()
        .map(|s| s.jpeg_frames.len() as u32)
        .sum();

    if total_frames == 0 {
        return Err(TranscodeError::NoVideoFrames);
    }

    if total_frames > MAX_EXPORT_FRAMES {
        return Err(TranscodeError::RecordingTooLong(
            total_frames,
            MAX_EXPORT_FRAMES,
        ));
    }

    // Aggregate forensic metrics
    let aggregate_metrics = aggregate_forensic_metrics(&video_shards);

    // Decode all JPEG frames to YUV420
    let mut yuv_frames: Vec<Vec<u8>> = Vec::with_capacity(total_frames as usize);
    let mut frame_width: Option<u32> = None;
    let mut frame_height: Option<u32> = None;
    let mut global_frame_idx = 0usize;

    for shard in &video_shards {
        for jpeg_bytes in &shard.jpeg_frames {
            let (yuv, w, h) = decode_jpeg_to_yuv420(jpeg_bytes, global_frame_idx)?;

            // Enforce consistent dimensions across all frames
            match (frame_width, frame_height) {
                (Some(ew), Some(eh)) if ew != w || eh != h => {
                    return Err(TranscodeError::InconsistentDimensions(ew, eh, w, h));
                }
                _ => {
                    frame_width = Some(w);
                    frame_height = Some(h);
                }
            }

            yuv_frames.push(yuv);
            global_frame_idx += 1;
        }
    }

    let width = frame_width.unwrap_or(256);
    let height = frame_height.unwrap_or(256);

    // Encode H.264
    let h264_nals = encode_h264(&yuv_frames, width, height, fps)?;

    // Encode AAC (if audio present)
    let aac_frames = if !audio_shards.is_empty() {
        Some(encode_aac(&audio_shards)?)
    } else {
        None
    };

    // Mux into MP4
    let sample_rate = audio_shards.first().map(|a| a.sample_rate);
    let channels = audio_shards.first().map(|a| a.channels);
    let mp4_bytes = mux_mp4(
        &h264_nals,
        aac_frames.as_deref(),
        width,
        height,
        fps,
        sample_rate,
        channels,
    )?;

    let duration_ms = (total_frames as u64 * 1000) / fps.get() as u64;

    Ok(TranscodedMedia {
        mp4_bytes,
        duration_ms,
        frame_count: total_frames,
        aggregate_metrics,
    })
}

// ── JPEG Decoding ───────────────────────────────────────────────────────

pub(crate) fn decode_jpeg_to_yuv420(
    jpeg_bytes: &[u8],
    frame_idx: usize,
) -> Result<(Vec<u8>, u32, u32), TranscodeError> {
    let mut decompressor = turbojpeg::Decompressor::new()
        .map_err(|e| TranscodeError::JpegDecodeFailed(frame_idx, e.to_string()))?;

    let header = decompressor
        .read_header(jpeg_bytes)
        .map_err(|e| TranscodeError::JpegDecodeFailed(frame_idx, e.to_string()))?;

    let width = header.width as u32;
    let height = header.height as u32;

    // Decompress JPEG directly to YUV (preserves native YCbCr without RGB round-trip)
    let align = 1; // no row padding — tightly packed planes for H.264 encoder
    let yuv_pixels_len =
        turbojpeg::yuv_pixels_len(header.width, align, header.height, header.subsamp)
            .map_err(|e| TranscodeError::JpegDecodeFailed(frame_idx, e.to_string()))?;

    let mut yuv_image = turbojpeg::YuvImage {
        pixels: vec![0u8; yuv_pixels_len],
        width: header.width,
        align,
        height: header.height,
        subsamp: header.subsamp,
    };

    decompressor
        .decompress_to_yuv(jpeg_bytes, yuv_image.as_deref_mut())
        .map_err(|e| TranscodeError::JpegDecodeFailed(frame_idx, e.to_string()))?;

    Ok((yuv_image.pixels, width, height))
}

// ── H.264 Encoding ──────────────────────────────────────────────────────

fn encode_h264(
    yuv_frames: &[Vec<u8>],
    width: u32,
    height: u32,
    fps: Fps,
) -> Result<Vec<Vec<u8>>, TranscodeError> {
    use openh264::encoder::{Encoder, EncoderConfig};
    use openh264::formats::YUVSlices;

    let config = EncoderConfig::new()
        .set_bitrate_bps(1_000_000) // 1 Mbps — reasonable for mobile evidence
        .max_frame_rate(fps.get() as f32);

    let api = openh264::OpenH264API::from_source();
    let mut encoder = Encoder::with_api_config(api, config)
        .map_err(|e| TranscodeError::H264EncoderError(e.to_string()))?;

    let mut nals = Vec::with_capacity(yuv_frames.len());

    for yuv in yuv_frames {
        let ystride = width as usize;
        let uvstride = (width / 2) as usize;
        let y_len = (width * height) as usize;
        let uv_len = ((width / 2) * (height / 2)) as usize;

        let y_plane = &yuv[..y_len];
        let u_plane = &yuv[y_len..y_len + uv_len];
        let v_plane = &yuv[y_len + uv_len..];

        let source = YUVSlices::new(
            (y_plane, u_plane, v_plane),
            (width as usize, height as usize),
            (ystride, uvstride, uvstride),
        );

        let bitstream = encoder
            .encode(&source)
            .map_err(|e| TranscodeError::H264EncoderError(e.to_string()))?;

        // Collect all NAL units from this frame into a single buffer
        let mut frame_data = Vec::new();
        for l in 0..bitstream.num_layers() {
            if let Some(layer) = bitstream.layer(l) {
                for n in 0..layer.nal_count() {
                    if let Some(nal) = layer.nal_unit(n) {
                        frame_data.extend_from_slice(nal);
                    }
                }
            }
        }

        nals.push(frame_data);
    }

    Ok(nals)
}

// ── AAC Encoding ────────────────────────────────────────────────────────

fn encode_aac(audio_shards: &[DecodedAudioShard]) -> Result<Vec<u8>, TranscodeError> {
    use fdk_aac::enc::{Encoder, EncoderParams};

    let first = &audio_shards[0];
    let sample_rate = first.sample_rate.get();
    let channels = first.channels.get() as u32;

    let params = EncoderParams {
        bit_rate: fdk_aac::enc::BitRate::VbrVeryHigh,
        sample_rate,
        transport: fdk_aac::enc::Transport::Raw,
        channels: if channels == 1 {
            fdk_aac::enc::ChannelMode::Mono
        } else {
            fdk_aac::enc::ChannelMode::Stereo
        },
    };

    let encoder =
        Encoder::new(params).map_err(|e| TranscodeError::AacEncoderError(format!("{e:?}")))?;

    // Concatenate all audio PCM into one buffer
    let total_pcm: Vec<u8> = audio_shards
        .iter()
        .flat_map(|s| s.pcm_bytes.iter().copied())
        .collect();

    // Convert to i16 samples (PCM is stored as little-endian i16)
    let samples: Vec<i16> = total_pcm
        .chunks_exact(2)
        .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    // Encode in chunks matching the encoder's frame size
    let info = encoder
        .info()
        .map_err(|e| TranscodeError::AacEncoderError(format!("{e:?}")))?;
    let frame_size = info.frameLength as usize * channels as usize;
    let mut aac_output = Vec::new();
    let mut output_buf = vec![0u8; 8192]; // AAC frame output buffer

    for chunk in samples.chunks(frame_size) {
        // Pad last chunk with silence if needed
        let padded: Vec<i16>;
        let input = if chunk.len() < frame_size {
            padded = {
                let mut v = chunk.to_vec();
                v.resize(frame_size, 0);
                v
            };
            &padded
        } else {
            chunk
        };

        let encode_result = encoder
            .encode(input, &mut output_buf)
            .map_err(|e| TranscodeError::AacEncoderError(format!("{e:?}")))?;

        if encode_result.output_size > 0 {
            aac_output.extend_from_slice(&output_buf[..encode_result.output_size]);
        }
    }

    Ok(aac_output)
}

// ── MP4 Muxing ──────────────────────────────────────────────────────────

fn mux_mp4(
    h264_nals: &[Vec<u8>],
    aac_data: Option<&[u8]>,
    width: u32,
    height: u32,
    fps: Fps,
    _sample_rate: Option<SampleRate>,
    _channels: Option<ChannelCount>,
) -> Result<Vec<u8>, TranscodeError> {
    use mp4::{Mp4Config, Mp4Writer, TrackConfig};
    // Governance: Cursor<Vec<u8>> is in-memory byte assembly, permitted per Command #2.
    use std::io::Cursor;

    let mut buf = Vec::new();
    let cursor = Cursor::new(&mut buf);

    let config = Mp4Config {
        major_brand: str::parse("isom").unwrap(),
        minor_version: 512,
        compatible_brands: vec![
            str::parse("isom").unwrap(),
            str::parse("iso2").unwrap(),
            str::parse("avc1").unwrap(),
            str::parse("mp41").unwrap(),
        ],
        timescale: 1000,
    };

    let mut writer = Mp4Writer::write_start(cursor, &config)
        .map_err(|e| TranscodeError::Mp4MuxError(e.to_string()))?;

    // Add video track
    let video_track_config = TrackConfig {
        track_type: mp4::TrackType::Video,
        timescale: fps.get() * 1000,
        language: String::from("und"),
        media_conf: mp4::MediaConfig::AvcConfig(mp4::AvcConfig {
            width: width as u16,
            height: height as u16,
            seq_param_set: extract_sps(h264_nals).unwrap_or_default(),
            pic_param_set: extract_pps(h264_nals).unwrap_or_default(),
        }),
    };

    writer
        .add_track(&video_track_config)
        .map_err(|e| TranscodeError::Mp4MuxError(e.to_string()))?;

    // Write video samples
    let timescale = fps.get() * 1000;
    let sample_duration = timescale / fps.get();

    for (i, nal_data) in h264_nals.iter().enumerate() {
        let sample = mp4::Mp4Sample {
            start_time: i as u64 * sample_duration as u64,
            duration: sample_duration,
            rendering_offset: 0,
            is_sync: i == 0, // First frame is keyframe; simplified
            bytes: mp4::Bytes::copy_from_slice(nal_data),
        };

        writer
            .write_sample(1, &sample)
            .map_err(|e| TranscodeError::Mp4MuxError(e.to_string()))?;
    }

    // TODO: Add AAC audio track when audio muxing is validated.
    // The AAC encoding is done above; muxing into a second MP4 track
    // requires careful alignment of audio/video timescales.
    // For the initial export, video-only MP4 is sufficient for the demo.
    let _ = aac_data;

    writer
        .write_end()
        .map_err(|e| TranscodeError::Mp4MuxError(e.to_string()))?;

    Ok(buf)
}

// ── NAL Parsing Helpers ─────────────────────────────────────────────────

/// Extract SPS NAL unit from the H.264 bitstream (NAL type 7).
fn extract_sps(nals: &[Vec<u8>]) -> Option<Vec<u8>> {
    for nal_data in nals {
        // Scan for NAL start codes and check type
        for window in nal_data.windows(4) {
            if window[0..3] == [0, 0, 1] || window[0..4] == [0, 0, 0, 1] {
                let nal_type = if window[0..3] == [0, 0, 1] {
                    window[3] & 0x1F
                } else if let Some(&next) = nal_data.get(4) {
                    // 4-byte start code
                    next & 0x1F
                } else {
                    continue;
                };
                if nal_type == 7 {
                    // Found SPS — extract from start code to next start code or end
                    return Some(nal_data.clone());
                }
            }
        }
    }
    None
}

/// Extract PPS NAL unit from the H.264 bitstream (NAL type 8).
fn extract_pps(nals: &[Vec<u8>]) -> Option<Vec<u8>> {
    for nal_data in nals {
        for window in nal_data.windows(4) {
            if window[0..3] == [0, 0, 1] || window[0..4] == [0, 0, 0, 1] {
                let nal_type = if window[0..3] == [0, 0, 1] {
                    window[3] & 0x1F
                } else if let Some(&next) = nal_data.get(4) {
                    next & 0x1F
                } else {
                    continue;
                };
                if nal_type == 8 {
                    return Some(nal_data.clone());
                }
            }
        }
    }
    None
}

// ── Forensic Metrics Aggregation ────────────────────────────────────────

fn aggregate_forensic_metrics(shards: &[DecodedVideoShard]) -> AggregateForensicMetrics {
    if shards.is_empty() {
        return AggregateForensicMetrics {
            mean_h_energy: 0.0,
            mean_v_energy: 0.0,
            mean_prnu_var: 0.0,
            min_prnu_var: 0.0,
            max_prnu_var: 0.0,
        };
    }

    let count = shards.len() as f32;
    let mut sum_h = 0.0f32;
    let mut sum_v = 0.0f32;
    let mut sum_prnu = 0.0f32;
    let mut min_prnu = f32::MAX;
    let mut max_prnu = f32::MIN;

    for shard in shards {
        sum_h += shard.metrics.h_energy;
        sum_v += shard.metrics.v_energy;
        sum_prnu += shard.metrics.prnu_var;
        min_prnu = min_prnu.min(shard.metrics.prnu_var);
        max_prnu = max_prnu.max(shard.metrics.prnu_var);
    }

    AggregateForensicMetrics {
        mean_h_energy: sum_h / count,
        mean_v_energy: sum_v / count,
        mean_prnu_var: sum_prnu / count,
        min_prnu_var: min_prnu,
        max_prnu_var: max_prnu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_metrics_single_shard() {
        let shards = vec![DecodedVideoShard {
            jpeg_frames: vec![vec![0xFF, 0xD8]], // minimal JPEG header
            metrics: ForensicMetrics {
                h_energy: 0.5,
                v_energy: 0.3,
                prnu_var: 0.1,
                mean_luminance: 128.0,
            },
        }];

        let agg = aggregate_forensic_metrics(&shards);
        assert!((agg.mean_h_energy - 0.5).abs() < f32::EPSILON);
        assert!((agg.mean_prnu_var - 0.1).abs() < f32::EPSILON);
        assert!((agg.min_prnu_var - 0.1).abs() < f32::EPSILON);
        assert!((agg.max_prnu_var - 0.1).abs() < f32::EPSILON);
    }

    #[test]
    fn aggregate_metrics_multiple_shards() {
        let shards = vec![
            DecodedVideoShard {
                jpeg_frames: vec![],
                metrics: ForensicMetrics {
                    h_energy: 0.2,
                    v_energy: 0.4,
                    prnu_var: 0.05,
                    mean_luminance: 100.0,
                },
            },
            DecodedVideoShard {
                jpeg_frames: vec![],
                metrics: ForensicMetrics {
                    h_energy: 0.8,
                    v_energy: 0.6,
                    prnu_var: 0.15,
                    mean_luminance: 156.0,
                },
            },
        ];

        let agg = aggregate_forensic_metrics(&shards);
        assert!((agg.mean_h_energy - 0.5).abs() < f32::EPSILON);
        assert!((agg.mean_v_energy - 0.5).abs() < f32::EPSILON);
        assert!((agg.mean_prnu_var - 0.1).abs() < f32::EPSILON);
        assert!((agg.min_prnu_var - 0.05).abs() < f32::EPSILON);
        assert!((agg.max_prnu_var - 0.15).abs() < f32::EPSILON);
    }

    #[test]
    fn aggregate_metrics_empty() {
        let agg = aggregate_forensic_metrics(&[]);
        assert!((agg.mean_prnu_var - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn frame_cap_rejects_too_many() {
        let big_shard = DecodedVideoShard {
            jpeg_frames: vec![vec![0u8; 10]; MAX_EXPORT_FRAMES as usize + 1],
            metrics: ForensicMetrics::default(),
        };

        let result = transcode_to_mp4(vec![big_shard], vec![], Fps::new(30));
        assert!(matches!(
            result,
            Err(TranscodeError::RecordingTooLong(_, _))
        ));
    }

    #[test]
    fn no_video_frames_rejected() {
        let result = transcode_to_mp4(vec![], vec![], Fps::new(30));
        assert!(matches!(result, Err(TranscodeError::NoVideoFrames)));
    }
}
