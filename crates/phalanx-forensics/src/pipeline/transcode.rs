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

// ── Encoder Strategy (the slot) ─────────────────────────────────────────

/// The output of a [`MediaTranscoder`] backend: the finished MP4 container and
/// the number of video frames it actually encoded.
///
/// `duration_ms` is deliberately NOT here — it is a pure function of
/// `frame_count` + `fps`, derived once by [`transcode_recording`], so it has a
/// single owner and no backend can disagree with it.
pub struct EncodedMedia {
    /// Complete MP4 file bytes (codec + container chosen by the backend).
    pub mp4_bytes: Vec<u8>,
    /// Number of video frames the backend encoded into the container.
    pub frame_count: u32,
}

/// A pluggable media-encode backend — the codec/container strategy.
///
/// Mirrors the codebase's injected-strategy idiom (`PeerEvaluator`,
/// `TrustedClock`): one method, object-safe, selected at runtime via `&dyn`.
/// The software backend ([`SoftwareTranscoder`], openh264/fdk-aac/mp4) lives
/// behind the `software-transcode` feature; a native platform-encoder backend
/// (Android MediaCodec / iOS VideoToolbox) implements the same trait in
/// phalanx-ffi. Frame-cap enforcement and forensic aggregation are NOT here —
/// they are codec-independent and owned by [`transcode_recording`].
pub trait MediaTranscoder: Send + Sync {
    /// Encode decoded JPEG video frames + PCM audio into an MP4 container.
    fn transcode(
        &self,
        video: Vec<DecodedVideoShard>,
        audio: Vec<DecodedAudioShard>,
        fps: Fps,
    ) -> Result<EncodedMedia, TranscodeError>;
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

// ── Transcode Orchestration ─────────────────────────────────────────────

/// Transcode decoded video/audio shards into an MP4 container via the injected
/// [`MediaTranscoder`] backend.
///
/// Codec-independent: enforces the frame cap and aggregates forensic metrics
/// (both *before* the shards are moved into the backend), delegates the actual
/// encode + mux to `transcoder`, then derives `duration_ms` from the encoded
/// frame count (its single owner). Pure computation — no IO.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Frame-count/duration arithmetic bounded by the cap below.
pub fn transcode_recording(
    transcoder: &dyn MediaTranscoder,
    video_shards: Vec<DecodedVideoShard>,
    audio_shards: Vec<DecodedAudioShard>,
    fps: Fps,
) -> Result<TranscodedMedia, TranscodeError> {
    // Count total input frames and enforce the cap before doing any work.
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

    // Forensic aggregation is codec-independent — compute it before the shards
    // are moved into the backend.
    let aggregate_metrics = aggregate_forensic_metrics(&video_shards);

    // Delegate the actual encode + mux to the injected strategy.
    let encoded = transcoder.transcode(video_shards, audio_shards, fps)?;

    // `duration_ms` has a single owner: derived here from the frames the backend
    // reports it encoded and the frame rate.
    let duration_ms = (encoded.frame_count as u64 * 1000) / fps.get() as u64;

    Ok(TranscodedMedia {
        mp4_bytes: encoded.mp4_bytes,
        duration_ms,
        frame_count: encoded.frame_count,
        aggregate_metrics,
    })
}

// ── Software Backend (H.264 / AAC / MP4) ────────────────────────────────
//
// The default `MediaTranscoder`: turbojpeg decode → openh264 H.264 → fdk-aac
// AAC → `mp4` mux. Pure CPU computation, no IO. Gated behind
// `software-transcode` and EXCLUDED from FOSS/mobile builds — `fdk-aac` is
// non-free (no patent grant) and a self-built `openh264` is patent-exposed. On
// those builds a native platform encoder (MediaCodec/VideoToolbox) implements
// `MediaTranscoder` instead.

/// Software H.264/AAC/MP4 transcode backend. Zero-sized — constructed at the
/// use site, never stored.
#[cfg(feature = "software-transcode")]
pub struct SoftwareTranscoder;

#[cfg(feature = "software-transcode")]
impl MediaTranscoder for SoftwareTranscoder {
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Frame/index arithmetic bounded by the caller's frame cap.
    fn transcode(
        &self,
        video_shards: Vec<DecodedVideoShard>,
        audio_shards: Vec<DecodedAudioShard>,
        fps: Fps,
    ) -> Result<EncodedMedia, TranscodeError> {
        // Decode all JPEG frames to YUV420, enforcing consistent dimensions.
        let total_frames: usize = video_shards.iter().map(|s| s.jpeg_frames.len()).sum();
        let mut yuv_frames: Vec<Vec<u8>> = Vec::with_capacity(total_frames);
        let mut frame_width: Option<u32> = None;
        let mut frame_height: Option<u32> = None;
        let mut global_frame_idx = 0usize;

        for shard in &video_shards {
            for jpeg_bytes in &shard.jpeg_frames {
                let (yuv, w, h) = decode_jpeg_to_yuv420(jpeg_bytes, global_frame_idx)?;

                // Enforce consistent dimensions across all frames.
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

        // Encode H.264.
        let h264_nals = encode_h264(&yuv_frames, width, height, fps)?;

        // Encode AAC (if audio present) and bundle with metadata for muxing.
        let aac_bundle = if let Some(first) = audio_shards.first() {
            let sr = first.sample_rate;
            let ch = first.channels;
            let (frames, frame_len) = encode_aac(&audio_shards)?;
            Some((frames, frame_len, sr, ch))
        } else {
            None
        };

        // Mux into MP4.
        let mp4_bytes = mux_mp4(
            &h264_nals,
            aac_bundle
                .as_ref()
                .map(|(f, fl, sr, ch)| (f.as_slice(), *fl, *sr, *ch)),
            width,
            height,
            fps,
        )?;

        Ok(EncodedMedia {
            frame_count: h264_nals.len() as u32,
            mp4_bytes,
        })
    }
}

// ── JPEG Decoding ───────────────────────────────────────────────────────

#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // YUV plane arithmetic — dimensions validated by turbojpeg decoder.
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

// Indices governed by computed plane dimensions from width/height.
#[cfg(feature = "software-transcode")]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
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

// Indices governed by chunks_exact(2) iterator and non-empty input guard.
#[cfg(feature = "software-transcode")]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn encode_aac(audio_shards: &[DecodedAudioShard]) -> Result<(Vec<Vec<u8>>, u32), TranscodeError> {
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
    let frame_length = info.frameLength;
    let frame_size = frame_length as usize * channels as usize;
    let mut aac_frames: Vec<Vec<u8>> = Vec::new();
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
            aac_frames.push(output_buf[..encode_result.output_size].to_vec());
        }
    }

    Ok((aac_frames, frame_length))
}

// ── AAC ↔ MP4 Type Mapping ─────────────────────────────────────────────

#[cfg(feature = "software-transcode")]
fn sample_rate_to_freq_index(rate: SampleRate) -> Result<mp4::SampleFreqIndex, TranscodeError> {
    match rate.get() {
        96_000 => Ok(mp4::SampleFreqIndex::Freq96000),
        88_200 => Ok(mp4::SampleFreqIndex::Freq88200),
        64_000 => Ok(mp4::SampleFreqIndex::Freq64000),
        48_000 => Ok(mp4::SampleFreqIndex::Freq48000),
        44_100 => Ok(mp4::SampleFreqIndex::Freq44100),
        32_000 => Ok(mp4::SampleFreqIndex::Freq32000),
        24_000 => Ok(mp4::SampleFreqIndex::Freq24000),
        22_050 => Ok(mp4::SampleFreqIndex::Freq22050),
        16_000 => Ok(mp4::SampleFreqIndex::Freq16000),
        12_000 => Ok(mp4::SampleFreqIndex::Freq12000),
        11_025 => Ok(mp4::SampleFreqIndex::Freq11025),
        8_000 => Ok(mp4::SampleFreqIndex::Freq8000),
        7_350 => Ok(mp4::SampleFreqIndex::Freq7350),
        other => Err(TranscodeError::AacEncoderError(format!(
            "unsupported sample rate for MP4 AAC: {other} Hz"
        ))),
    }
}

#[cfg(feature = "software-transcode")]
fn channel_count_to_config(ch: ChannelCount) -> Result<mp4::ChannelConfig, TranscodeError> {
    match ch.get() {
        1 => Ok(mp4::ChannelConfig::Mono),
        2 => Ok(mp4::ChannelConfig::Stereo),
        3 => Ok(mp4::ChannelConfig::Three),
        4 => Ok(mp4::ChannelConfig::Four),
        5 => Ok(mp4::ChannelConfig::Five),
        6 => Ok(mp4::ChannelConfig::FiveOne),
        7 | 8 => Ok(mp4::ChannelConfig::SevenOne),
        other => Err(TranscodeError::AacEncoderError(format!(
            "unsupported channel count for MP4 AAC: {other}"
        ))),
    }
}

// ── MP4 Muxing ──────────────────────────────────────────────────────────

#[cfg(feature = "software-transcode")]
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // MP4 container byte offset arithmetic and dimension casts.
fn mux_mp4(
    h264_nals: &[Vec<u8>],
    aac: Option<(&[Vec<u8>], u32, SampleRate, ChannelCount)>,
    width: u32,
    height: u32,
    fps: Fps,
) -> Result<Vec<u8>, TranscodeError> {
    use mp4::{Mp4Config, Mp4Writer, TrackConfig};
    // Governance: Cursor<Vec<u8>> is in-memory byte assembly, permitted per Command #2.
    use std::io::Cursor;

    let mut buf = Vec::new();
    let cursor = Cursor::new(&mut buf);

    let config = Mp4Config {
        major_brand: str::parse("isom")
            .map_err(|e: mp4::Error| TranscodeError::Mp4MuxError(e.to_string()))?,
        minor_version: 512,
        compatible_brands: vec![
            str::parse("isom")
                .map_err(|e: mp4::Error| TranscodeError::Mp4MuxError(e.to_string()))?,
            str::parse("iso2")
                .map_err(|e: mp4::Error| TranscodeError::Mp4MuxError(e.to_string()))?,
            str::parse("avc1")
                .map_err(|e: mp4::Error| TranscodeError::Mp4MuxError(e.to_string()))?,
            str::parse("mp41")
                .map_err(|e: mp4::Error| TranscodeError::Mp4MuxError(e.to_string()))?,
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

    // Add AAC audio track (track 2) when audio data is present
    if let Some((frames, frame_len, rate, ch)) = aac {
        let freq_index = sample_rate_to_freq_index(rate)?;
        let chan_conf = channel_count_to_config(ch)?;

        let audio_track_config = TrackConfig {
            track_type: mp4::TrackType::Audio,
            timescale: rate.get(),
            language: String::from("und"),
            media_conf: mp4::MediaConfig::AacConfig(mp4::AacConfig {
                bitrate: 0, // VBR — bitrate not signaled in esds
                profile: mp4::AudioObjectType::AacLowComplexity,
                freq_index,
                chan_conf,
            }),
        };

        writer
            .add_track(&audio_track_config)
            .map_err(|e| TranscodeError::Mp4MuxError(e.to_string()))?;

        for (i, frame_bytes) in frames.iter().enumerate() {
            let sample = mp4::Mp4Sample {
                start_time: i as u64 * frame_len as u64,
                duration: frame_len,
                rendering_offset: 0,
                is_sync: true, // all AAC-LC frames are random-access
                bytes: mp4::Bytes::copy_from_slice(frame_bytes),
            };

            writer
                .write_sample(2, &sample)
                .map_err(|e| TranscodeError::Mp4MuxError(e.to_string()))?;
        }
    }

    writer
        .write_end()
        .map_err(|e| TranscodeError::Mp4MuxError(e.to_string()))?;

    Ok(buf)
}

// ── NAL Parsing Helpers ─────────────────────────────────────────────────

/// Extract SPS NAL unit from the H.264 bitstream (NAL type 7).
// Indices governed by windows(4) iterator: window always has exactly 4 elements.
#[cfg(feature = "software-transcode")]
#[allow(clippy::indexing_slicing)]
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
// Indices governed by windows(4) iterator: window always has exactly 4 elements.
#[cfg(feature = "software-transcode")]
#[allow(clippy::indexing_slicing)]
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    /// A no-op backend so the codec-independent orchestration (frame cap, empty
    /// check) is testable WITHOUT the `software-transcode` feature — these
    /// paths reject before the transcoder is ever invoked.
    struct StubTranscoder;
    impl MediaTranscoder for StubTranscoder {
        fn transcode(
            &self,
            _video: Vec<DecodedVideoShard>,
            _audio: Vec<DecodedAudioShard>,
            _fps: Fps,
        ) -> Result<EncodedMedia, TranscodeError> {
            Ok(EncodedMedia {
                mp4_bytes: vec![0u8; 4],
                frame_count: 0,
            })
        }
    }

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

        let result = transcode_recording(&StubTranscoder, vec![big_shard], vec![], Fps::new(30));
        assert!(matches!(
            result,
            Err(TranscodeError::RecordingTooLong(_, _))
        ));
    }

    #[test]
    fn no_video_frames_rejected() {
        let result = transcode_recording(&StubTranscoder, vec![], vec![], Fps::new(30));
        assert!(matches!(result, Err(TranscodeError::NoVideoFrames)));
    }

    /// Real software encode through the strategy: decode → H.264 → mux. Gated on
    /// the feature so it only runs where the codecs are compiled in.
    #[cfg(feature = "software-transcode")]
    #[test]
    fn software_transcoder_round_trips_real_frames() {
        use crate::reassembler::compress_frame;

        let (w, h) = (64u32, 64u32);
        let make = |seed: u8| {
            let y = vec![seed; (w * h) as usize];
            let uv = vec![128u8; ((w / 2) * (h / 2) * 2) as usize];
            compress_frame(&y, &uv, w, h, false).expect("compress frame")
        };
        let video = vec![DecodedVideoShard {
            jpeg_frames: vec![make(16), make(32)],
            metrics: ForensicMetrics::default(),
        }];

        let out = transcode_recording(&SoftwareTranscoder, video, vec![], Fps::new(30))
            .expect("software transcode succeeds");

        assert!(!out.mp4_bytes.is_empty(), "produces a non-empty MP4");
        assert_eq!(out.frame_count, 2, "encodes both frames");
        assert_eq!(
            out.duration_ms,
            2 * 1000 / 30,
            "duration derived from frame count + fps"
        );
    }
}
