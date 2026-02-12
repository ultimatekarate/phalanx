
pub enum ForensicVerdict {
    Pass,
    Suspect(String), // "Moiré pattern detected"
    Fail(String),    // "Motion does not match Gyro"
}

pub trait PassiveDetector {
    /// Returns a score 0.0 (Real) to 1.0 (Fake)
    fn analyze(&self, frame: &VideoFrame, context: &FrameContext) -> f32;
    
    /// Returns a human-readable verdict
    fn verify(&self, frame: &VideoFrame, context: &FrameContext) -> ForensicVerdict;
}