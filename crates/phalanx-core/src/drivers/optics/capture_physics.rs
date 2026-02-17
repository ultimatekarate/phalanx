// What if the device has a high end sensor?

// PSEUDOCODE

pub enum ShutterType {
    Rolling(f32), // Readout time in ms
    Global,       // Instant readout
}

pub struct MotionPhysicsVerifier {
    shutter_type: ShutterType,
}

impl PassiveDetector for MotionPhysicsVerifier {
    fn analyze(&self, frame: &VideoFrame, context: &FrameContext) -> f32 {
        let gyro_motion = context.gyro.magnitude();

        match self.shutter_type {
            // Standard Phone (Rolling Shutter)
            ShutterType::Rolling(readout_ms) => {
                let expected_skew = calculate_expected_skew(gyro_motion, readout_ms);
                let actual_skew = measure_geometry_skew(frame);

                // If geometry is too perfect, it's fake
                return diff(expected_skew, actual_skew);
            }

            // BIG SPENDER High-End Sensor (Global Shutter)
            ShutterType::Global => {
                let expected_blur_vector =
                    calculate_blur_vector(gyro_motion, context.exposure_time);
                let actual_blur = measure_motion_blur_direction(frame);

                // If image is too sharp or blur direction is wrong, it's fake
                return diff(expected_blur_vector, actual_blur);
            }
        }
    }
}
