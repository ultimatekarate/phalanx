// src/lib.rs

// --- 1. BASE DOMAIN ---
pub mod base {
    pub mod config;
    pub mod engine;
    pub mod governor;
    pub mod types;
}

// --- 2. PRIMITIVES ---
pub mod primitives {
    pub mod identity;
    pub mod shards;
    pub mod time;
}

// --- 3. STORAGE ---
pub mod storage {
    pub mod crucible;
    pub mod strategies;
    pub mod vault;
}

// --- 4. TRANSPORT ---
pub mod transport {
    pub mod swarm;
}

// --- 5. SECURITY ---
pub mod security {
    pub mod e2ee;
    pub mod grant;
    pub mod locator;
    pub mod sentinel;
    pub mod telemetry;
    pub mod trust;
}

pub mod simulation;

// --- 6. DRIVERS (Conditional) ---
#[cfg(feature = "edge")]
pub mod drivers {
    pub mod sensors {
        pub mod audio;
        pub mod camera;
        pub mod sensors;
    }
    pub mod optics {
        pub mod capture_physics;
        pub mod moire;
    }
}

// --- 7. RE-EXPORTS ---
pub use base::config::PhalanxConfig;
pub use primitives::identity::{PhalanxIdentity, IdentityError};
pub use transport::swarm::{setup_phalanx_swarm, PhalanxBehaviour, PhalanxEvent};

// --- 8. SHARED LOGIC ---
pub fn init_identity() -> Result<PhalanxIdentity, IdentityError> {
    let id_path = "identity.bin";

    match PhalanxIdentity::load_from_disk(id_path) {
        Ok(identity) => {
            tracing::info!(path = %id_path, "Existing identity loaded successfully");
            Ok(identity)
        }
        // Handle the specific case where the identity does not yet exist
        Err(IdentityError::IoError(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(path = %id_path, "Identity not found. Initiating generation protocol.");

            // Generate a new identity and mnemonic pair
            let (new_identity, mnemonic) = PhalanxIdentity::generate()?;

            // Forensic Backup: In a production environment, this should be routed 
            // to a secure out-of-band logging service or encrypted vault.
            tracing::info!("Identity generated. Emergency Mnemonic: {}", mnemonic);

            // Persist to the guardian layer before returning the sentinel
            new_identity.save_to_disk(id_path)?;
            
            Ok(new_identity)
        }
        // Propagate corruption, permission errors, or version mismatches
        Err(err) => {
            tracing::error!(
                path = %id_path, 
                error = %err, 
                "Identity initialization failed due to system or data corruption"
            );
            Err(err)
        }
    }
}
