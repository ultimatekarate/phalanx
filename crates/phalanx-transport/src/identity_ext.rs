use libp2p::identity::Keypair;

use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_proto::prelude::*;

pub trait Libp2pExt {
    fn to_libp2p_keypair(&self) -> Keypair;
    fn to_network_id(&self) -> NetworkId;
}

impl Libp2pExt for PhalanxIdentity {
    fn to_libp2p_keypair(&self) -> Keypair {
        let mut bytes = self.keypair.to_bytes();
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("Critical: PhalanxIdentity contains invalid Ed25519 material")
    }

    fn to_network_id(&self) -> NetworkId {
        let libp2p_key = self.to_libp2p_keypair();
        NetworkId(libp2p_key.public().to_peer_id().to_string())
    }
}

mod test {

    #[test]
    fn test_identity_generation_and_did() {
        use super::*;
        const IDENTITY_VERSION: u32 = 1;
        let identity = PhalanxIdentity::new_ephemeral();
        assert!(!identity.did.0.starts_with("did:key:"));
        assert!(identity.did.0.len() > 40);
        assert_eq!(identity.version, IDENTITY_VERSION);
    }

    #[test]
    fn test_mnemonic_recovery() {
        let (original, phrase) = PhalanxIdentity::generate().unwrap();
        let original_did = original.did.clone();

        let recovered = PhalanxIdentity::restore(&phrase).expect("Failed to restore");

        assert_eq!(original_did, recovered.did);
        assert_eq!(original.keypair.to_bytes(), recovered.keypair.to_bytes());
        assert_eq!(recovered.version, IDENTITY_VERSION);
    }
}
