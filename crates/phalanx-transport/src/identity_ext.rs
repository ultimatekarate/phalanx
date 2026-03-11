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
        crate::PeerMapper::to_network_id(&libp2p_key.public().to_peer_id())
    }
}
