use libp2p::identity::Keypair;

use phalanx_proto::identity::MeshAddress;
use phalanx_proto::prelude::PhalanxIdentity;
use zeroize::Zeroizing;

pub trait Libp2pExt {
    fn to_libp2p_keypair(&self) -> Keypair;
    /// The libp2p `PeerId` for this identity, base58btc-encoded — the
    /// `/p2p/<peer-id>` tail of a dialable multiaddr (e.g. for Stronghold
    /// pairing). Derived from the same Ed25519 keypair the swarm uses.
    fn libp2p_peer_id(&self) -> String;
    /// Returns the canonical mesh-routing address for this identity.
    /// Equivalent to `PeerMapper::to_mesh_address(&keypair.public().to_peer_id())`,
    /// computed via the Ed25519 keypair this identity wraps.
    fn to_mesh_address(&self) -> MeshAddress;
}

impl Libp2pExt for PhalanxIdentity {
    fn to_libp2p_keypair(&self) -> Keypair {
        let mut bytes = Zeroizing::new(self.keypair.to_bytes());
        // Safety: PhalanxIdentity is always constructed with valid Ed25519 material;
        // invalid key bytes would indicate a corrupted identity, which is unrecoverable.
        #[allow(clippy::expect_used)]
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("Critical: PhalanxIdentity contains invalid Ed25519 material")
    }

    fn libp2p_peer_id(&self) -> String {
        self.to_libp2p_keypair().public().to_peer_id().to_string()
    }

    fn to_mesh_address(&self) -> MeshAddress {
        let libp2p_key = self.to_libp2p_keypair();
        crate::PeerMapper::to_mesh_address(&libp2p_key.public().to_peer_id())
    }
}
