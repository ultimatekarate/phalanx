// crates/phalanx-transport/src/adapters/kademlia.rs

use libp2p::kad::{ProviderRecord, RecordKey};
use phalanx_proto::kademlia::DhtProviderSet;
use std::str::FromStr;

pub fn translate_to_libp2p_records(set: DhtProviderSet, key_raw: &str) -> Vec<ProviderRecord> {
    let key = RecordKey::new(&key_raw);

    set.providers
        .into_iter()
        .filter_map(|p| {
            // Mapping Forensic NetworkId back to Physical PeerId
            let peer_id = libp2p::PeerId::from_str(&p.network_id.0).ok()?;

            Some(ProviderRecord {
                key: key.clone(),
                provider: peer_id,
                expires: None, // libp2p handles internal TTL differently
                addresses: Vec::new(),
            })
        })
        .collect()
}
