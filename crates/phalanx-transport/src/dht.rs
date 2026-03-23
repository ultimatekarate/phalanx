// crates/phalanx-transport/src/dht.rs
//
// Re-exports for Kademlia DHT types. Crates that implement custom
// `RecordStore` backends (e.g. phalanx-node's RedbStore) import from
// here instead of depending on libp2p directly.

pub use libp2p::kad::store::{Error as StoreError, RecordStore, Result as StoreResult};
pub use libp2p::kad::{ProviderRecord, Record, RecordKey};
pub use libp2p::PeerId;
