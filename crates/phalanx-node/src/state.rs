#[derive(Clone, Default)]
pub struct SyncReputationCache {
    pub scores: Arc<RwLock<HashMap<NetworkId, f32>>>,
}

impl PeerEvaluator for SyncReputationCache {
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32 {
        *self.scores.read().unwrap().get(peer_id).unwrap_or(&1.0)
    }
}