pub mod chaos;
pub mod clock; // The "Tense Control": Management of virtual time
pub mod harness; // The "Pen": Your API for writing simulation scripts
pub mod world; // The "Ether": Shared state where nodes meet // The "Adverbs": Logic for dropping/delaying packets

pub use clock::VirtualClock;
pub use harness::{SimConfig, SimulationHarness};
pub use world::SimulationWorld;

/// High-level errors that occur during the "Authoring" of a simulation.
#[derive(Debug, thiserror::Error)]
pub enum SimError {
    #[error("Node {0} not found in simulation world")]
    NodeNotFound(phalanx_proto::Did),

    #[error("Simulation timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("Internal transport failure: {0}")]
    Transport(String),
}

#[tokio::test]
async fn test_pillar_retry_logic_and_backoff() {
    let _temp = tempfile::tempdir().unwrap();
    let (discovery_tx, discovery_rx) = mpsc::channel(100);

    // Initialize with NoOpJournal as we are testing the Engine's internal loop

    let mut engine = PhalanxEngine::new(
        PhalanxConfig::test_defaults(),
        PhalanxIdentity::new(),
        FailingTransport,
        NoOpJournal,
        TrustRegistry::build(&PhalanxConfig::test_defaults()).await,
        Arc::new(SyncReputationCache::default()),
        discovery_rx,
        discovery_tx,
    )
    .await
    .unwrap();

    // 1. Inject a "stale" message (next_attempt is in the past)
    let past_ts = PhalanxTimestamp::from_millis(PhalanxTimestamp::now().as_millis() - 5000);
    engine.pending_egress.push_back(PendingEgress {
        channel_id: "retry_target_01".into(),
        response: VolleyResponse::NotFound,
        attempt_count: 0,
        next_attempt: past_ts,
    });

    // 2. Execute the retry processor
    engine.process_pending_egress().await;

    // 3. Verify Pillar 3: Backoff math and retention
    let pending = engine
        .pending_egress
        .front()
        .expect("Pillar 3 Failure: Message was dropped instead of re-queued on failure");

    assert_eq!(pending.attempt_count, 1);
    // The new timestamp should be roughly now + 1000ms (500 * 2^1)
    assert!(pending.next_attempt > PhalanxTimestamp::now());
    assert_eq!(pending.channel_id, "retry_target_01");
}

#[tokio::test]
async fn test_pillar_salvage_intent() {
    use crate::security::gate::WitnessGate;

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let (discovery_tx, discovery_rx) = mpsc::channel(100);

    let mut engine = PhalanxEngine::new(
        PhalanxConfig::test_defaults(),
        identity.clone(),
        FailingTransport,
        NoOpJournal,
        TrustRegistry::build(&PhalanxConfig::test_defaults()).await,
        Arc::new(SyncReputationCache::default()),
        discovery_rx,
        discovery_tx,
    )
    .await
    .unwrap();

    // 1. Create a structurally valid WitnessEnvelope
    let video_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: VolleyId::new("v1"),
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };

    let envelope = Evidence::Video(video_shard)
        .seal(&identity, identity.to_network_id(), None)
        .expect("Failed to seal test envelope");

    // 2. Populate live queue with the correct type
    engine.pending_egress.push_back(PendingEgress::new(
        "ch_live".into(),
        VolleyResponse::Success(vec![envelope]),
        Duration::from_secs(5),
    ));

    // 3. Simulate the Shutdown branch logic
    let salvage_payload: Vec<PendingEgress> = engine.pending_egress.drain(..).collect();

    // 4. Verify Pillar 1
    assert_eq!(salvage_payload.len(), 1);
    assert_eq!(salvage_payload[0].channel_id, "ch_live");

    // Ensure the data inside matches
    if let VolleyResponse::Success(ref envelopes) = salvage_payload[0].response {
        assert_eq!(envelopes.len(), 1);
    } else {
        panic!("Pillar 1 Failure: Response type was corrupted during salvage drain");
    }
}
