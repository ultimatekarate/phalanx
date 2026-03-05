// TODO: Re-enable when SimulationHarness is implemented (all methods are currently todo!() stubs).
// The 6 non-harness tests have been extracted to phalanx-node/tests/:
//   - test_salvage_on_node_death          -> storage_actor_tests.rs
//   - test_out_of_sequence_salvage        -> guardian_tests.rs
//   - test_stronghold_crash_recovery      -> guardian_tests.rs
//   - test_leaf_mode_isolation            -> guardian_tests.rs
//   - test_pillar_salvage_under_disk_pressure -> storage_actor_tests.rs
//   - test_reputation_gate_signature_mismatch -> storage_actor_tests.rs
#![cfg(feature = "__disabled_legacy_tests")]

use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::primitives::identity::{NetworkId, PhalanxIdentity};
use phalanx_core::primitives::shards::{
    self, create_video_shard, ChunkType, Evidence, ShardId, StorageSequence, VolleyId,
    WitnessEnvelope,
};
use phalanx_core::security::telemetry::{init_observability, NodeRole, SimEvent};
use phalanx_core::simulation::SimulationHarness;
use phalanx_core::transport::events::NetworkEvent;
use tokio::time::Duration;

#[tokio::test]
async fn test_vampire_attack_defense() -> Result<(), Box<dyn std::error::Error>> {
    init_observability();
    let config = PhalanxConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, mut telemetry_rx) = SimulationHarness::init_mesh(config.clone(), physics);
    let victim_did = harness
        .spawn_node("Victim", NodeRole::Guardian)
        .await
        .expect("Spawn failed");

    let (attacker_identity, _) = PhalanxIdentity::generate()?;
    let attacker_net_id = attacker_identity.to_network_id();
    let vid = VolleyId::new("vampire_stream");

    for i in 0..5 {
        let shard = create_video_shard(vec![vec![1]], StorageSequence(i), 30, vid.clone())?;

        let mut envelope = WitnessEnvelope::new(
            Evidence::Video(shard),
            &attacker_identity,
            attacker_net_id.clone(),
            None,
        )?;

        // POISON: Tamper with evidence to break signature
        if let Evidence::Video(ref mut v) = envelope.evidence {
            v.fps = 145;
        }

        let serialized = postcard::to_stdvec(&envelope)?;
        let chunks = shards::chunkify(
            ShardId(i as u32),
            serialized,
            4096,
            attacker_identity.did.clone(),
            ChunkType::Witnessed,
        )?;

        if let Some(first_chunk) = chunks.first() {
            harness
                .inject_event(
                    &victim_did,
                    NetworkEvent::DataReceived {
                        origin: attacker_net_id.clone(),
                        topic: config.network.video_topic.clone(),
                        data: postcard::to_stdvec(first_chunk)?,
                    },
                )
                .await?;
        }
    }

    // Monitor for defense event
    let mut defense_triggered = false;
    let sleep = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(sleep);

    loop {
        tokio::select! {
            Some(event) = telemetry_rx.recv() => {
                if let SimEvent::AttackAttemptBlocked { attacker, .. } = event {
                    if attacker == attacker_net_id {
                        defense_triggered = true;
                        break;
                    }
                }
            }
            _ = &mut sleep => {
                tracing::warn!("Vampire monitoring timed out");
                break;
            }
        }
    }

    assert!(
        defense_triggered,
        "Vampire defense failed to block malformed payload"
    );
    Ok(())
}
