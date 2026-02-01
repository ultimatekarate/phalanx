use libp2p::{futures::StreamExt};
use phalanx::{
    stronghold::Stronghold, 
    sentinel::Sentinel,
    config::PhalanxConfig,
};
use std::error::Error;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    println!("PHALANX STRONGHOLD: Initializing Headless PDS...");

    let config = PhalanxConfig::load("phalanx.toml")
        .expect("Failed to load phalanx.toml.");
    
    let mut storage = Stronghold::new("./vault", &config);
    let mut sentinel = Sentinel::new(&config);
    let mut swarm = phalanx::setup_phalanx_swarm(&config).await?;

    // Use the topics already managed by the sentinel
    sentinel.subscribe_all(&mut swarm)?;

    let port = std::env::args().nth(1).unwrap_or_else(|| "4001".to_string());
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", port).parse()?)?;

    // Cleanup and Heartbeat timers
    let mut cleanup_timer = tokio::time::interval(Duration::from_secs(10));
    let mut heartbeat_timer = tokio::time::interval(Duration::from_secs(30));

    println!("Stronghold Status: Online. PeerID: {}", swarm.local_peer_id());

    loop {
        tokio::select! {
            // 1. Handle Incoming Network Traffic
            event = swarm.select_next_some() => {
                // Delegate all network event logic to the sentinel.
                // It now returns a WitnessEnvelope only when a shard is fully reassembled.
                if let Some(envelope) = sentinel.handle_network_event(event, &mut swarm) {
                    // Security & verification are now handled inside ingest_envelope
                    storage.ingest_envelope(envelope);
                }
            }

            // 2. Periodic Peer Cleanup & Forensic Salvage
            _ = cleanup_timer.tick() => {
                let local_id = *swarm.local_peer_id();
                let stale_data = sentinel.process_cleanup(local_id);
                
                for (_peer_id, envelopes) in stale_data {
                    for envelope in envelopes {
                        storage.ingest_envelope(envelope);
                    }
                }
            }

            // 3. Outgoing Heartbeats
            _ = heartbeat_timer.tick() => {
                let hb = sentinel.generate_heartbeat(swarm.local_peer_id());
                if let Ok(data) = postcard::to_stdvec(&hb) {
                    let _ = swarm.behaviour_mut().gossipsub.publish(sentinel.control_topic.clone(), data);
                }
            }
        }
    }
}