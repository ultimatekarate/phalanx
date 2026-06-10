// crates/phalanx-node/src/actors/revocation.rs
//
// Revocation actor (cryptographic forgetting). Processes inbound revocation
// tokens OFF the MeshSentinel run loop: deserialize, verify the self-contained
// signature, forward to StorageActor for authorization + execution, then on
// success re-publish to gossipsub and withdraw the local DHT provider records.
//
// Stateless: holds only its outbound senders + lifecycle. Distinct from
// `recovery.rs` (manifest-walk recovery) — different domain, different trigger.

use std::sync::Arc;

use tokio::sync::mpsc;

use phalanx_proto::identity::MeshAddress;

use crate::actors::egress::EgressCommand;
use crate::actors::shutdown::ShutdownSignal;
use crate::actors::storage::StorageCommand;

/// Commands accepted by the revocation actor.
#[derive(Debug)]
pub enum RevocationCommand {
    /// An inbound revocation token arrived on the revocation gossip topic.
    /// `origin` is the libp2p propagation source; `data` is the raw frame.
    InboundToken { origin: MeshAddress, data: Vec<u8> },
}

pub struct RevocationActor {
    storage_tx: mpsc::Sender<StorageCommand>,
    egress_tx: mpsc::Sender<EgressCommand>,
    rx: mpsc::Receiver<RevocationCommand>,
    shutdown: Arc<ShutdownSignal>,
}

impl RevocationActor {
    pub fn new(
        storage_tx: mpsc::Sender<StorageCommand>,
        egress_tx: mpsc::Sender<EgressCommand>,
        rx: mpsc::Receiver<RevocationCommand>,
        shutdown: Arc<ShutdownSignal>,
    ) -> Self {
        Self {
            storage_tx,
            egress_tx,
            rx,
            shutdown,
        }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                Some(cmd) = self.rx.recv() => {
                    self.handle_command(cmd).await;
                }
                else => break,
            }
        }

        // Post-loop drain: finish any tokens queued before cancellation.
        while let Ok(cmd) = self.rx.try_recv() {
            self.handle_command(cmd).await;
        }
    }

    async fn handle_command(&mut self, cmd: RevocationCommand) {
        match cmd {
            RevocationCommand::InboundToken { origin, data } => {
                self.handle_revocation(origin, &data).await;
            }
        }
    }

    /// Cryptographic Forgetting: process an inbound revocation token from gossipsub.
    async fn handle_revocation(&mut self, origin: MeshAddress, data: &[u8]) {
        // 1. Deserialize
        let token: phalanx_proto::revocation::RevocationToken =
            match phalanx_forensics::gate::unmarshal_checked(data, "revocation_token") {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(peer = %origin, error = %e, "Malformed revocation token");
                    return;
                }
            };

        // 2. Verify self-contained signature
        if let Err(e) = phalanx_forensics::revocation::verify_revocation_token(&token) {
            tracing::warn!(
                peer = %origin,
                recording = %token.recording_id,
                error = %e,
                "Invalid revocation token rejected"
            );
            return;
        }

        // 3. Forward to StorageActor for authorization and execution
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let recording_id = token.recording_id.clone();
        if self
            .storage_tx
            .send(StorageCommand::Revoke {
                token: token.clone(),
                reply_to: reply_tx,
            })
            .await
            .is_err()
        {
            tracing::error!("Storage channel closed — cannot process revocation");
            return;
        }

        match reply_rx.await {
            Ok(Ok(())) => {
                tracing::info!(recording = %recording_id, "Revocation applied — propagating");
                // 4. Epidemic propagation: republish to gossipsub
                let _ = self
                    .egress_tx
                    .send(EgressCommand::PublishRevocation(token))
                    .await;
                // 5. Withdraw local DHT provider records
                let _ = self
                    .egress_tx
                    .send(EgressCommand::WithdrawProvider(recording_id))
                    .await;
            }
            Ok(Err(e)) => {
                tracing::warn!(recording = %recording_id, error = %e, "Revocation rejected");
            }
            Err(_) => {
                tracing::error!("Storage reply channel dropped during revocation");
            }
        }
    }
}
