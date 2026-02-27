pub struct PlaybackCoordinator<S: PlaybackSink> {
    storage_tx: mpsc::Sender<StorageCommand>,
    decryption_key: Option<SymmetricKey>,
    sink: S,
    discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,
    current_sequence: StorageSequence,
}

impl<S: PlaybackSink> PlaybackCoordinator<S> {
    pub fn new(
        storage_tx: mpsc::Sender<StorageCommand>,
        decryption_key: Option<SymmetricKey>,
        sink: S,
        discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,
    ) -> Self {
        Self {
            storage_tx,
            decryption_key,
            sink,
            discovery_tx,
            current_sequence: StorageSequence(1), // Forensic truth starts at 1
        }
    }

    pub async fn run(&mut self, volley_id: VolleyId) -> Result<()> {
        loop {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

            // 2. Ask the StorageActor for the frame
            self.storage_tx
                .send(StorageCommand::GetShard {
                    volley_id: volley_id.clone(),
                    sequence_id: self.current_sequence,
                    reply_to: reply_tx,
                })
                .await
                .context("StorageActor mailbox closed")?;

            // 3. Await the response from the StorageActor
            let shard_opt = reply_rx
                .await
                .context("StorageActor dropped the response channel")?;
            match shard_opt {
                Some(envelope) => {
                    let payload = match &envelope.evidence {
                        Evidence::Video(v) => &v.payload,
                        Evidence::Audio(a) => &a.payload,
                        Evidence::Gap(_) | Evidence::Handover(_) => {
                            self.current_sequence.0 += 1;
                            continue;
                        }
                    };

                    let frame_data = match payload {
                        DataPayload::Clear(data) => data.clone(),
                        DataPayload::Encrypted { .. } => {
                            let key = self.decryption_key.as_ref().context(
                                "Encountered encrypted shard, but no SymmetricKey was provided",
                            )?;
                            payload.decrypt(key)?
                        }
                        DataPayload::Missing(_) => {
                            self.current_sequence.0 += 1;
                            continue;
                        }
                    };

                    self.sink
                        .handle_chunk(self.current_sequence, frame_data)
                        .await?;
                    self.current_sequence.0 += 1;
                }
                None => {
                    // Gap detected, trigger Samson Reflex
                    let _ = self
                        .discovery_tx
                        .try_send((volley_id.clone(), self.current_sequence));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}
