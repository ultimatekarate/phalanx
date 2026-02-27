   struct RecoveryJournal(Vec<PendingEgress>);

    #[async_trait::async_trait]
    impl TransientJournal for RecoveryJournal {
        async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
            // Pillar 2: Return the "salvaged" state
            Ok(self.0.clone())
        }
        async fn record_pending_egress(&mut self, _: &[PendingEgress]) -> Result<(), ShardError> {
            Ok(())
        }
        async fn record_chunk(&mut self, _: &ShardChunk) -> Result<(), ShardError> {
            Ok(())
        }
        async fn sync(&mut self) -> Result<(), ShardError> {
            Ok(())
        }
        async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
            Ok(vec![])
        }
        async fn clear(&mut self) -> Result<(), ShardError> {
            Ok(())
        }
    }