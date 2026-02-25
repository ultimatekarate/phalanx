#[tokio::test]
async fn test_playback_resurrection_with_mesh_gap() {
    // 1. Setup our "Safe Room" components
    let identity = PhalanxIdentity::new_random();
    let guardian = Guardian::new_in_memory();
    let (disc_tx, mut disc_rx) = mpsc::channel(1);
    let (ui_tx, mut ui_rx) = mpsc::channel(10);

    // 2. Initialize the Coordinator with a VideoPlayerSink
    let sink = VideoPlayerSink::new(ui_tx);
    let mut coordinator =
        PlaybackCoordinator::new(guardian.clone(), identity.clone(), sink, disc_tx);

    // 3. Scenario: Shard 1 arrived via Gossip before Node A died.
    let shard_1 = identity.encrypt_and_sign(1, b"Frame 1 Data");
    guardian.insert_verified(shard_1).await;

    // 4. Start the Playback Brain
    let _handle = tokio::spawn(async move {
        coordinator.run().await.unwrap();
    });

    // 5. Verification: Frame 1 plays instantly (JIT Decrypted)
    let frame_1 = ui_rx
        .recv()
        .await
        .expect("Playback should start with Frame 1");
    assert_eq!(frame_1, b"Frame 1 Data");

    // 6. Verification: Gap Detection
    // Playback hits Shard 2. It's missing. Coordinator must signal the Mesh.
    let missing_seq = disc_rx
        .recv()
        .await
        .expect("Coordinator should signal for Shard 2");
    assert_eq!(missing_seq, 2);

    // 7. Scenario: Mesh heals. Shard 2 is retrieved from Node C.
    let shard_2 = identity.encrypt_and_sign(2, b"Frame 2 Data");
    guardian.insert_verified(shard_2).await;

    // 8. Verification: Playback resumes automatically
    let frame_2 = ui_rx
        .recv()
        .await
        .expect("Playback should resume with Frame 2");
    assert_eq!(frame_2, b"Frame 2 Data");
}

#[tokio::test]
async fn test_exodus_resurrection_logic() {
    // 1. Setup the Safe Room environment
    let identity = PhalanxIdentity::new_random();
    let guardian = Guardian::new_in_memory();
    let (disc_tx, mut disc_rx) = mpsc::channel(1);
    let (ui_tx, mut ui_rx) = mpsc::channel(10);

    let sink = VideoPlayerSink::new(ui_tx);
    let mut coordinator = ExodusCoordinator::new(guardian.clone(), identity.clone(), sink, disc_tx);

    // 2. Pre-load Shard 1
    let shard_1 = identity.encrypt_and_sign(1, b"Frame 1");
    guardian.insert_verified(shard_1).await;

    // 3. Start Coordinator
    let _handle = tokio::spawn(async move {
        coordinator.run().await.unwrap();
    });

    // 4. Verify Immediate Resurrection (Shard 1)
    let frame = ui_rx.recv().await.expect("Should receive Frame 1");
    assert_eq!(frame, b"Frame 1");

    // 5. Verify Gap Discovery (Shard 2 is missing)
    let missing_id = disc_rx
        .recv()
        .await
        .expect("Should signal discovery for Shard 2");
    assert_eq!(missing_id, 2);

    // 6. Mesh provides Shard 2 (Resurrection continues)
    let shard_2 = identity.encrypt_and_sign(2, b"Frame 2");
    guardian.insert_verified(shard_2).await;

    let frame_2 = ui_rx.recv().await.expect("Should receive Frame 2");
    assert_eq!(frame_2, b"Frame 2");
}
