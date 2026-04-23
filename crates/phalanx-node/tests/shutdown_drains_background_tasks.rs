#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
// Integration test for the graceful shutdown path added to resolve C2.
//
// Asserts that `MeshSentinel::shutdown()` drives every spawned background
// task — the six actor loops plus the vitals daemon — to termination within
// a tight deadline. If a task's cancel arm is miswired or the post-loop
// drain hangs, the outer `tokio::time::timeout` will fail the test instead
// of letting CI hang until the job timeout expires.

mod common;

use common::build_test_sentinel;
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::test]
async fn shutdown_drains_all_background_tasks_within_deadline() {
    // The ingress channel is kept alive for the duration of the test so the
    // sentinel's run() loop (which we never call here) would not exit on its
    // own — we want the shutdown() call to be what drives the actors down.
    let (_ingress_tx, ingress_rx) = mpsc::channel(1);
    let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

    // 5-second budget is well clear of the 10-second per-task deadline inside
    // shutdown(); anything less than 5s here means the actors drained
    // promptly, which is the expected path. Exceeding 5s flags a miswired
    // cancel arm or a blocking operation inside an actor's post-loop drain.
    tokio::time::timeout(Duration::from_secs(5), sentinel.shutdown())
        .await
        .expect("shutdown must drain within 5s");
}
