/// crates/phalanx-dashboard/src/bridge.rs
pub struct TuiObserver {
    tx: mpsc::Sender<DashboardAction>,
}

impl MeshObserver for TuiObserver {
    fn observe_event(&self, event: &SimEvent) {
        // Map core events to UI updates
        let _ = self.tx.try_send(DashboardAction::UpdateMeshRadar(event.clone()));
    }
}