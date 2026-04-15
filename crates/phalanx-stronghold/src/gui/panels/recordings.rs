// crates/phalanx-stronghold/src/gui/panels/recordings.rs
//
// Recording browser: select a community, list recordings with completion
// status. Uses EvidenceStore directly (same as CLI). Extracts lightweight
// RecordingSummary, drops full Recording immediately.

use eframe::egui;
use phalanx_proto::community::CommunityId;

use crate::gui::bridge::DaemonBridge;
use crate::gui::state::{AsyncReply, CommunitiesState, RecordingSummary, RecordingsState};
use crate::persistence::evidence_store::EvidenceStore;

pub fn render(
    ui: &mut egui::Ui,
    _ctx: &egui::Context,
    bridge: &DaemonBridge,
    state: &mut RecordingsState,
    communities_state: &CommunitiesState,
) {
    ui.heading("Recordings");
    ui.add_space(8.0);

    // Community selector
    let communities = match &communities_state.communities {
        AsyncReply::Ready(Ok(list)) => list.as_slice(),
        _ => &[],
    };

    ui.horizontal(|ui| {
        ui.label("Community:");
        let current_label = state
            .selected_community
            .as_ref()
            .map(|(_, name)| name.as_str())
            .unwrap_or("Select...");

        egui::ComboBox::from_id_salt("recordings_community")
            .selected_text(current_label)
            .show_ui(ui, |ui| {
                for info in communities {
                    let label = format!("{} ({})", info.name, info.member_count);
                    if ui
                        .selectable_label(
                            state.selected_community.as_ref().map(|(id, _)| id) == Some(&info.id),
                            &label,
                        )
                        .clicked()
                    {
                        state.selected_community = Some((info.id, info.name.clone()));
                        state.recordings = AsyncReply::Idle; // Trigger reload
                    }
                }
            });

        if ui.button("Refresh").clicked() {
            state.recordings = AsyncReply::Idle;
        }
    });

    ui.add_space(12.0);

    // Auto-load when community is selected and recordings are idle
    if let (Some((cid, _)), AsyncReply::Idle) = (&state.selected_community, &state.recordings) {
        let vault_path = bridge.vault_path.clone();
        let community_id = *cid;
        let (tx, rx) = oneshot::channel();
        bridge.runtime.spawn(async move {
            let result = load_recording_summaries(&vault_path, &community_id).await;
            let _ = tx.send(result);
        });
        state.recordings = AsyncReply::pending(rx);
    }

    // Display recordings table
    match &state.recordings {
        AsyncReply::Pending { .. } => {
            ui.spinner();
        }
        AsyncReply::Ready(Ok(recordings)) => {
            if recordings.is_empty() {
                ui.label("No recordings found for this community.");
            } else {
                ui.label(format!("{} recording(s)", recordings.len()));
                ui.add_space(4.0);

                egui::Grid::new("recordings_grid")
                    .striped(true)
                    .min_col_width(100.0)
                    .show(ui, |ui| {
                        ui.strong("Recording ID");
                        ui.strong("Artifacts");
                        ui.strong("Status");
                        ui.strong("Owner");
                        ui.end_row();

                        for rec in recordings {
                            ui.monospace(rec.id.as_str());
                            ui.label(format!("{}", rec.artifact_count));
                            let status = if rec.is_complete { "Complete" } else { "Gaps" };
                            let color = if rec.is_complete {
                                egui::Color32::GREEN
                            } else {
                                egui::Color32::YELLOW
                            };
                            ui.colored_label(color, status);
                            let short_did = rec.owner_did.get(..20).unwrap_or(&rec.owner_did);
                            ui.monospace(short_did);
                            ui.end_row();
                        }
                    });
            }
        }
        AsyncReply::Ready(Err(msg)) => {
            ui.colored_label(egui::Color32::RED, msg);
        }
        AsyncReply::Error(msg) => {
            ui.colored_label(egui::Color32::RED, msg);
        }
        AsyncReply::Idle => {
            if state.selected_community.is_none() {
                ui.label("Select a community to browse recordings.");
            }
        }
    }
}

/// Load recording summaries from the evidence store.
/// Reads full recordings but immediately extracts lightweight summaries.
async fn load_recording_summaries(
    vault_path: &std::path::Path,
    community_id: &CommunityId,
) -> Result<Vec<RecordingSummary>, String> {
    let store = EvidenceStore::new(vault_path.to_path_buf());
    let recording_ids = store
        .list_recordings(community_id)
        .await
        .map_err(|e| format!("Failed to list recordings: {e}"))?;

    let mut summaries = Vec::with_capacity(recording_ids.len());

    for rid in &recording_ids {
        match store.read_recording(community_id, rid).await {
            Ok(rec) => {
                summaries.push(RecordingSummary {
                    id: rec.id,
                    owner_did: rec.owner_did.to_string(),
                    artifact_count: rec.artifacts.len(),
                    is_complete: rec.is_complete,
                });
                // rec dropped here — no envelope payloads retained
            }
            Err(e) => {
                summaries.push(RecordingSummary {
                    id: rid.clone(),
                    owner_did: "?".into(),
                    artifact_count: 0,
                    is_complete: false,
                });
                tracing::warn!(recording = %rid, error = %e, "Failed to read recording");
            }
        }
    }

    Ok(summaries)
}
