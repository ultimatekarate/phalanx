// crates/phalanx-stronghold/src/gui/panels/communities.rs
//
// Community roster panel: list communities from disk, import via file dialog.
// On import, writes to disk AND sends Import command to the live CommunityActor
// so the routing table updates immediately.

use eframe::egui;
use phalanx_proto::community::Community;

use crate::actors::community::CommunityCommand;
use crate::gui::bridge::DaemonBridge;
use crate::gui::state::{AsyncReply, CommunitiesState, CommunityInfo};
use crate::gui::widgets::hex_encode;

pub fn render(
    ui: &mut egui::Ui,
    _ctx: &egui::Context,
    bridge: &DaemonBridge,
    state: &mut CommunitiesState,
) {
    ui.heading("Communities");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        // Refresh button — scan communities from disk
        if ui.button("Refresh").clicked() {
            let vault_path = bridge.vault_path.clone();
            let (tx, rx) = oneshot::channel();
            bridge.runtime.spawn(async move {
                let result = load_communities_from_disk(&vault_path).await;
                let _ = tx.send(result);
            });
            state.communities = AsyncReply::Pending(rx);
        }

        // Import button — native file dialog
        if ui.button("Import Community").clicked() {
            let picked = rfd::FileDialog::new()
                .add_filter("Community", &["bin"])
                .set_title("Select community roster file")
                .pick_file();

            if let Some(path) = picked {
                let vault_path = bridge.vault_path.clone();
                let community_tx = bridge.community_tx.clone();
                let (tx, rx) = oneshot::channel();
                bridge.runtime.spawn(async move {
                    let result = import_community(&vault_path, &path, &community_tx).await;
                    let _ = tx.send(result);
                });
                state.import_result = AsyncReply::Pending(rx);
            }
        }
    });

    // Import result feedback
    if let Some(Ok(msg)) = state.import_result.as_ready() {
        ui.add_space(4.0);
        ui.colored_label(egui::Color32::GREEN, msg);
    }
    if let Some(Err(msg)) = state.import_result.as_ready() {
        ui.add_space(4.0);
        ui.colored_label(egui::Color32::RED, msg);
    }
    if let Some(msg) = state.import_result.as_error() {
        ui.add_space(4.0);
        ui.colored_label(egui::Color32::RED, msg);
    }

    ui.add_space(12.0);

    // Auto-load on first render
    if matches!(state.communities, AsyncReply::Idle) {
        let vault_path = bridge.vault_path.clone();
        let (tx, rx) = oneshot::channel();
        bridge.runtime.spawn(async move {
            let result = load_communities_from_disk(&vault_path).await;
            let _ = tx.send(result);
        });
        state.communities = AsyncReply::Pending(rx);
    }

    // Display communities table
    match &state.communities {
        AsyncReply::Pending(_) => {
            ui.spinner();
        }
        AsyncReply::Ready(Ok(communities)) => {
            if communities.is_empty() {
                ui.label("No communities imported yet.");
            } else {
                egui::Grid::new("communities_grid")
                    .striped(true)
                    .min_col_width(80.0)
                    .show(ui, |ui| {
                        ui.strong("Name");
                        ui.strong("ID");
                        ui.strong("Members");
                        ui.end_row();

                        for info in communities {
                            ui.label(&info.name);
                            let short_id = hex_encode(&info.id.0);
                            let display = short_id.get(..16).unwrap_or(&short_id);
                            ui.monospace(display);
                            ui.label(format!("{}", info.member_count));
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
        AsyncReply::Idle => {}
    }
}

// ── Async Helpers ──────────────────────────────────────────────────────

async fn load_communities_from_disk(
    vault_path: &std::path::Path,
) -> Result<Vec<CommunityInfo>, String> {
    let communities_dir = vault_path.join("communities");
    if !communities_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = tokio::fs::read_dir(&communities_dir)
        .await
        .map_err(|e| format!("Failed to read communities dir: {e}"))?;

    let mut result = Vec::new();

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }

        let bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(_) => continue,
        };

        if let Ok(community) = postcard::from_bytes::<Community>(&bytes) {
            result.push(CommunityInfo {
                id: community.fingerprint,
                name: community.name.to_string(),
                member_count: community.members.len(),
            });
        }
    }

    Ok(result)
}

async fn import_community(
    vault_path: &std::path::Path,
    source_path: &std::path::Path,
    community_tx: &tokio::sync::mpsc::Sender<CommunityCommand>,
) -> Result<String, String> {
    let bytes = tokio::fs::read(source_path)
        .await
        .map_err(|e| format!("Failed to read file: {e}"))?;

    let community: Community = postcard::from_bytes(&bytes)
        .map_err(|e| format!("Failed to deserialize community: {e}"))?;

    let name = community.name.to_string();
    let id = community.fingerprint;

    // Write to disk for persistence
    let communities_dir = vault_path.join("communities");
    tokio::fs::create_dir_all(&communities_dir)
        .await
        .map_err(|e| format!("Failed to create communities dir: {e}"))?;

    let out_path = communities_dir.join(format!("{}.community.bin", hex_encode(&id.0)));
    tokio::fs::write(&out_path, &bytes)
        .await
        .map_err(|e| format!("Failed to write community file: {e}"))?;

    // Send to live actor for routing
    let (tx, rx) = oneshot::channel();
    community_tx
        .try_send(CommunityCommand::Import {
            community,
            reply_to: tx,
        })
        .map_err(|_| "Community actor channel full".to_string())?;

    match rx.await {
        Ok(Ok(_)) => Ok(format!("Imported: {name}")),
        Ok(Err(e)) => Err(format!("Import rejected: {e}")),
        Err(_) => Err("Community actor did not reply".into()),
    }
}
