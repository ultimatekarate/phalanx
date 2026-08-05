// crates/phalanx-stronghold/src/gui/panels/corroborate.rs
//
// Corroboration workflow: select community → select recordings → add grants
// → run Corroboration Gate → display proof results.
//
// Calls ops::corroborate::run_corroboration() on the tokio runtime.

use eframe::egui;
use phalanx_proto::community::CommunityId;

use crate::gui::bridge::DaemonBridge;
use crate::gui::state::{AsyncReply, CorroborateState, RecordingSummary};
use crate::gui::widgets::hex_encode;
use crate::persistence::evidence_store::EvidenceStore;

pub fn render(
    ui: &mut egui::Ui,
    _ctx: &egui::Context,
    bridge: &DaemonBridge,
    state: &mut CorroborateState,
) {
    ui.heading("Corroborate");
    ui.add_space(8.0);

    // ── Step 1: Community selector ─────────────────────────────────────
    render_community_selector(ui, bridge, state);

    // ── Step 2: Recording selection ────────────────────────────────────
    if state.selected_community.is_some() {
        ui.add_space(12.0);
        render_recording_selector(ui, bridge, state);
    }

    // ── Step 3: Grant files ────────────────────────────────────────────
    ui.add_space(12.0);
    render_grant_selector(ui, state);

    // ── Step 4: Run button ─────────────────────────────────────────────
    ui.add_space(12.0);
    render_run_button(ui, bridge, state);

    // ── Step 5: Results ────────────────────────────────────────────────
    ui.add_space(12.0);
    render_results(ui, state);
}

fn render_community_selector(
    ui: &mut egui::Ui,
    bridge: &DaemonBridge,
    state: &mut CorroborateState,
) {
    ui.label("Step 1: Select Community");
    let current_label = state
        .selected_community
        .as_ref()
        .map(|(_, name)| name.as_str())
        .unwrap_or("Select...");

    egui::ComboBox::from_id_salt("corroborate_community")
        .selected_text(current_label)
        .show_ui(ui, |ui| {
            // Load communities from disk inline — cheap scan
            let communities_dir = bridge.vault_path.join("communities");
            if let Ok(entries) = std::fs::read_dir(&communities_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                        continue;
                    }
                    if let Ok(bytes) = std::fs::read(&path) {
                        // Wrapped envelope on disk — strip the version byte
                        // before postcard decode. Silently skip malformed files.
                        if let Ok(body) = phalanx_forensics::identity::strip_payload_version(&bytes)
                        {
                            if let Ok(community) =
                                postcard::from_bytes::<phalanx_proto::community::Community>(body)
                            {
                                let name = community.name.to_string();
                                let id = community.fingerprint;
                                if ui
                                    .selectable_label(
                                        state.selected_community.as_ref().map(|(i, _)| i)
                                            == Some(&id),
                                        &name,
                                    )
                                    .clicked()
                                {
                                    state.selected_community = Some((id, name));
                                    state.available_recordings = AsyncReply::Idle;
                                    state.selected_recording_indices.clear();
                                    state.result = AsyncReply::Idle;
                                }
                            }
                        }
                    }
                }
            }
        });
}

fn render_recording_selector(
    ui: &mut egui::Ui,
    bridge: &DaemonBridge,
    state: &mut CorroborateState,
) {
    ui.label("Step 2: Select Recordings (minimum 2)");

    // Auto-load recordings when idle
    if let (Some((cid, _)), AsyncReply::Idle) =
        (&state.selected_community, &state.available_recordings)
    {
        let vault_path = bridge.vault_path.clone();
        let community_id = *cid;
        let (tx, rx) = oneshot::channel();
        bridge.runtime.spawn(async move {
            let result = load_summaries(&vault_path, &community_id).await;
            let _ = tx.send(result);
        });
        state.available_recordings = AsyncReply::pending(rx);
    }

    match &state.available_recordings {
        AsyncReply::Pending { .. } => {
            ui.spinner();
        }
        AsyncReply::Ready(Ok(recordings)) => {
            // Ensure selection vector matches recording count
            if state.selected_recording_indices.len() != recordings.len() {
                state.selected_recording_indices = vec![false; recordings.len()];
            }

            for (i, rec) in recordings.iter().enumerate() {
                if let Some(checked) = state.selected_recording_indices.get_mut(i) {
                    let status = if rec.is_complete { "complete" } else { "gaps" };
                    let label = format!(
                        "{} — {} artifacts, {}",
                        rec.id.as_str(),
                        rec.artifact_count,
                        status
                    );
                    ui.checkbox(checked, label);
                }
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

fn render_grant_selector(ui: &mut egui::Ui, state: &mut CorroborateState) {
    ui.label("Step 3: Grant Files");

    if ui.button("Add Grant Files").clicked() {
        let picked = rfd::FileDialog::new()
            .add_filter("Grant", &["bin"])
            .set_title("Select grant files")
            .pick_files();

        if let Some(files) = picked {
            for f in files {
                if !state.grant_paths.contains(&f) {
                    state.grant_paths.push(f);
                }
            }
        }
    }

    // Display selected grants with remove buttons
    let mut to_remove = None;
    for (i, path) in state.grant_paths.iter().enumerate() {
        ui.horizontal(|ui| {
            if ui.small_button("x").clicked() {
                to_remove = Some(i);
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                ui.monospace(name);
            } else {
                ui.monospace(path.display().to_string());
            }
        });
    }
    if let Some(i) = to_remove {
        state.grant_paths.remove(i);
    }
}

#[allow(clippy::arithmetic_side_effects)] // selected_count: count of true booleans, bounded by vec length
fn render_run_button(ui: &mut egui::Ui, bridge: &DaemonBridge, state: &mut CorroborateState) {
    let selected_count = state
        .selected_recording_indices
        .iter()
        .filter(|&&v| v)
        .count();
    let can_run = state.selected_community.is_some()
        && selected_count >= 2
        && !state.grant_paths.is_empty()
        && !state.result.is_pending();

    ui.add_enabled_ui(can_run, |ui| {
        if ui.button("Run Corroboration Gate").clicked() {
            // Collect selected recording IDs
            if let AsyncReply::Ready(Ok(recordings)) = &state.available_recordings {
                let selected_ids: Vec<_> = recordings
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| {
                        state
                            .selected_recording_indices
                            .get(*i)
                            .copied()
                            .unwrap_or(false)
                    })
                    .map(|(_, rec)| rec.id.clone())
                    .collect();

                if let Some((cid, _)) = &state.selected_community {
                    let community_id = *cid;
                    let identity = bridge.identity.clone();
                    let config = bridge.config.clone();
                    let vault_path = bridge.vault_path.clone();
                    let grant_paths = state.grant_paths.clone();
                    let recording_ids = selected_ids;

                    let (tx, rx) = oneshot::channel();
                    bridge.runtime.spawn(async move {
                        let evidence_store = EvidenceStore::new(vault_path.clone());
                        let proof_store =
                            crate::persistence::proof_store::ProofStore::new(vault_path);
                        let result = crate::ops::corroborate::run_corroboration(
                            &identity,
                            &evidence_store,
                            &proof_store,
                            &config.corroboration,
                            &community_id,
                            &grant_paths,
                            &recording_ids,
                        )
                        .await
                        .map_err(|e| format!("{e}"));
                        let _ = tx.send(result);
                    });
                    state.result = AsyncReply::pending(rx);
                }
            }
        }
    });

    if state.result.is_pending() {
        ui.spinner();
        ui.label("Running corroboration...");
    }
}

fn render_results(ui: &mut egui::Ui, state: &CorroborateState) {
    match &state.result {
        AsyncReply::Ready(Ok(proof)) => {
            ui.separator();
            ui.heading("Corroboration Proof");
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Proof Hash:");
                ui.monospace(hex_encode(&proof.proof_hash));
            });
            ui.horizontal(|ui| {
                ui.label("Producer:");
                ui.monospace(proof.producer_did.to_string());
            });

            ui.add_space(8.0);

            // Attestations
            ui.collapsing(
                format!("Attestations ({})", proof.attestations.len()),
                |ui| {
                    egui::Grid::new("attestation_grid")
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong("Device DID");
                            ui.strong("Recording");
                            ui.strong("Frames");
                            ui.strong("PRNU mean");
                            ui.end_row();

                            for att in &proof.attestations {
                                let did_str = att.did.to_string();
                                let short = did_str.get(..20).unwrap_or(&did_str);
                                ui.monospace(short);
                                ui.monospace(att.recording_id.as_str());
                                ui.label(format!("{}", att.frame_count));
                                ui.label(format!("{:.4}", att.prnu_profile.mean_prnu_var));
                                ui.end_row();
                            }
                        });
                },
            );

            // Divergences
            ui.collapsing(
                format!("Sensor Divergences ({})", proof.divergences.len()),
                |ui| {
                    egui::Grid::new("divergence_grid")
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong("Device A");
                            ui.strong("Device B");
                            ui.strong("KS Stat");
                            ui.strong("p-value");
                            ui.end_row();

                            for div in &proof.divergences {
                                let a_str = div.device_a.to_string();
                                let b_str = div.device_b.to_string();
                                ui.monospace(a_str.get(..16).unwrap_or(&a_str));
                                ui.monospace(b_str.get(..16).unwrap_or(&b_str));
                                ui.label(format!("{:.4}", div.ks_statistic));
                                ui.label(format!("{:.6}", div.p_value));
                                ui.end_row();
                            }
                        });
                },
            );
        }
        AsyncReply::Ready(Err(msg)) => {
            ui.separator();
            ui.colored_label(egui::Color32::RED, format!("Corroboration failed: {msg}"));
        }
        AsyncReply::Error(msg) => {
            ui.separator();
            ui.colored_label(egui::Color32::RED, msg);
        }
        _ => {}
    }
}

/// Same pattern as recordings panel — lightweight summaries only.
async fn load_summaries(
    vault_path: &std::path::Path,
    community_id: &CommunityId,
) -> Result<Vec<RecordingSummary>, String> {
    let store = EvidenceStore::new(vault_path.to_path_buf());
    let ids = store
        .list_recordings(community_id)
        .await
        .map_err(|e| format!("{e}"))?;

    let mut out = Vec::with_capacity(ids.len());
    for rid in &ids {
        match store.read_recording(community_id, rid).await {
            Ok(rec) => {
                out.push(RecordingSummary {
                    id: rec.id,
                    owner_did: rec.owner_did.to_string(),
                    artifact_count: rec.artifacts.len(),
                    is_complete: rec.is_complete,
                });
            }
            Err(e) => {
                out.push(RecordingSummary {
                    id: rid.clone(),
                    owner_did: "?".into(),
                    artifact_count: 0,
                    is_complete: false,
                });
                tracing::warn!(recording = %rid, error = %e, "Failed to read recording");
            }
        }
    }
    Ok(out)
}
