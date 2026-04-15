// crates/phalanx-stronghold/src/gui/panels/export.rs
//
// Export workflow: select community → list proofs → select proof → add grants
// → choose output dir → export → display results.
//
// Calls ops::export::run_export() on the tokio runtime.

use eframe::egui;

use crate::gui::bridge::DaemonBridge;
use crate::gui::state::{AsyncReply, ExportState};
use crate::gui::widgets::short_hex;
use crate::persistence::proof_store::ProofStore;

pub fn render(
    ui: &mut egui::Ui,
    _ctx: &egui::Context,
    bridge: &DaemonBridge,
    state: &mut ExportState,
) {
    ui.heading("Export");
    ui.add_space(8.0);

    // ── Step 1: Community selector ─────────────────────────────────────
    ui.label("Step 1: Select Community");
    let current_label = state
        .selected_community
        .as_ref()
        .map(|(_, name)| name.as_str())
        .unwrap_or("Select...");

    egui::ComboBox::from_id_salt("export_community")
        .selected_text(current_label)
        .show_ui(ui, |ui| {
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
                                    state.proof_list = AsyncReply::Idle;
                                    state.selected_proof = None;
                                    state.result = AsyncReply::Idle;
                                }
                            }
                        }
                    }
                }
            }
        });

    // ── Step 2: List and select proof ──────────────────────────────────
    if state.selected_community.is_some() {
        ui.add_space(12.0);
        ui.label("Step 2: Select Proof");

        // Auto-load proofs when idle
        if let (Some((cid, _)), AsyncReply::Idle) = (&state.selected_community, &state.proof_list) {
            let vault_path = bridge.vault_path.clone();
            let community_id = *cid;
            let (tx, rx) = oneshot::channel();
            bridge.runtime.spawn(async move {
                let store = ProofStore::new(vault_path);
                let result = store
                    .list_proofs(&community_id)
                    .await
                    .map_err(|e| format!("{e}"));
                let _ = tx.send(result);
            });
            state.proof_list = AsyncReply::pending(rx);
        }

        match &state.proof_list {
            AsyncReply::Pending { .. } => {
                ui.spinner();
            }
            AsyncReply::Ready(Ok(proofs)) => {
                if proofs.is_empty() {
                    ui.label("No proofs found. Run corroboration first.");
                } else {
                    for hash in proofs {
                        let is_selected = state.selected_proof.as_ref() == Some(hash);
                        let label = short_hex(hash);
                        if ui.selectable_label(is_selected, &label).clicked() {
                            state.selected_proof = Some(*hash);
                        }
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

    // ── Step 3: Grant files ────────────────────────────────────────────
    ui.add_space(12.0);
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

    // ── Step 4: Output directory ───────────────────────────────────────
    ui.add_space(12.0);
    ui.label("Step 4: Output Directory");

    ui.horizontal(|ui| {
        if ui.button("Select Output Dir").clicked() {
            let picked = rfd::FileDialog::new()
                .set_title("Select export output directory")
                .pick_folder();
            if let Some(dir) = picked {
                state.output_dir = Some(dir);
            }
        }
        if let Some(dir) = &state.output_dir {
            ui.monospace(dir.display().to_string());
        }
    });

    // ── Step 5: Export button ──────────────────────────────────────────
    ui.add_space(12.0);

    let can_export = state.selected_community.is_some()
        && state.selected_proof.is_some()
        && !state.grant_paths.is_empty()
        && state.output_dir.is_some()
        && !state.result.is_pending();

    ui.add_enabled_ui(can_export, |ui| {
        if ui.button("Export Proof").clicked() {
            if let (Some((cid, _)), Some(proof_hash), Some(output_dir)) = (
                &state.selected_community,
                &state.selected_proof,
                &state.output_dir,
            ) {
                let community_id = *cid;
                let proof_hash = *proof_hash;
                let identity = bridge.identity.clone();
                let config = bridge.config.clone();
                let vault_path = bridge.vault_path.clone();
                let grant_paths = state.grant_paths.clone();
                let output_dir = output_dir.clone();

                let (tx, rx) = oneshot::channel();
                // run_export produces a !Send future (c2pa::Signer is !Send).
                // Run on a dedicated thread with its own single-threaded runtime.
                std::thread::spawn(move || {
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            let _ = tx.send(Err(format!("Runtime error: {e}")));
                            return;
                        }
                    };
                    let result = rt.block_on(async {
                        let evidence_store = crate::persistence::evidence_store::EvidenceStore::new(
                            vault_path.clone(),
                        );
                        let proof_store = ProofStore::new(vault_path);
                        crate::ops::export::run_export(
                            &identity,
                            &evidence_store,
                            &proof_store,
                            &config.corroboration,
                            &community_id,
                            &proof_hash,
                            &grant_paths,
                            &output_dir,
                        )
                        .await
                        .map_err(|e| format!("{e}"))
                    });
                    let _ = tx.send(result);
                });
                state.result = AsyncReply::pending(rx);
            }
        }
    });

    if state.result.is_pending() {
        ui.spinner();
        ui.label("Exporting...");
    }

    // ── Results ────────────────────────────────────────────────────────
    match &state.result {
        AsyncReply::Ready(Ok(paths)) => {
            ui.add_space(8.0);
            ui.separator();
            ui.colored_label(
                egui::Color32::GREEN,
                format!("Export complete: {} file(s)", paths.len()),
            );
            for path in paths {
                ui.monospace(path.display().to_string());
            }
        }
        AsyncReply::Ready(Err(msg)) => {
            ui.add_space(8.0);
            ui.separator();
            ui.colored_label(egui::Color32::RED, format!("Export failed: {msg}"));
        }
        AsyncReply::Error(msg) => {
            ui.add_space(8.0);
            ui.colored_label(egui::Color32::RED, msg);
        }
        _ => {}
    }
}
