// crates/phalanx-stronghold/src/gui/panels/communities.rs
//
// Community roster panel: list communities from disk, import via file dialog,
// drill into a detail view with member table + Dissolve button.
//
// On import, writes to disk AND sends Import command to the live
// CommunityActor so the routing table updates immediately.
//
// Hands layer — presentation + bridge dispatch. Verification, projection,
// and zeroize are owned by `CommunityActor` (Sentence) and the
// `verify_community_vouches` Verb.

use std::time::{SystemTime, UNIX_EPOCH};

use eframe::egui;
use phalanx_proto::community::{Community, CommunityId, CommunityRoster};

use crate::actors::community::CommunityCommand;
use crate::gui::bridge::DaemonBridge;
use crate::gui::state::{AsyncReply, CommunitiesState, CommunityInfo};
use crate::gui::widgets::hex_encode;

// ── Entry Point ────────────────────────────────────────────────────────

pub fn render(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    bridge: &DaemonBridge,
    state: &mut CommunitiesState,
) {
    // Refresh list after a successful Dissolve — one-shot transition
    // from Ready(Ok) to Idle plus a fresh fetch.
    if let Some(Ok(())) = state.dissolve_result.as_ready() {
        state.dissolve_result = AsyncReply::Idle;
        state.selected = None;
        spawn_list_refresh(bridge, state);
    }

    if state.selected.is_some() {
        render_detail(ui, ctx, bridge, state);
    } else {
        render_list(ui, ctx, bridge, state);
    }
}

// ── List View ──────────────────────────────────────────────────────────

fn render_list(
    ui: &mut egui::Ui,
    _ctx: &egui::Context,
    bridge: &DaemonBridge,
    state: &mut CommunitiesState,
) {
    ui.heading("Communities");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if ui.button("Refresh").clicked() {
            spawn_list_refresh(bridge, state);
        }

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
                state.import_result = AsyncReply::pending(rx);
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
        spawn_list_refresh(bridge, state);
    }

    // Display communities table. Each row is a clickable button that
    // selects the community and kicks off a GetDetail fetch.
    match &state.communities {
        AsyncReply::Pending { .. } => {
            ui.spinner();
        }
        AsyncReply::Ready(Ok(communities)) => {
            if communities.is_empty() {
                ui.label("No communities imported yet.");
            } else {
                let mut click_target: Option<CommunityId> = None;
                egui::Grid::new("communities_grid")
                    .striped(true)
                    .min_col_width(80.0)
                    .show(ui, |ui| {
                        ui.strong("Name");
                        ui.strong("ID");
                        ui.strong("Members");
                        ui.end_row();

                        for info in communities {
                            // Clickable name button — opens detail.
                            if ui.button(&info.name).clicked() {
                                click_target = Some(info.id);
                            }
                            let short_id = hex_encode(&info.id.0);
                            let display = short_id.get(..16).unwrap_or(&short_id);
                            ui.monospace(display);
                            ui.label(format!("{}", info.member_count));
                            ui.end_row();
                        }
                    });

                if let Some(id) = click_target {
                    state.selected = Some(id);
                    spawn_detail_fetch(bridge, state, id);
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

// ── Detail View ────────────────────────────────────────────────────────

fn render_detail(
    ui: &mut egui::Ui,
    _ctx: &egui::Context,
    bridge: &DaemonBridge,
    state: &mut CommunitiesState,
) {
    ui.horizontal(|ui| {
        if ui.button("< Back").clicked() {
            state.selected = None;
            state.detail = AsyncReply::Idle;
            state.dissolve_result = AsyncReply::Idle;
        }
        ui.heading("Community Detail");
    });
    ui.add_space(8.0);

    match &state.detail {
        AsyncReply::Pending { .. } => {
            ui.spinner();
        }
        AsyncReply::Ready(Some(roster)) => {
            render_roster(ui, bridge, state, roster.clone());
        }
        AsyncReply::Ready(None) => {
            ui.colored_label(
                egui::Color32::YELLOW,
                "Community not found in live roster — it may have been dissolved.",
            );
            if ui.button("Return to list").clicked() {
                state.selected = None;
                state.detail = AsyncReply::Idle;
            }
        }
        AsyncReply::Error(msg) => {
            ui.colored_label(egui::Color32::RED, msg);
        }
        AsyncReply::Idle => {
            // Detail not yet requested — shouldn't happen in normal flow,
            // but cover the case defensively.
            ui.label("Loading...");
        }
    }

    // Dissolve error (success already triggers list refresh in `render`)
    if let Some(Err(msg)) = state.dissolve_result.as_ready() {
        ui.add_space(8.0);
        ui.colored_label(egui::Color32::RED, msg);
    }
    if let Some(msg) = state.dissolve_result.as_error() {
        ui.add_space(8.0);
        ui.colored_label(egui::Color32::RED, msg);
    }
}

fn render_roster(
    ui: &mut egui::Ui,
    bridge: &DaemonBridge,
    state: &mut CommunitiesState,
    roster: CommunityRoster,
) {
    // Header block: name + expiration badge.
    ui.horizontal(|ui| {
        ui.strong(roster.summary.name.as_str());
        ui.add_space(8.0);
        let (color, text) = expiration_badge(roster.summary.expires_at);
        ui.colored_label(color, text);
    });
    ui.add_space(4.0);

    // ID, quorum.
    let id_hex = hex_encode(&roster.summary.id.0);
    ui.label(format!("ID: {id_hex}"));
    ui.label(format!(
        "Quorum: {}/{}",
        roster.summary.quorum.value(),
        roster.summary.member_count
    ));
    if let Some(stronghold_did) = &roster.stronghold_did {
        ui.label(format!("Stronghold DID: {}", stronghold_did.as_str()));
    }

    ui.add_space(8.0);
    ui.strong("Members");
    ui.add_space(4.0);

    egui::Grid::new("community_detail_members")
        .striped(true)
        .min_col_width(120.0)
        .show(ui, |ui| {
            ui.strong("DID");
            ui.strong("Vouches");
            ui.strong("Joined");
            ui.end_row();

            for member in &roster.members {
                ui.monospace(truncate_did(member.did.as_str()));
                ui.label(format!("{}", member.vouch_count));
                ui.label(format_timestamp_short(member.joined_at));
                ui.end_row();
            }
        });

    ui.add_space(12.0);

    let is_dissolving = state.dissolve_result.is_pending();
    ui.horizontal(|ui| {
        let btn = egui::Button::new(
            egui::RichText::new("Dissolve community")
                .color(egui::Color32::WHITE)
                .strong(),
        )
        .fill(egui::Color32::from_rgb(180, 40, 40));
        let resp = ui.add_enabled(!is_dissolving, btn);
        if resp.clicked() {
            spawn_dissolve(bridge, state, roster.summary.id);
        }
        if is_dissolving {
            ui.spinner();
            ui.label("Dissolving...");
        }
    });
    ui.add_space(4.0);
    ui.small("Dissolve zeroizes roster material and removes the community from the routing table.");
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Map the expiration timestamp to a badge color + label.
/// Boundaries match the plan spec: green >7d, amber <7d, red expired.
#[allow(clippy::cast_possible_truncation)] // Epoch millis fit in u64 for centuries.
fn expiration_badge(expires_at: phalanx_proto::time::PhalanxTimestamp) -> (egui::Color32, String) {
    const DAY_MS: u64 = 86_400_000;
    const SEVEN_DAYS_MS: u64 = 7 * DAY_MS;

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let expires_ms = expires_at.0;

    if expires_ms <= now_ms {
        (egui::Color32::RED, "EXPIRED".to_owned())
    } else {
        let remaining_ms = expires_ms.saturating_sub(now_ms);
        let days = remaining_ms / DAY_MS;
        if remaining_ms < SEVEN_DAYS_MS {
            (
                egui::Color32::from_rgb(220, 160, 0),
                format!("expires in {days}d"),
            )
        } else {
            (egui::Color32::GREEN, format!("expires in {days}d"))
        }
    }
}

/// Render a `PhalanxTimestamp` (epoch millis) as a short UTC string.
/// Not RFC-3339 — just enough to be useful in a roster row.
fn format_timestamp_short(ts: phalanx_proto::time::PhalanxTimestamp) -> String {
    // Epoch seconds fit in i64 for billions of years — fall back to 0 on overflow.
    let secs = i64::try_from(ts.0 / 1000).unwrap_or(0);
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "-".to_owned())
}

/// Truncate a DID string to `did:key:z...xxxx` for table display.
fn truncate_did(did: &str) -> String {
    if did.len() <= 24 {
        return did.to_owned();
    }
    let prefix = did.get(..16).unwrap_or(did);
    let suffix = did.get(did.len().saturating_sub(6)..).unwrap_or("");
    format!("{prefix}...{suffix}")
}

/// Kick off an async list refresh. Mutates `state.communities` to Pending.
fn spawn_list_refresh(bridge: &DaemonBridge, state: &mut CommunitiesState) {
    let vault_path = bridge.vault_path.clone();
    let (tx, rx) = oneshot::channel();
    bridge.runtime.spawn(async move {
        let result = load_communities_from_disk(&vault_path).await;
        let _ = tx.send(result);
    });
    state.communities = AsyncReply::pending(rx);
}

/// Kick off a detail fetch via the live actor. Mutates `state.detail`.
fn spawn_detail_fetch(bridge: &DaemonBridge, state: &mut CommunitiesState, id: CommunityId) {
    let community_tx = bridge.community_tx.clone();
    let (outer_tx, outer_rx) = oneshot::channel();
    bridge.runtime.spawn(async move {
        let (inner_tx, inner_rx) = oneshot::channel();
        if community_tx
            .send(CommunityCommand::GetDetail {
                community_id: id,
                reply_to: inner_tx,
            })
            .await
            .is_err()
        {
            let _ = outer_tx.send(None);
            return;
        }
        let _ = outer_tx.send(inner_rx.await.unwrap_or(None));
    });
    state.detail = AsyncReply::pending(outer_rx);
}

/// Kick off a Dissolve via the live actor. Mutates `state.dissolve_result`.
/// On success, `render` clears selection and refreshes the list.
fn spawn_dissolve(bridge: &DaemonBridge, state: &mut CommunitiesState, id: CommunityId) {
    let community_tx = bridge.community_tx.clone();
    let vault_path = bridge.vault_path.clone();
    let (outer_tx, outer_rx) = oneshot::channel();
    bridge.runtime.spawn(async move {
        let (inner_tx, inner_rx) = oneshot::channel();
        if community_tx
            .send(CommunityCommand::Dissolve {
                community_id: id,
                reply_to: inner_tx,
            })
            .await
            .is_err()
        {
            let _ = outer_tx.send(Err("Community actor channel closed".to_owned()));
            return;
        }
        match inner_rx.await {
            Ok(Ok(())) => {
                // Also remove the on-disk roster so it doesn't get
                // auto-re-imported next launch.
                let file_name = format!("{}.community.bin", hex_encode(&id.0));
                let file_path = vault_path.join("communities").join(file_name);
                if let Err(e) = tokio::fs::remove_file(&file_path).await {
                    // File-missing is benign — dissolve still succeeds
                    // from a user-visible perspective.
                    if e.kind() != std::io::ErrorKind::NotFound {
                        let _ =
                            outer_tx.send(Err(format!("Dissolved, but disk cleanup failed: {e}")));
                        return;
                    }
                }
                let _ = outer_tx.send(Ok(()));
            }
            Ok(Err(e)) => {
                let _ = outer_tx.send(Err(format!("Dissolve rejected: {e}")));
            }
            Err(_) => {
                let _ = outer_tx.send(Err("Community actor did not reply".to_owned()));
            }
        }
    });
    state.dissolve_result = AsyncReply::pending(outer_rx);
}

// ── Async Helpers (disk I/O) ───────────────────────────────────────────

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

        // Files on disk are wrapped envelopes (see `cmd_import_community`).
        // Silently skip any file whose envelope version is unknown.
        let body = match phalanx_forensics::identity::strip_payload_version(&bytes) {
            Ok(b) => b,
            Err(_) => continue,
        };

        if let Ok(community) = postcard::from_bytes::<Community>(body) {
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

    // The picked file is a wrapped envelope produced by `cmd_create_community`.
    // Strip the version byte before postcard decode; persist the wrapped form.
    let body = phalanx_forensics::identity::strip_payload_version(&bytes)
        .map_err(|e| format!("Community envelope rejected: {e}"))?;

    let community: Community =
        postcard::from_bytes(body).map_err(|e| format!("Failed to deserialize community: {e}"))?;

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
