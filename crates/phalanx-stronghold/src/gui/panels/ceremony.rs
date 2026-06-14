// crates/phalanx-stronghold/src/gui/panels/ceremony.rs
//
// Ceremony panel — Stronghold-side initiator UI for Trusted Community
// creation (Phase 7.B.4). The Stronghold is the coordinator; vouchers
// sign on their phones. See `linguistic-code-model.md` §VIII and the
// `cached-wibbling-dove.md` plan for the full architecture.
//
// Hands layer — rendering + runtime task spawning only. All validation
// and signature work lives in `phalanx-forensics` (Laboratory); actor
// dispatch lives in `phalanx-stronghold::actors::community`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use eframe::egui;
use phalanx_forensics::identity::{
    CommunityAssemblyParams, MAX_EXPIRES_SECS, QR_PAYLOAD_BUDGET_BYTES, strip_vouch_response,
    wrap_payload_version, wrap_vouch_request,
};
use phalanx_proto::community::{
    CeremonyMember, CeremonyNonce, Community, CommunityGrants, CommunityId, Quorum, Vouch,
    VouchRequest, VouchResponse,
};
use phalanx_proto::identity::Did;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::trust::{PetName, TrustLevel};

use crate::actors::community::CommunityCommand;
use crate::gui::bridge::DaemonBridge;
use crate::gui::state::{AsyncReply, CeremonyPanelState, CeremonyStage, ConfigureForm};

// ── Ceremony UX constants ───────────────────────────────────────────────

/// Default community lifetime when the organizer does not override —
/// 30 days, the `MAX_EXPIRES_SECS` ceiling. Good for a demo; operators
/// can shorten later once an expiry picker ships.
const DEFAULT_EXPIRES_SECS: u64 = MAX_EXPIRES_SECS;

/// Conservative per-vouch byte budget for the QR-payload preflight. A
/// single serialized `Vouch` is ~96 B in practice; we round up for
/// envelope overhead. This governs only the preflight warning — the
/// authoritative budget check lives in `assemble_community`.
const VOUCH_BYTES_ESTIMATE: usize = 128;

/// Fixed baseline overhead for the community envelope (fingerprint,
/// name, grants, expires_at, etc.). Empirically ~200 B; we round up
/// for safety. Combined with per-vouch and per-member estimates, this
/// is enough to catch obvious over-budget rosters before the organizer
/// commits to issuing request QRs.
const PAYLOAD_OVERHEAD_ESTIMATE: usize = 256;

/// Per-member envelope overhead in the serialized Community (DID +
/// joined_at + vouches vec header).
const PER_MEMBER_BYTES_ESTIMATE: usize = 80;

// ── Entry ───────────────────────────────────────────────────────────────

/// Top-level render. Dispatches by `state.stage`. Every per-frame task
/// is routed through `bridge.runtime.spawn` so the egui thread never
/// blocks on IO — this is non-negotiable for a narrated live demo.
pub fn render(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    bridge: &DaemonBridge,
    state: &mut CeremonyPanelState,
) {
    ui.heading("Trusted Community Ceremony");
    ui.label(
        "Configure a community, collect vouches from members' phones, \
         then share the join QR.",
    );
    ui.separator();

    // Absorb async replies that landed since the previous frame. Done
    // before dispatch so the active stage sees the updated state.
    drain_replies(state);

    match &state.stage {
        CeremonyStage::Configure => render_configure(ui, bridge, state),
        CeremonyStage::CollectingVouches { .. } => render_collecting(ui, ctx, bridge, state),
        CeremonyStage::Ready { .. } => render_ready(ui, ctx, state),
        CeremonyStage::Cancelled { .. } => render_cancelled(ui, state),
    }

    if let Some(toast) = &state.toast {
        ui.add_space(8.0);
        ui.colored_label(egui::Color32::LIGHT_BLUE, toast);
    }
}

/// Absorb any `AsyncReply::Ready` outcomes that landed last frame and
/// mutate the stage accordingly. Keeps each render-fn focused on
/// drawing rather than re-entrancy bookkeeping.
fn drain_replies(state: &mut CeremonyPanelState) {
    // Assemble reply → transition CollectingVouches → Ready (or toast on error).
    if let AsyncReply::Ready(result) = &state.assemble {
        match result {
            Ok((_id, community)) => {
                let (qr_image, join_uri) = build_join_surface(community);
                state.stage = CeremonyStage::Ready {
                    community: community.clone(),
                    qr_image,
                    qr_texture: None,
                    join_uri,
                };
                state.toast = Some("Community assembled.".into());
            }
            Err(msg) => {
                state.toast = Some(format!("Assembly failed: {msg}"));
            }
        }
        state.assemble = AsyncReply::Idle;
    }

    // Verified import reply → insert into responses map. Dedup check is
    // eager (panel-side) in `spawn_import_response`; here we trust the
    // incoming pair.
    if let AsyncReply::Ready(result) = &state.import {
        match result.clone() {
            Ok((request_id, response)) => {
                if let CeremonyStage::CollectingVouches { responses, .. } = &mut state.stage {
                    responses.insert(request_id, response);
                    state.toast = Some("Response imported and verified.".into());
                }
            }
            Err(msg) => {
                state.toast = Some(format!("Import failed: {msg}"));
            }
        }
        state.import = AsyncReply::Idle;
    }

    // Export reply → show a confirmation toast.
    if let AsyncReply::Ready(result) = &state.export {
        state.toast = Some(match result {
            Ok(path) => format!("Request exported to {}", path.display()),
            Err(msg) => format!("Export failed: {msg}"),
        });
        state.export = AsyncReply::Idle;
    }
}

// ── Stage: Configure ────────────────────────────────────────────────────

fn render_configure(ui: &mut egui::Ui, bridge: &DaemonBridge, state: &mut CeremonyPanelState) {
    ui.label("Configure");
    ui.add_space(4.0);

    // Show the operator's own DID so they can confirm the coordinator
    // identity before the demo starts. Pulled from the dashboard source.
    ui.horizontal(|ui| {
        ui.label("Coordinator DID:");
        let did = bridge.identity.did.as_str();
        ui.monospace(did);
    });
    ui.add_space(8.0);

    // Name
    ui.horizontal(|ui| {
        ui.label("Community name:");
        ui.text_edit_singleline(&mut state.form.name);
    });

    ui.add_space(8.0);
    ui.label(
        "Member DIDs (one per slot — paste from each phone's \
              'Show my DID' screen):",
    );

    // Existing member list, each row with a remove button.
    let mut remove_idx: Option<usize> = None;
    for (idx, did) in state.form.member_dids.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            ui.label(format!("{}.", idx.saturating_add(1)));
            ui.add(egui::TextEdit::singleline(did).desired_width(480.0));
            if ui.button("✕").on_hover_text("Remove member").clicked() {
                remove_idx = Some(idx);
            }
        });
    }
    if let Some(idx) = remove_idx {
        state.form.member_dids.remove(idx);
        state.form.error = None;
    }

    // Add-member buffer.
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut state.form.new_did_buf)
                .hint_text("did:key:z…")
                .desired_width(480.0),
        );
        let can_add = !state.form.new_did_buf.trim().is_empty();
        if ui
            .add_enabled(can_add, egui::Button::new("+ Add member"))
            .clicked()
        {
            let did = state.form.new_did_buf.trim().to_owned();
            state.form.member_dids.push(did);
            state.form.new_did_buf.clear();
            state.form.error = None;
        }
    });

    // Quorum slider — clamp to [2, N-1] on every frame so deletes reduce
    // the slider automatically.
    ui.add_space(8.0);
    let (min_q, max_q) = quorum_bounds(state.form.member_dids.len());
    let clamped_q = state.form.quorum.clamp(min_q, max_q.max(min_q));
    if clamped_q != state.form.quorum {
        state.form.quorum = clamped_q;
        state.toast = Some(format!(
            "Quorum clamped to {clamped_q} (requires {min_q}–{max_q} for {} members).",
            state.form.member_dids.len(),
        ));
    }
    ui.horizontal(|ui| {
        ui.label("Quorum:");
        ui.add(
            egui::Slider::new(&mut state.form.quorum, min_q..=max_q.max(min_q))
                .text("vouches per member"),
        );
    });

    // QR-budget preflight — orange warning if likely oversized.
    ui.add_space(8.0);
    let projected = project_payload_size(state.form.member_dids.len(), state.form.quorum);
    if projected > QR_PAYLOAD_BUDGET_BYTES {
        ui.colored_label(
            egui::Color32::from_rgb(0xC9, 0x7C, 0x1B),
            format!(
                "Projected payload ~{projected} B exceeds QR budget \
                 ({QR_PAYLOAD_BUDGET_BYTES} B) — assembly will succeed, but the join \
                 QR will be Universal-Link-only.",
            ),
        );
    }

    // Form error.
    if let Some(err) = &state.form.error {
        ui.add_space(8.0);
        ui.colored_label(egui::Color32::RED, err);
    }

    // Start button.
    ui.add_space(12.0);
    let can_start = state.form.member_dids.len() >= 3
        && !state.form.name.trim().is_empty()
        && state.form.quorum >= 2;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(can_start, egui::Button::new("Start ceremony"))
            .on_hover_text(
                "Issue one request QR per (member, voucher) slot. Needs \
                 ≥ 3 members so quorum ≥ 2 is satisfiable without \
                 self-vouching.",
            )
            .clicked()
        {
            match start_ceremony(bridge, &state.form) {
                Ok(started) => {
                    state.stage = started;
                    state.toast = Some(
                        "Ceremony started. Show each request QR to \
                                        the matching voucher."
                            .into(),
                    );
                    state.form.error = None;
                }
                Err(msg) => {
                    state.form.error = Some(msg);
                }
            }
        }
    });
}

/// Compute `[min_q, max_q]` where `max_q = N - 1` under the v1
/// self-contained rule (no self-vouching). The min is always 2 — a
/// 1-vouch community is not trusted.
fn quorum_bounds(member_count: usize) -> (u16, u16) {
    let min = 2u16;
    // saturating: N < 2 is the "no members" case — reports min, UI
    // clamps to min..=min which egui renders as a locked slider.
    let max = u16::try_from(member_count.saturating_sub(1)).unwrap_or(u16::MAX);
    (min, max.max(min))
}

/// Rough projection of the serialized + wrapped community payload
/// size. Used by the Configure preflight only — not authoritative.
fn project_payload_size(member_count: usize, quorum: u16) -> usize {
    let total_vouches = member_count.saturating_mul(quorum.into());
    total_vouches
        .saturating_mul(VOUCH_BYTES_ESTIMATE)
        .saturating_add(member_count.saturating_mul(PER_MEMBER_BYTES_ESTIMATE))
        .saturating_add(PAYLOAD_OVERHEAD_ESTIMATE)
}

/// Validate the Configure form into a `CollectingVouches` stage. Pure
/// with respect to the panel — returns the transition on success, the
/// error message on failure. `stronghold_did` is auto-populated from
/// `bridge.identity.did` (plan 7.B.4 "`stronghold_did` auto-populate").
#[allow(clippy::cast_possible_truncation)] // Epoch millis fit in u64 for centuries.
fn start_ceremony(bridge: &DaemonBridge, form: &ConfigureForm) -> Result<CeremonyStage, String> {
    // Name.
    let name = PetName::new(form.name.trim()).map_err(|e| format!("Name: {e}"))?;

    // Members — parse, dedup, validate non-empty.
    let mut members: Vec<Did> = Vec::with_capacity(form.member_dids.len());
    for (idx, raw) in form.member_dids.iter().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(format!(
                "Member {} is blank — remove or fill in before starting.",
                idx.saturating_add(1),
            ));
        }
        if trimmed.len() > Did::MAX_WIRE_LEN {
            return Err(format!(
                "Member {} DID is longer than {} bytes — paste a valid did:key.",
                idx.saturating_add(1),
                Did::MAX_WIRE_LEN,
            ));
        }
        let did = Did::new(trimmed);
        if members.contains(&did) {
            return Err(format!(
                "Member {} is a duplicate of an earlier member — each DID must be unique.",
                idx.saturating_add(1),
            ));
        }
        members.push(did);
    }
    if members.len() < 3 {
        return Err("Need at least 3 members for quorum ≥ 2 under the self-contained rule.".into());
    }

    // Quorum.
    let quorum_u8 =
        u8::try_from(form.quorum).map_err(|_| "Quorum value out of range".to_owned())?;
    let quorum = Quorum::new(quorum_u8).ok_or_else(|| "Quorum must be ≥ 1".to_owned())?;
    if usize::from(quorum.value()) >= members.len() {
        return Err(format!(
            "Quorum {} is too large — max is {} for {} members (self-vouching forbidden).",
            quorum.value(),
            members.len().saturating_sub(1),
            members.len(),
        ));
    }

    // Timestamps: now (millis), member_joined_at = now, expires_at = now + 30d.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock: {e}"))?
        .as_millis() as u64;
    let now = PhalanxTimestamp::from_millis(now_ms);
    let expires_at = PhalanxTimestamp::from_millis(
        now_ms.saturating_add(DEFAULT_EXPIRES_SECS.saturating_mul(1000)),
    );

    // Tentative fingerprint (what every voucher signs over).
    let tentative = CommunityId::compute(&name, quorum, &members);

    // Fresh per-ceremony entropy. Mixed into every `request_id` so that
    // an aborted-and-restarted ceremony with identical `(name, quorum,
    // members)` produces a *different* dedup key set — the initiator's
    // `responses` map never silently merges across runs. Not signed
    // (the vouch signature already commits to `(member, tentative,
    // joined_at)`, which is stable across restarts); nonce only protects
    // the coordinator's local bookkeeping.
    let ceremony_nonce = CeremonyNonce::random();

    // Self-contained voucher assignment: roster-order wrap, K vouchers per member.
    let requests = build_request_slots(
        &members,
        quorum,
        tentative,
        &ceremony_nonce,
        &name,
        now,
        now,
    );

    // Seed the assembly draft. Members' `vouches` start empty; we
    // repopulate them from `responses` at "Assemble community" time.
    let draft = CommunityAssemblyParams {
        name,
        quorum,
        joined_at: now,
        expires_at,
        stronghold_did: Some(bridge.identity.did.clone()),
        baseline_trust: TrustLevel::Verified,
        grants: CommunityGrants::default(),
        members: members
            .iter()
            .map(|did| CeremonyMember {
                did: did.clone(),
                vouches: Vec::new(),
            })
            .collect(),
    };

    Ok(CeremonyStage::CollectingVouches {
        params_draft: Box::new(draft),
        tentative,
        ceremony_nonce,
        requests,
        responses: HashMap::new(),
        issued_at: now,
        showing_qr_for: None,
    })
}

/// Generate the full `(member, voucher)` slot set under the v1
/// self-contained rule: for each member at index `i`, the `k` vouchers
/// are the members at `i+1, i+2, …, i+k` modulo `n`. Never produces a
/// self-vouch (the caller enforces `k < n`).
///
/// The `%` in the index walk is arithmetic-side-effects-safe because
/// `n == members.len() > 0` is a precondition (`start_ceremony` rejects
/// empty rosters upstream). The suppression keeps the modulo readable
/// rather than forcing a checked wrapper for a mathematical invariant.
#[allow(clippy::arithmetic_side_effects)] // n > 0 enforced by start_ceremony.
fn build_request_slots(
    members: &[Did],
    quorum: Quorum,
    tentative: CommunityId,
    ceremony_nonce: &CeremonyNonce,
    name: &PetName,
    issued_at: PhalanxTimestamp,
    member_joined_at: PhalanxTimestamp,
) -> Vec<VouchRequest> {
    let k = usize::from(quorum.value());
    let n = members.len();
    if n == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(n.saturating_mul(k));
    for (i, member_did) in members.iter().enumerate() {
        for j in 1..=k {
            let voucher_idx = i.wrapping_add(j) % n;
            if voucher_idx == i {
                // Defensive — start_ceremony already rejects k >= n.
                continue;
            }
            let Some(voucher_did) = members.get(voucher_idx) else {
                // Unreachable given n > 0 and voucher_idx < n, but keeps
                // the helper total.
                continue;
            };
            let request_id =
                VouchRequest::compute_id(&tentative, ceremony_nonce, voucher_did, member_did);
            out.push(VouchRequest {
                request_id,
                tentative_fingerprint: tentative,
                ceremony_nonce: *ceremony_nonce,
                name: name.clone(),
                quorum,
                members: members.to_vec(),
                member_did: member_did.clone(),
                voucher_did: voucher_did.clone(),
                issued_at,
                member_joined_at,
            });
        }
    }
    out
}

// ── Stage: CollectingVouches ────────────────────────────────────────────

fn render_collecting(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    bridge: &DaemonBridge,
    state: &mut CeremonyPanelState,
) {
    // Narrow borrow of the CollectingVouches fields so we can mutate
    // assemble / import / export on state without overlapping borrows.
    let (requests_clone, responses_clone, tentative, issued_at) = match &state.stage {
        CeremonyStage::CollectingVouches {
            requests,
            responses,
            tentative,
            issued_at,
            ..
        } => (requests.clone(), responses.clone(), *tentative, *issued_at),
        _ => return,
    };
    let total_slots = requests_clone.len();
    let filled = responses_clone.len();

    ui.horizontal(|ui| {
        ui.label(format!(
            "Collecting vouches: {filled} / {total_slots} signed"
        ));
        ui.separator();
        ui.monospace(format!("Fingerprint: {}", short_hex(&tentative.0)));
    });

    // Progress bar — egui's built-in ProgressBar.
    #[allow(clippy::cast_precision_loss)] // Progress ratio — visible rounding is fine.
    let ratio = if total_slots == 0 {
        0.0
    } else {
        filled as f32 / total_slots as f32
    };
    ui.add(egui::ProgressBar::new(ratio).show_percentage());

    ui.add_space(8.0);

    // Per-slot rows.
    egui::ScrollArea::vertical()
        .max_height(360.0)
        .show(ui, |ui| {
            let mut open_modal_for: Option<[u8; 32]> = None;
            let mut export_for: Option<VouchRequest> = None;
            let mut import_now = false;

            for request in &requests_clone {
                let signed = responses_clone.contains_key(&request.request_id);
                ui.horizontal(|ui| {
                    ui.label(if signed { "✓" } else { "…" });
                    ui.label(format!(
                        "member {} · voucher {}",
                        short_did(&request.member_did),
                        short_did(&request.voucher_did),
                    ));
                    ui.separator();
                    let countdown = freshness_label(issued_at, request.member_joined_at);
                    ui.monospace(countdown);
                    ui.separator();

                    if ui.button("Show QR").clicked() {
                        open_modal_for = Some(request.request_id);
                    }
                    if ui.button("Export request").clicked() {
                        export_for = Some(request.clone());
                    }
                    if !import_now && ui.button("Import response").clicked() {
                        import_now = true;
                    }
                });
            }

            if let Some(id) = open_modal_for {
                if let CeremonyStage::CollectingVouches { showing_qr_for, .. } = &mut state.stage {
                    *showing_qr_for = Some(id);
                }
            }

            if let Some(req) = export_for {
                spawn_export_request(bridge, state, req);
            }

            if import_now {
                spawn_import_response(
                    bridge,
                    state,
                    requests_clone.clone(),
                    responses_clone.clone(),
                );
            }
        });

    ui.add_space(12.0);

    // QR modal — rendered last so it sits above the list.
    let modal_request = match &state.stage {
        CeremonyStage::CollectingVouches {
            showing_qr_for: Some(id),
            requests,
            ..
        } => requests.iter().find(|r| &r.request_id == id).cloned(),
        _ => None,
    };
    if let Some(req) = modal_request {
        render_qr_modal(ctx, state, &req);
    }

    // Footer: Assemble + Cancel.
    ui.horizontal(|ui| {
        let can_assemble = filled == total_slots && total_slots > 0;
        let assemble_pending = matches!(state.assemble, AsyncReply::Pending { .. });
        if ui
            .add_enabled(
                can_assemble && !assemble_pending,
                egui::Button::new("Assemble community"),
            )
            .on_hover_text(
                "Builds the final Community from every verified vouch, imports \
                 it, and renders the join QR on the next frame.",
            )
            .clicked()
        {
            spawn_assemble(bridge, state, &requests_clone, &responses_clone);
        }
        if assemble_pending {
            ui.label("Assembling…");
        }

        if ui.button("Cancel ceremony").clicked() {
            if let CeremonyStage::CollectingVouches { params_draft, .. } =
                std::mem::replace(&mut state.stage, CeremonyStage::Configure)
            {
                state.stage = CeremonyStage::Cancelled {
                    reason: "Cancelled by organizer.".into(),
                    last_draft: params_draft,
                };
            }
        }
    });
}

/// Modal window showing one request QR plus the raw base64url payload
/// so the voucher has both a scan target and a copy fallback.
fn render_qr_modal(ctx: &egui::Context, state: &mut CeremonyPanelState, request: &VouchRequest) {
    let payload_bytes = match postcard::to_allocvec(request) {
        Ok(b) => wrap_vouch_request(&b),
        Err(e) => {
            state.toast = Some(format!("QR render failed: {e}"));
            if let CeremonyStage::CollectingVouches { showing_qr_for, .. } = &mut state.stage {
                *showing_qr_for = None;
            }
            return;
        }
    };
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);

    let mut open = true;
    egui::Window::new("Scan with voucher's phone")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label(format!("Voucher: {}", short_did(&request.voucher_did),));
            ui.label(format!("Signing for: {}", short_did(&request.member_did)));
            ui.separator();

            match build_qr_image(&payload_b64) {
                Some(image) => {
                    let texture = ctx.load_texture(
                        format!("ceremony_qr_{}", short_hex(&request.request_id)),
                        image,
                        egui::TextureOptions::NEAREST,
                    );
                    // 360×360 px displayed; the source is already scaled.
                    ui.image((texture.id(), egui::vec2(360.0, 360.0)));
                }
                None => {
                    ui.colored_label(
                        egui::Color32::RED,
                        "Payload too large for a QR — use 'Export request' instead.",
                    );
                }
            }

            ui.add_space(8.0);
            ui.label("Fallback — copy this string into the voucher's phone:");
            ui.add(
                egui::TextEdit::multiline(&mut payload_b64.as_str())
                    .desired_rows(3)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace),
            );
        });
    if !open {
        if let CeremonyStage::CollectingVouches { showing_qr_for, .. } = &mut state.stage {
            *showing_qr_for = None;
        }
    }
}

/// UX hint showing "(signed JOINED_AT + WINDOW) − now" as a
/// countdown. The authoritative freshness check is on the *signed*
/// `member_joined_at` inside `verify_vouch_response`, so this label is
/// presentation-only.
#[allow(clippy::cast_possible_truncation)]
fn freshness_label(_issued_at: PhalanxTimestamp, member_joined_at: PhalanxTimestamp) -> String {
    use phalanx_proto::community::CEREMONY_RESPONSE_FRESHNESS_SECS;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let deadline_ms = member_joined_at
        .0
        .saturating_add(CEREMONY_RESPONSE_FRESHNESS_SECS.saturating_mul(1000));
    if now_ms >= deadline_ms {
        "issued >1h ago — response may be rejected".into()
    } else {
        let remaining = deadline_ms.saturating_sub(now_ms) / 1000;
        format!("{remaining}s left")
    }
}

// ── Stage: Ready ────────────────────────────────────────────────────────

fn render_ready(ui: &mut egui::Ui, ctx: &egui::Context, state: &mut CeremonyPanelState) {
    ui.label("Community ready — share the join QR with members.");
    ui.add_space(8.0);

    let (qr_image, join_uri, community_name, member_count) = match &state.stage {
        CeremonyStage::Ready {
            qr_image,
            join_uri,
            community,
            ..
        } => (
            qr_image.clone(),
            join_uri.clone(),
            community.name.as_str().to_owned(),
            community.members.len(),
        ),
        _ => return,
    };

    ui.horizontal(|ui| {
        ui.label("Name:");
        ui.monospace(community_name);
    });
    ui.horizontal(|ui| {
        ui.label("Members:");
        ui.label(format!("{member_count}"));
    });
    ui.separator();

    // Lazy-load the QR texture: we hold the ColorImage on the stage and
    // materialize it into a TextureHandle on first render. load_texture
    // returns a cached handle when called with the same name.
    if let Some(image) = qr_image {
        let texture = ensure_ready_texture(ctx, state, image);
        if let Some(tex) = texture {
            ui.image((tex.id(), egui::vec2(420.0, 420.0)));
        }
    } else {
        ui.colored_label(
            egui::Color32::from_rgb(0xC9, 0x7C, 0x1B),
            "Payload exceeds QR capacity — share the Universal Link below.",
        );
    }

    ui.add_space(8.0);
    ui.label("Join URI:");
    ui.add(
        egui::TextEdit::multiline(&mut join_uri.as_str())
            .desired_rows(3)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    if ui.button("Copy URI").clicked() {
        ctx.copy_text(join_uri);
    }

    ui.add_space(12.0);
    if ui.button("Start another ceremony").clicked() {
        state.stage = CeremonyStage::Configure;
        state.form = ConfigureForm::default();
        state.toast = None;
    }
}

/// Load (and cache) the Ready-stage QR texture. Returns a clone of the
/// cached handle since egui's handle is Clone-cheap (internally a
/// Rc-like structure).
fn ensure_ready_texture(
    ctx: &egui::Context,
    state: &mut CeremonyPanelState,
    image: egui::ColorImage,
) -> Option<egui::TextureHandle> {
    if let CeremonyStage::Ready { qr_texture, .. } = &mut state.stage {
        if qr_texture.is_none() {
            *qr_texture =
                Some(ctx.load_texture("ceremony_ready_qr", image, egui::TextureOptions::NEAREST));
        }
        qr_texture.clone()
    } else {
        None
    }
}

// ── Stage: Cancelled ────────────────────────────────────────────────────

fn render_cancelled(ui: &mut egui::Ui, state: &mut CeremonyPanelState) {
    let reason = match &state.stage {
        CeremonyStage::Cancelled { reason, .. } => reason.clone(),
        _ => return,
    };

    ui.colored_label(egui::Color32::LIGHT_RED, &reason);
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if ui
            .button("Start over")
            .on_hover_text(
                "Reopen Configure with the previous roster pre-populated. \
                 Rename the community or adjust members before starting again — \
                 identical inputs produce identical request_ids, which would \
                 collide with the aborted ceremony's responses.",
            )
            .clicked()
        {
            if let CeremonyStage::Cancelled { last_draft, .. } =
                std::mem::replace(&mut state.stage, CeremonyStage::Configure)
            {
                state.form = rehydrate_form(&last_draft);
                state.toast = Some("Form restored from the cancelled ceremony.".into());
            }
        }

        if ui.button("Discard").clicked() {
            state.stage = CeremonyStage::Configure;
            state.form = ConfigureForm::default();
            state.toast = None;
        }
    });
}

/// Reconstruct a `ConfigureForm` from the last assembly draft. Used by
/// "Start over" — the draft stores the authoritative roster, so we
/// simply project it back into the editable surface.
fn rehydrate_form(draft: &CommunityAssemblyParams) -> ConfigureForm {
    ConfigureForm {
        name: draft.name.as_str().to_owned(),
        member_dids: draft
            .members
            .iter()
            .map(|m| m.did.as_str().to_owned())
            .collect(),
        new_did_buf: String::new(),
        quorum: u16::from(draft.quorum.value()),
        error: None,
    }
}

// ── Spawn helpers ───────────────────────────────────────────────────────

/// Kick off an export of a single VouchRequest. Task flow:
///   1. AsyncFileDialog::save_file on the tokio runtime.
///   2. postcard-serialize + envelope-wrap the request.
///   3. Write bytes to the picked path.
/// Result lands on `state.export`.
fn spawn_export_request(
    bridge: &DaemonBridge,
    state: &mut CeremonyPanelState,
    request: VouchRequest,
) {
    let (tx, rx) = oneshot::channel();
    let suggested_name = format!("{}.request.bin", short_hex(&request.request_id));
    bridge.runtime.spawn(async move {
        let Some(picked) = rfd::AsyncFileDialog::new()
            .set_file_name(&suggested_name)
            .add_filter("Vouch request envelope", &["bin"])
            .set_title("Export vouch request")
            .save_file()
            .await
        else {
            let _ = tx.send(Err("file save cancelled".into()));
            return;
        };
        let path: PathBuf = picked.path().to_path_buf();
        let body = match postcard::to_allocvec(&request) {
            Ok(b) => b,
            Err(e) => {
                let _ = tx.send(Err(format!("encode: {e}")));
                return;
            }
        };
        let wrapped = wrap_vouch_request(&body);
        if let Err(e) = tokio::fs::write(&path, &wrapped).await {
            let _ = tx.send(Err(format!("write {}: {e}", path.display())));
            return;
        }
        let _ = tx.send(Ok(path));
    });
    state.export = AsyncReply::pending(rx);
}

/// Kick off a pick + read + verify of a single VouchResponse. Task flow:
///   1. AsyncFileDialog::pick_file.
///   2. tokio::fs::read → strip envelope → postcard decode → `VouchResponse`.
///   3. Eager dedup check on `(voucher_did, member_did)` using the
///      passed `existing_responses` snapshot — prevents a second
///      response for the same slot from counting as fresh verification.
///   4. Find the originating `VouchRequest` by `request_id`.
///   5. `CommunityCommand::VerifyVouchResponse` through the actor.
///   6. On Ok, hand back `(request_id, response)` on the panel's oneshot.
fn spawn_import_response(
    bridge: &DaemonBridge,
    state: &mut CeremonyPanelState,
    requests: Vec<VouchRequest>,
    existing_responses: HashMap<[u8; 32], VouchResponse>,
) {
    let community_tx = bridge.community_tx.clone();
    let (tx, rx) = oneshot::channel();
    bridge.runtime.spawn(async move {
        let Some(picked) = rfd::AsyncFileDialog::new()
            .add_filter("Vouch response envelope", &["bin"])
            .set_title("Import vouch response")
            .pick_file()
            .await
        else {
            let _ = tx.send(Err("file selection cancelled".into()));
            return;
        };
        let path = picked.path().to_path_buf();
        let bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) => {
                let _ = tx.send(Err(format!("read {}: {e}", path.display())));
                return;
            }
        };
        let body = match strip_vouch_response(&bytes) {
            Ok(b) => b,
            Err(e) => {
                let _ = tx.send(Err(format!("envelope: {e}")));
                return;
            }
        };
        let response: VouchResponse = match postcard::from_bytes(body) {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.send(Err(format!("decode: {e}")));
                return;
            }
        };

        // Eager dedup — reject before the actor round-trip.
        if existing_responses.contains_key(&response.request_id) {
            let _ = tx.send(Err(
                "this voucher already signed this slot — drop the duplicate response".into(),
            ));
            return;
        }

        let request = match requests
            .iter()
            .find(|r| r.request_id == response.request_id)
        {
            Some(r) => r.clone(),
            None => {
                let _ = tx.send(Err(
                    "request_id does not match any open slot in this ceremony".into(),
                ));
                return;
            }
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        if community_tx
            .send(CommunityCommand::VerifyVouchResponse {
                request: Box::new(request),
                response: Box::new(response.clone()),
                reply_to: reply_tx,
            })
            .await
            .is_err()
        {
            let _ = tx.send(Err("community actor channel closed".into()));
            return;
        }

        match reply_rx.await {
            Ok(Ok(())) => {
                let _ = tx.send(Ok((response.request_id, response)));
            }
            Ok(Err(ce)) => {
                let _ = tx.send(Err(format!("verify: {ce}")));
            }
            Err(_) => {
                let _ = tx.send(Err("actor dropped reply channel".into()));
            }
        }
    });
    state.import = AsyncReply::pending(rx);
}

/// Marshal the responses map into the `Vec<CeremonyMember>` the
/// `AssembleAndImport` command expects, then dispatch it. The actor
/// clones the assembled community on success and returns it via the
/// reply channel, so the Ready transition happens in `drain_replies`
/// without a second round-trip.
fn spawn_assemble(
    bridge: &DaemonBridge,
    state: &mut CeremonyPanelState,
    requests: &[VouchRequest],
    responses: &HashMap<[u8; 32], VouchResponse>,
) {
    let mut params = match &state.stage {
        CeremonyStage::CollectingVouches { params_draft, .. } => params_draft.clone(),
        _ => return,
    };

    // Replace the empty-vouches skeleton with the verified responses.
    let roster: Vec<Did> = params.members.iter().map(|m| m.did.clone()).collect();
    match collect_members_from_responses(requests, responses, &roster) {
        Ok(members) => params.members = members,
        Err(msg) => {
            state.toast = Some(format!("Marshaling failed: {msg}"));
            return;
        }
    }

    let community_tx = bridge.community_tx.clone();
    let (tx, rx) = oneshot::channel();
    bridge.runtime.spawn(async move {
        let (reply_tx, reply_rx) = oneshot::channel();
        if community_tx
            .send(CommunityCommand::AssembleAndImport {
                params,
                reply_to: reply_tx,
            })
            .await
            .is_err()
        {
            let _ = tx.send(Err("community actor channel closed".into()));
            return;
        }
        match reply_rx.await {
            Ok(Ok((id, community))) => {
                let _ = tx.send(Ok((id, community)));
            }
            Ok(Err(ce)) => {
                let _ = tx.send(Err(format!("assemble: {ce}")));
            }
            Err(_) => {
                let _ = tx.send(Err("actor dropped reply channel".into()));
            }
        }
    });
    state.assemble = AsyncReply::pending(rx);
}

// ── Marshaling (Phase 7.B.8) ────────────────────────────────────────────

/// Fold the verified responses into `Vec<CeremonyMember>`, preserving
/// roster order so the `CommunityId::compute` sort stays stable and
/// the assembled Community's `members` vector has a deterministic
/// shape. Each member's `vouches` list is drawn from every request
/// whose `member_did` matches and whose `request_id` has a response.
///
/// Errors:
/// - Returns `Err` if a response's `request_id` is missing from the
///   `requests` slice — unreachable in the normal flow (the panel
///   only admits verified responses via `spawn_import_response`) but
///   makes the helper total.
pub fn collect_members_from_responses(
    requests: &[VouchRequest],
    responses: &HashMap<[u8; 32], VouchResponse>,
    roster: &[Did],
) -> Result<Vec<CeremonyMember>, String> {
    // Validate every response corresponds to a known request_id.
    for id in responses.keys() {
        if !requests.iter().any(|r| &r.request_id == id) {
            return Err(format!(
                "response with request_id {} has no matching request",
                short_hex(id),
            ));
        }
    }

    let mut out = Vec::with_capacity(roster.len());
    for member_did in roster {
        let vouches: Vec<Vouch> = requests
            .iter()
            .filter(|r| &r.member_did == member_did)
            .filter_map(|r| responses.get(&r.request_id).map(|resp| resp.vouch.clone()))
            .collect();
        out.push(CeremonyMember {
            did: member_did.clone(),
            vouches,
        });
    }
    Ok(out)
}

// ── QR + URI helpers ────────────────────────────────────────────────────

/// Build a square QR ColorImage from a UTF-8 payload. Returns `None`
/// if the payload is too large for the maximum QR version under the
/// chosen error-correction level. Includes a 4-module quiet zone so
/// camera scanners lock on reliably.
fn build_qr_image(payload: &str) -> Option<egui::ColorImage> {
    let code = qrcode::QrCode::with_error_correction_level(payload, qrcode::EcLevel::M).ok()?;
    let modules = code.width();
    let colors = code.to_colors();
    if colors.len() != modules.saturating_mul(modules) {
        return None;
    }

    // 6 pixels per module = crisp at 360–420 px display size; 4-module
    // quiet zone meets the QR spec.
    const SCALE: usize = 6;
    const QUIET_ZONE_MODULES: usize = 4;
    let inner = modules.saturating_mul(SCALE);
    let quiet = QUIET_ZONE_MODULES.saturating_mul(SCALE);
    let side = inner.saturating_add(quiet.saturating_mul(2));

    let mut pixels = vec![egui::Color32::WHITE; side.saturating_mul(side)];
    for my in 0..modules {
        for mx in 0..modules {
            let color_idx = my.saturating_mul(modules).saturating_add(mx);
            let Some(color) = colors.get(color_idx) else {
                // Unreachable given the length assertion above, but
                // keeps the pixel walk total.
                continue;
            };
            if !matches!(color, qrcode::Color::Dark) {
                continue;
            }
            let x0 = quiet.saturating_add(mx.saturating_mul(SCALE));
            let y0 = quiet.saturating_add(my.saturating_mul(SCALE));
            for dy in 0..SCALE {
                let row = y0.saturating_add(dy);
                for dx in 0..SCALE {
                    let col = x0.saturating_add(dx);
                    let idx = row.saturating_mul(side).saturating_add(col);
                    if let Some(p) = pixels.get_mut(idx) {
                        *p = egui::Color32::BLACK;
                    }
                }
            }
        }
    }

    Some(egui::ColorImage {
        size: [side, side],
        pixels,
    })
}

/// Build the Ready-stage join surface: the join URI and (best-effort)
/// QR image. Always returns a URI; the QR is `None` if the payload
/// exceeds QR capacity. Universal-Link form so the production Android
/// App Link intercepts the tap directly.
fn build_join_surface(community: &Community) -> (Option<egui::ColorImage>, String) {
    let body = match postcard::to_allocvec(community) {
        Ok(b) => b,
        Err(_) => return (None, "https://phalanx.app/c/join#error=serialize".into()),
    };
    let wrapped = wrap_payload_version(&body);
    let b64 = URL_SAFE_NO_PAD.encode(&wrapped);
    let uri = format!("https://phalanx.app/c/join#data={b64}");
    let qr = build_qr_image(&uri);
    (qr, uri)
}

// ── Formatting helpers ──────────────────────────────────────────────────

fn short_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s.truncate(16);
    s
}

fn short_did(did: &Did) -> String {
    let s = did.as_str();
    if s.len() <= 24 {
        s.to_owned()
    } else {
        format!("{}…", &s[..24])
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use phalanx_proto::community::{Vouch, VouchSignature};

    fn sample_dids(n: usize) -> Vec<Did> {
        (0..n)
            .map(|i| Did::new(format!("did:key:z{i}-test")))
            .collect()
    }

    fn sample_name() -> PetName {
        PetName::new("Demo Community").unwrap()
    }

    /// Deterministic nonce for tests — the production path uses
    /// `CeremonyNonce::random()`, but inline tests want stable
    /// `request_id`s for the deterministic-id assertion.
    fn sample_nonce() -> CeremonyNonce {
        CeremonyNonce([0xABu8; 16])
    }

    #[test]
    fn quorum_bounds_small_roster() {
        assert_eq!(quorum_bounds(0), (2, 2));
        assert_eq!(quorum_bounds(1), (2, 2));
        assert_eq!(quorum_bounds(2), (2, 2));
        assert_eq!(quorum_bounds(3), (2, 2));
        assert_eq!(quorum_bounds(5), (2, 4));
    }

    #[test]
    fn request_slots_self_contained_n3_k2() {
        let members = sample_dids(3);
        let q = Quorum::new(2).unwrap();
        let tentative = CommunityId::compute(&sample_name(), q, &members);
        let now = PhalanxTimestamp::from_millis(1_000_000);
        let slots = build_request_slots(
            &members,
            q,
            tentative,
            &sample_nonce(),
            &sample_name(),
            now,
            now,
        );
        // N × K = 3 × 2 = 6 slots.
        assert_eq!(slots.len(), 6);
        // Every slot is for a distinct (member, voucher) pair.
        for s in &slots {
            assert_ne!(
                s.member_did, s.voucher_did,
                "self-vouching must never happen"
            );
        }
        // Every member is vouched exactly K times.
        for m in &members {
            let count = slots.iter().filter(|s| &s.member_did == m).count();
            assert_eq!(count, 2, "member {m:?} should have K=2 vouchers");
        }
    }

    #[test]
    fn request_slots_deterministic_id() {
        let members = sample_dids(3);
        let q = Quorum::new(2).unwrap();
        let tentative = CommunityId::compute(&sample_name(), q, &members);
        let now = PhalanxTimestamp::from_millis(42);
        let a = build_request_slots(
            &members,
            q,
            tentative,
            &sample_nonce(),
            &sample_name(),
            now,
            now,
        );
        let b = build_request_slots(
            &members,
            q,
            tentative,
            &sample_nonce(),
            &sample_name(),
            now,
            now,
        );
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.request_id, y.request_id);
        }
    }

    #[test]
    fn collect_members_groups_by_target() {
        let members = sample_dids(3);
        let q = Quorum::new(2).unwrap();
        let tentative = CommunityId::compute(&sample_name(), q, &members);
        let now = PhalanxTimestamp::from_millis(0);
        let requests = build_request_slots(
            &members,
            q,
            tentative,
            &sample_nonce(),
            &sample_name(),
            now,
            now,
        );
        // Synthesize a fake response for every request (signature is a
        // placeholder; the marshaling helper doesn't verify).
        let responses: HashMap<[u8; 32], VouchResponse> = requests
            .iter()
            .map(|r| {
                (
                    r.request_id,
                    VouchResponse {
                        request_id: r.request_id,
                        vouch: Vouch {
                            voucher_did: r.voucher_did.clone(),
                            signature: VouchSignature::new([0xABu8; 64]),
                        },
                    },
                )
            })
            .collect();
        let grouped = collect_members_from_responses(&requests, &responses, &members).unwrap();
        assert_eq!(grouped.len(), members.len());
        for (i, m) in grouped.iter().enumerate() {
            assert_eq!(m.did, members[i]);
            assert_eq!(m.vouches.len(), 2, "each member has K=2 vouches");
        }
    }

    #[test]
    fn collect_members_rejects_orphan_response() {
        let members = sample_dids(3);
        let q = Quorum::new(2).unwrap();
        let tentative = CommunityId::compute(&sample_name(), q, &members);
        let now = PhalanxTimestamp::from_millis(0);
        let requests = build_request_slots(
            &members,
            q,
            tentative,
            &sample_nonce(),
            &sample_name(),
            now,
            now,
        );
        let mut responses = HashMap::new();
        responses.insert(
            [0xFFu8; 32],
            VouchResponse {
                request_id: [0xFFu8; 32],
                vouch: Vouch {
                    voucher_did: Did::new("did:key:zOrphan"),
                    signature: VouchSignature::new([0u8; 64]),
                },
            },
        );
        let err = collect_members_from_responses(&requests, &responses, &members)
            .expect_err("orphan response must be rejected");
        assert!(err.contains("no matching request"), "got: {err}");
    }

    #[test]
    fn rehydrate_form_roundtrips_draft() {
        let members = sample_dids(3);
        let q = Quorum::new(2).unwrap();
        let now = PhalanxTimestamp::from_millis(0);
        let draft = CommunityAssemblyParams {
            name: sample_name(),
            quorum: q,
            joined_at: now,
            expires_at: PhalanxTimestamp::from_millis(30 * 86_400 * 1000),
            stronghold_did: None,
            baseline_trust: TrustLevel::Verified,
            grants: CommunityGrants::default(),
            members: members
                .iter()
                .map(|did| CeremonyMember {
                    did: did.clone(),
                    vouches: Vec::new(),
                })
                .collect(),
        };
        let form = rehydrate_form(&draft);
        assert_eq!(form.name, "Demo Community");
        assert_eq!(form.quorum, 2);
        assert_eq!(form.member_dids.len(), 3);
        assert_eq!(form.member_dids[0], "did:key:z0-test");
    }

    #[test]
    fn project_payload_size_scales_with_roster() {
        let small = project_payload_size(3, 2);
        let big = project_payload_size(30, 5);
        assert!(big > small, "bigger roster should project higher");
    }

    #[test]
    fn build_qr_image_returns_some_for_tiny_payload() {
        let img = build_qr_image("hello").expect("tiny payload encodes");
        assert!(img.size[0] > 0 && img.size[0] == img.size[1]);
        assert_eq!(img.pixels.len(), img.size[0] * img.size[1]);
    }

    #[test]
    fn short_hex_first_16_chars() {
        let mut b = [0u8; 32];
        b[0] = 0xde;
        b[1] = 0xad;
        b[2] = 0xbe;
        b[3] = 0xef;
        let s = short_hex(&b);
        assert_eq!(s.len(), 16);
        assert!(s.starts_with("deadbeef"));
    }
}
