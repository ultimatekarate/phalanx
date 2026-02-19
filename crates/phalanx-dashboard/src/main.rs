mod widgets;

use std::collections::HashMap;
use std::{
    io,
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};

use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::primitives::identity::NetworkId;
use phalanx_core::security::telemetry::{ChaosMode, NodeRole, SimEvent};
use phalanx_core::simulation::SimulationHarness;

use widgets::{NetworkRadar, TrafficVector, VectorStyle};

struct ActiveVector {
    origin: NetworkId,
    target: NetworkId,
    timestamp: Instant,
}

struct AppState {
    active_peers: HashMap<NetworkId, Instant>,
    node_modes: HashMap<NetworkId, ChaosMode>,
    node_roles: HashMap<NetworkId, NodeRole>,
    active_vectors: Vec<ActiveVector>,
    logs: Vec<String>,
    total_bytes_processed: u64,
    current_scenario: String,
}

impl AppState {
    fn new() -> Self {
        Self {
            active_peers: HashMap::new(),
            node_modes: HashMap::new(),
            node_roles: HashMap::new(),
            active_vectors: Vec::new(),
            logs: Vec::new(),
            total_bytes_processed: 0,
            current_scenario: "Stable".to_string(),
        }
    }

    fn add_log(&mut self, msg: String) {
        self.logs.insert(0, msg);
        if self.logs.len() > 50 {
            self.logs.pop();
        }
    }

    fn prune_vectors(&mut self) {
        self.active_vectors
            .retain(|v| v.timestamp.elapsed() < Duration::from_secs(2));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let config = PhalanxConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, mut telemetry_rx) = SimulationHarness::init_mesh(config, physics);

    // Initialize AppState early so we can register initial nodes
    let mut app = AppState::new();

    // 1. SPAWN GUARDIANS (Standard Nodes)
    let did_alpha = harness.spawn_node("Alpha", NodeRole::Guardian).await;
    let net_alpha = harness
        .resolve_did(&did_alpha)
        .await
        .expect("Failed to resolve Alpha");
    app.node_roles.insert(net_alpha, NodeRole::Guardian);

    let did_beta = harness.spawn_node("Beta", NodeRole::Guardian).await;
    let net_beta = harness
        .resolve_did(&did_beta)
        .await
        .expect("Failed to resolve Beta");
    app.node_roles.insert(net_beta, NodeRole::Guardian);

    let did_gamma = harness.spawn_node("Gamma", NodeRole::Guardian).await;
    let net_gamma = harness
        .resolve_did(&did_gamma)
        .await
        .expect("Failed to resolve Gamma");
    app.node_roles.insert(net_gamma, NodeRole::Guardian);

    // 2. SPAWN STRONGHOLD (Bastion)
    let did_bastion = harness.spawn_node("Bastion", NodeRole::Stronghold).await;
    let net_bastion = harness
        .resolve_did(&did_bastion)
        .await
        .expect("Failed to resolve Bastion");
    app.node_roles.insert(net_bastion, NodeRole::Stronghold);

    let mut running = true;

    while running {
        if crossterm::event::poll(Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => running = false,

                    KeyCode::Char('t') => {
                        // 1. Pick two random nodes if we have them
                        let nodes: Vec<NetworkId> = app.active_peers.keys().cloned().collect();
                        if nodes.len() >= 2 {
                            let origin = nodes[0];
                            let target = nodes[1];

                            app.add_log(format!("[TEST] Forcing Vector {} -> {}", origin, target));

                            // 2. Manually push to active_vectors
                            app.active_vectors.push(ActiveVector {
                                origin,
                                target,
                                timestamp: Instant::now(),
                            });
                        } else {
                            app.add_log("[ERR] Not enough nodes for test vector".to_string());
                        }
                    }

                    // --- CHAOS CONTROLS ---
                    KeyCode::Char('1') => {
                        app.current_scenario = "Alpha: Packet Loss".to_string();
                        app.add_log("!!! INJECTING FAULT: Alpha Packet Loss".into());
                        app.node_modes.insert(net_alpha, ChaosMode::PacketLoss(0.5));
                        harness
                            .inject_chaos(&did_alpha, ChaosMode::PacketLoss(0.5))
                            .await;
                    }
                    KeyCode::Char('2') => {
                        app.current_scenario = "Beta: Vampire Attack".to_string();
                        app.add_log("!!! INJECTING FAULT: Beta Hyperactivity".into());
                        app.node_modes.insert(net_beta, ChaosMode::Hyperactive);
                        harness
                            .inject_chaos(&did_beta, ChaosMode::Hyperactive)
                            .await;
                    }
                    KeyCode::Char('3') => {
                        app.current_scenario = "Gamma: Byzantine Fault".to_string();
                        app.add_log("!!! INJECTING FAULT: Gamma Corruption".into());
                        app.node_modes.insert(net_gamma, ChaosMode::Byzantine);
                        harness.inject_chaos(&did_gamma, ChaosMode::Byzantine).await;
                    }
                    KeyCode::Char('0') => {
                        app.current_scenario = "Stable".to_string();
                        app.add_log("--- SYSTEM STABILIZED ---".into());
                        app.node_modes.clear();
                        harness.inject_chaos(&did_alpha, ChaosMode::Stable).await;
                        harness.inject_chaos(&did_beta, ChaosMode::Stable).await;
                        harness.inject_chaos(&did_gamma, ChaosMode::Stable).await;
                    }
                    _ => {}
                }
            }
        }
        app.prune_vectors();

        while let Ok(event) = telemetry_rx.try_recv() {
            match event {
                SimEvent::Heartbeat { origin, .. } => {
                    app.active_peers.insert(origin, Instant::now());
                }
                SimEvent::PeerDiscovered { peer, role, source } => {
                    app.node_roles.insert(peer, role);
                    app.active_peers.insert(peer, Instant::now());
                    app.add_log(format!("[DISCOVERY] {:?} {} via {:?}", role, peer, source));
                }
                SimEvent::ShardProcessed { peer_id, byte_size } => {
                    app.total_bytes_processed += byte_size.as_u64();
                    app.add_log(format!(
                        "[DATA] {} processed {} bytes",
                        peer_id,
                        byte_size.as_u64()
                    ));
                }
                SimEvent::AttackAttemptBlocked { attacker, reason } => {
                    app.add_log(format!("[DEFENSE] Blocked {}: {}", attacker, reason));
                }
                // NEW: Visualizing Offload Events
                SimEvent::OffloadComplete {
                    origin,
                    target,
                    size,
                } => {
                    // Check the Role of the Target to determine the Log Message
                    let target_role = app.node_roles.get(&target).unwrap_or(&NodeRole::Guardian);

                    let log_msg = if *target_role == NodeRole::Stronghold {
                        format!(
                            "[ARCHIVE] {} -> {}: {} bytes secured",
                            origin,
                            target,
                            size.as_u64()
                        )
                    } else {
                        format!("[GOSSIP] {} -> {}: sync", origin, target)
                    };

                    // Only log Archive events to avoid flooding the list,
                    // OR log Gossip sparingly.
                    if *target_role == NodeRole::Stronghold {
                        app.add_log(log_msg);
                    }

                    // ALWAYS Register Vector for Visualization
                    // This ensures the green/cyan lines appear for all traffic
                    if let Some(existing) = app
                        .active_vectors
                        .iter_mut()
                        .find(|v| v.origin == origin && v.target == target)
                    {
                        existing.timestamp = Instant::now();
                    } else {
                        app.active_vectors.push(ActiveVector {
                            origin,
                            target,
                            timestamp: Instant::now(),
                        });
                    }
                }
                _ => {}
            }
        }

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(f.area());

            let left_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
                .split(chunks[0]);

            let peer_list: Vec<(NetworkId, Instant)> =
                app.active_peers.iter().map(|(k, v)| (*k, *v)).collect();

            let widget_vectors: Vec<TrafficVector> = app
                .active_vectors
                .iter()
                .map(|v| TrafficVector {
                    from: v.origin,
                    to: v.target,
                    age_seconds: v.timestamp.elapsed().as_secs_f32(),
                    style: VectorStyle::Standard,
                })
                .collect();

            f.render_widget(
                NetworkRadar {
                    title: "Phalanx Mesh Radar",
                    nodes: &peer_list,
                    node_states: &app.node_modes,
                    node_roles: &app.node_roles,
                    traffic: &widget_vectors, // Pass the new traffic slice
                },
                left_chunks[0],
            );

            let stats_text = vec![
                Line::from(format!("Active Nodes: {}", app.active_peers.len())),
                Line::from(format!("Throughput:   {} bytes", app.total_bytes_processed)),
                Line::from(""),
                Line::from(Span::styled(
                    format!("STATUS: {}", app.current_scenario),
                    Style::default()
                        .fg(if app.current_scenario == "Stable" {
                            Color::Green
                        } else {
                            Color::Red
                        })
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from("Controls: [1] Pkt Loss [2] Vampire [3] Byzantine [0] Stabilize"),
            ];

            f.render_widget(
                Paragraph::new(stats_text).block(
                    Block::default()
                        .title("Telemetry & Control")
                        .borders(Borders::ALL),
                ),
                left_chunks[1],
            );

            let items: Vec<ListItem> = app
                .logs
                .iter()
                .map(|msg| {
                    let style = if msg.contains("!!!") {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    } else if msg.contains("DATA") {
                        Style::default().fg(Color::Green)
                    } else if msg.contains("DEFENSE") {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else if msg.contains("OFFLOAD") {
                        // CYAN for Offload Events
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    ListItem::new(Line::from(msg.as_str())).style(style)
                })
                .collect();

            f.render_widget(
                List::new(items)
                    .block(Block::default().title("Event Stream").borders(Borders::ALL)),
                chunks[1],
            );
        })?;
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
