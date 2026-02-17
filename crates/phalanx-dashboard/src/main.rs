mod widgets;

use std::{io, time::{Duration, Instant}};
use std::collections::HashMap;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Paragraph, List, ListItem},
    style::{Style, Modifier, Color},
    text::{Line, Span},
    Terminal,
};

use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::simulation::SimulationHarness;
use phalanx_core::security::telemetry::{SimEvent, ChaosMode};
use phalanx_core::primitives::identity::NetworkId;

use widgets::NetworkRadar;

struct AppState {
    active_peers: HashMap<NetworkId, Instant>,
    // NEW: Track the visual state of nodes
    node_modes: HashMap<NetworkId, ChaosMode>,
    logs: Vec<String>,
    total_bytes_processed: u64,
    current_scenario: String, 
}

impl AppState {
    fn new() -> Self {
        Self {
            active_peers: HashMap::new(),
            node_modes: HashMap::new(),
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

    // 1. SPAWN & RESOLVE IDs
    // We need both the DID (for Control) and NetworkId (for Visualization)
    let did_alpha = harness.spawn_node("Alpha").await;
    let net_alpha = harness.resolve_did(&did_alpha).await.expect("Failed to resolve Alpha");

    let did_beta = harness.spawn_node("Beta").await;
    let net_beta = harness.resolve_did(&did_beta).await.expect("Failed to resolve Beta");

    let did_gamma = harness.spawn_node("Gamma").await;
    let net_gamma = harness.resolve_did(&did_gamma).await.expect("Failed to resolve Gamma");

    let mut app = AppState::new();
    let mut running = true;

    while running {
        if crossterm::event::poll(Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => running = false,
                    
                    // --- CHAOS CONTROLS ---
                    // Now updating BOTH the simulation and the UI state
                    KeyCode::Char('1') => {
                        app.current_scenario = "Alpha: Packet Loss".to_string();
                        app.add_log("!!! INJECTING FAULT: Alpha Packet Loss".into());
                        app.node_modes.insert(net_alpha, ChaosMode::PacketLoss(0.5));
                        harness.inject_chaos(&did_alpha, ChaosMode::PacketLoss(0.5)).await;
                    }
                    KeyCode::Char('2') => {
                        app.current_scenario = "Beta: Vampire Attack".to_string();
                        app.add_log("!!! INJECTING FAULT: Beta Hyperactivity".into());
                        app.node_modes.insert(net_beta, ChaosMode::Hyperactive);
                        harness.inject_chaos(&did_beta, ChaosMode::Hyperactive).await;
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
                        app.node_modes.clear(); // Reset visuals
                        harness.inject_chaos(&did_alpha, ChaosMode::Stable).await;
                        harness.inject_chaos(&did_beta, ChaosMode::Stable).await;
                        harness.inject_chaos(&did_gamma, ChaosMode::Stable).await;
                    }
                    _ => {}
                }
            }
        }

        while let Ok(event) = telemetry_rx.try_recv() {
            match event {
                SimEvent::Heartbeat { origin, .. } => {
                    app.active_peers.insert(origin, Instant::now());
                }
                SimEvent::PeerDiscovered { peer, source, .. } => {
                    app.add_log(format!("[DISCOVERY] {} via {:?}", peer, source));
                    app.active_peers.insert(peer, Instant::now());
                }
                SimEvent::ShardProcessed { peer_id, byte_size } => {
                    app.total_bytes_processed += byte_size.as_u64();
                    app.add_log(format!("[DATA] {} processed {} bytes", peer_id, byte_size.as_u64()));
                }
                SimEvent::AttackAttemptBlocked { attacker, reason } => {
                    app.add_log(format!("[DEFENSE] Blocked {}: {}", attacker, reason));
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

            let peer_list: Vec<(NetworkId, Instant)> = app.active_peers
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect();
            
            f.render_widget(
                NetworkRadar {
                    title: "Phalanx Mesh Radar",
                    nodes: &peer_list,
                    node_states: &app.node_modes, // Pass the chaos state
                },
                left_chunks[0],
            );

            // ... (Rest of rendering logic remains the same) ...
            let stats_text = vec![
                Line::from(format!("Active Nodes: {}", app.active_peers.len())),
                Line::from(format!("Throughput:   {} bytes", app.total_bytes_processed)),
                Line::from(""),
                Line::from(Span::styled(
                    format!("STATUS: {}", app.current_scenario),
                    Style::default().fg(if app.current_scenario == "Stable" { Color::Green } else { Color::Red }).add_modifier(Modifier::BOLD)
                )),
                Line::from(""),
                Line::from("Controls: [1] Pkt Loss [2] Vampire [3] Byzantine [0] Stabilize"),
            ];

            f.render_widget(
                Paragraph::new(stats_text)
                    .block(Block::default().title("Telemetry & Control").borders(Borders::ALL)),
                left_chunks[1]
            );

            let items: Vec<ListItem> = app.logs
                .iter()
                .map(|msg| {
                    let style = if msg.contains("!!!") {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    } else if msg.contains("DATA") {
                        Style::default().fg(Color::Green)
                    } else if msg.contains("DEFENSE") { 
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    ListItem::new(Line::from(msg.as_str())).style(style)
                })
                .collect();
                
            f.render_widget(
                List::new(items)
                    .block(Block::default().title("Event Stream").borders(Borders::ALL)),
                chunks[1]
            );
        })?;
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}