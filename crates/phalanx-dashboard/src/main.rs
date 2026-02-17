mod widgets;

use std::{io, time::{Duration, Instant}};
use std::sync::Arc;
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
    style::{Style, Modifier},
    text::Line,
    Terminal,
};

// Core Imports
use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::simulation::SimulationHarness;
use phalanx_core::security::telemetry::SimEvent;
use phalanx_core::primitives::identity::NetworkId;

use widgets::NetworkRadar;

struct AppState {
    // Map of active nodes and their last heartbeat time
    active_peers: HashMap<NetworkId, Instant>,
    // Scrolling log of recent events
    logs: Vec<String>,
    // Stats
    total_bytes_processed: u64,
}

impl AppState {
    fn new() -> Self {
        Self {
            active_peers: HashMap::new(),
            logs: Vec::new(),
            total_bytes_processed: 0,
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
    // 1. Terminal Setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 2. Initialize Simulation
    let config = PhalanxConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();
    let (mut harness, relay_rx, mut telemetry_rx) = SimulationHarness::init_mesh(config, physics);

    // 3. Spawn Reactor
    let nodes_ref = Arc::clone(&harness.nodes);
    tokio::spawn(async move {
        SimulationHarness::run_mesh_relay(nodes_ref, relay_rx).await;
    });

    // 4. Seed Data
    harness.spawn_node("Alpha").await;
    harness.spawn_node("Beta").await;
    harness.spawn_node("Gamma").await;

    // 5. Run Loop
    let mut app = AppState::new();
    let mut running = true;

    while running {
        // --- Input Handling ---
        if crossterm::event::poll(Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    running = false;
                }
            }
        }

        // --- Data Ingestion ---
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
                SimEvent::ChunkIngested { origin, .. } => {
                    app.add_log(format!("[CHUNK] Ingested from {}", origin));
                }
                _ => {}
            }
        }

        // --- Rendering ---
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(f.area());

            let left_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
                .split(chunks[0]);

            // Widget 1: Network Radar
            let peer_list: Vec<(NetworkId, Instant)> = app.active_peers
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect();
            
            f.render_widget(
                NetworkRadar {
                    title: "Phalanx Mesh Radar",
                    nodes: &peer_list,
                },
                left_chunks[0],
            );

            // Widget 2: Stats
            let stats_text = format!(
                "Active Nodes: {}\nTotal Throughput: {} bytes\nFPS: 60",
                app.active_peers.len(),
                app.total_bytes_processed
            );
            f.render_widget(
                Paragraph::new(stats_text)
                    .block(Block::default().title("Telemetry").borders(Borders::ALL)),
                left_chunks[1]
            );

            // Widget 3: Event Logs
            let items: Vec<ListItem> = app.logs
                .iter()
                .map(|msg| ListItem::new(Line::from(msg.as_str())))
                .collect();
                
            f.render_widget(
                List::new(items)
                    .block(Block::default().title("Event Stream").borders(Borders::ALL))
                    .highlight_style(Style::default().add_modifier(Modifier::BOLD)),
                chunks[1]
            );
        })?;
    }

    // 6. Shutdown
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}