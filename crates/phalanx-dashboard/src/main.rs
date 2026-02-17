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
    style::{Style, Modifier},
    text::Line,
    Terminal,
};

use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::simulation::SimulationHarness;
use phalanx_core::security::telemetry::SimEvent;
use phalanx_core::primitives::identity::NetworkId;

use widgets::NetworkRadar;

struct AppState {
    active_peers: HashMap<NetworkId, Instant>,
    logs: Vec<String>,
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
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let config = PhalanxConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    // UPDATED: Now returns just (harness, telemetry_rx)
    // The relay is already running in the background!
    let (mut harness, mut telemetry_rx) = SimulationHarness::init_mesh(config, physics);

    harness.spawn_node("Alpha").await;
    harness.spawn_node("Beta").await;
    harness.spawn_node("Gamma").await;

    let mut app = AppState::new();
    let mut running = true;

    while running {
        if crossterm::event::poll(Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    running = false;
                }
            }
        }

        while let Ok(event) = telemetry_rx.try_recv() {
            match event {
                // Matched to simulation.rs uploaded code
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
                },
                left_chunks[0],
            );

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

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}