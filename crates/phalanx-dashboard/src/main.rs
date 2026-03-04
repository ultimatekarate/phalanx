mod state;
mod ui;
mod widgets;

use std::{io, time::Duration};

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use phalanx_node::config::NodeConfig;
use phalanx_proto::identity::NodeRole;
use phalanx_proto::telemetry::ChaosMode;
use phalanx_sim::physics::PhalanxPhysics;
use phalanx_sim::SimulationHarness;

use crate::state::DashboardState;
use crate::ui::render_dashboard;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, mut telemetry_rx) = SimulationHarness::init_mesh(config, physics);
    let mut state = DashboardState::new();

    // Node Initialization - Explicitly unpack the Option<Did> returned by spawn_node
    let did_alpha = harness
        .spawn_node("Alpha", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Alpha");
    let net_alpha = harness
        .resolve_did(&did_alpha)
        .await
        .expect("Resolution failed");
    state
        .node_roles
        .insert(net_alpha.clone(), NodeRole::Guardian);

    let did_beta = harness
        .spawn_node("Beta", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Beta");
    let net_beta = harness
        .resolve_did(&did_beta)
        .await
        .expect("Resolution failed");
    state
        .node_roles
        .insert(net_beta.clone(), NodeRole::Guardian);

    let did_gamma = harness
        .spawn_node("Gamma", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Gamma");
    let net_gamma = harness
        .resolve_did(&did_gamma)
        .await
        .expect("Resolution failed");
    state
        .node_roles
        .insert(net_gamma.clone(), NodeRole::Guardian);

    let did_bastion = harness
        .spawn_node("Bastion", NodeRole::Stronghold)
        .await
        .expect("Failed to spawn Bastion");
    let net_bastion = harness
        .resolve_did(&did_bastion)
        .await
        .expect("Resolution failed");
    state.node_roles.insert(net_bastion, NodeRole::Stronghold);

    while state.is_running {
        // Input Polling
        if crossterm::event::poll(Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => state.is_running = false,
                    KeyCode::Char('1') => {
                        state.current_scenario = "Alpha: Packet Loss".to_string();
                        state
                            .node_modes
                            .insert(net_alpha.clone(), ChaosMode::PacketLoss(0.5));
                        harness
                            .inject_chaos(&did_alpha, ChaosMode::PacketLoss(0.5))
                            .await;
                    }
                    KeyCode::Char('2') => {
                        state.current_scenario = "Beta: Vampire Attack".to_string();
                        state
                            .node_modes
                            .insert(net_beta.clone(), ChaosMode::Hyperactive);
                        harness
                            .inject_chaos(&did_beta, ChaosMode::Hyperactive)
                            .await;
                    }
                    KeyCode::Char('3') => {
                        state.current_scenario = "Gamma: Byzantine Fault".to_string();
                        state
                            .node_modes
                            .insert(net_gamma.clone(), ChaosMode::Byzantine);
                        harness.inject_chaos(&did_gamma, ChaosMode::Byzantine).await;
                    }
                    KeyCode::Char('0') => {
                        state.current_scenario = "Stable".to_string();
                        state.node_modes.clear();
                        harness.inject_chaos(&did_alpha, ChaosMode::Stable).await;
                        harness.inject_chaos(&did_beta, ChaosMode::Stable).await;
                        harness.inject_chaos(&did_gamma, ChaosMode::Stable).await;
                    }
                    _ => {}
                }
            }
        }

        state.tick_maintenance();

        // Process Telemetry Batch (Throttle at 100 events to maintain UI framerate)
        let mut events_processed = 0;
        while let Ok(event) = telemetry_rx.try_recv() {
            if events_processed >= 100 {
                break;
            }
            state.ingest_telemetry(event);
            events_processed += 1;
        }

        // Render Frame
        terminal.draw(|f| {
            render_dashboard(f, &state);
        })?;
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
