// crates/phalanx-dashboard/src/ui.rs

use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use phalanx_proto::identity::NetworkId;
use std::time::Instant;

use crate::state::DashboardState;
use crate::widgets::NetworkRadar;

pub fn render_dashboard(f: &mut Frame, state: &DashboardState) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(f.area());

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(main_chunks[0]);

    render_radar(f, state, left_chunks[0]);
    render_telemetry_stats(f, state, left_chunks[1]);
    render_event_stream(f, state, main_chunks[1]);
}

fn render_radar(f: &mut Frame, state: &DashboardState, area: ratatui::layout::Rect) {
    let peer_list: Vec<(NetworkId, Instant)> = state
        .active_peers
        .iter()
        .map(|(id, timestamp)| ((id.clone()), *timestamp))
        .collect();

    let widget_vectors = state.generate_widget_vectors();

    let radar_widget = NetworkRadar {
        title: "Phalanx Mesh Radar",
        nodes: &peer_list,
        node_states: &state.node_modes,
        node_roles: &state.node_roles,
        traffic: &widget_vectors,
    };

    f.render_widget(radar_widget, area);
}

fn render_telemetry_stats(f: &mut Frame, state: &DashboardState, area: ratatui::layout::Rect) {
    let status_color = if state.current_scenario == "Stable" {
        Color::Green
    } else {
        Color::Red
    };

    let stats_text = vec![
        Line::from(format!("Active Nodes: {}", state.active_peers.len())),
        Line::from(format!(
            "Throughput:   {} bytes",
            state.metrics.total_bytes_processed
        )),
        Line::from(format!("Active Flows: {}", state.active_vectors.len())),
        Line::from(""),
        Line::from(Span::styled(
            format!("STATUS: {}", state.current_scenario),
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Controls: [1] Pkt Loss [2] Vampire [3] Byzantine [0] Stabilize [q] Quit"),
    ];

    let paragraph = Paragraph::new(stats_text).block(
        Block::default()
            .title("Telemetry & Control")
            .borders(Borders::ALL),
    );

    f.render_widget(paragraph, area);
}

fn render_event_stream(f: &mut Frame, state: &DashboardState, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = state
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
            } else if msg.contains("ARCHIVE") {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(msg.as_str())).style(style)
        })
        .collect();

    let list = List::new(items).block(Block::default().title("Event Stream").borders(Borders::ALL));

    f.render_widget(list, area);
}
