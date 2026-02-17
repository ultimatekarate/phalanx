use phalanx_core::primitives::identity::NetworkId;
use phalanx_core::security::telemetry::{ChaosMode, NodeRole};
use ratatui::widgets::canvas::{Canvas, Context, Line as CanvasLine, Points, Rectangle}; // Import Rectangle
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    symbols::Marker,
    text::Span,
    widgets::{Block, Borders, Widget},
};
use std::collections::HashMap; // Import NodeRole

pub struct NetworkRadar<'a> {
    pub title: &'a str,
    pub nodes: &'a [(NetworkId, std::time::Instant)],
    pub node_states: &'a HashMap<NetworkId, ChaosMode>,
    // NEW: We need to know the role (Guardian vs Stronghold)
    pub node_roles: &'a HashMap<NetworkId, NodeRole>,
}

impl<'a> Widget for NetworkRadar<'a> {
    fn render(self, area: Rect, buf: &mut ratatui::buffer::Buffer) {
        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let inner_area = block.inner(area);
        block.render(area, buf);

        Canvas::default()
            .block(Block::default())
            .marker(Marker::Block)
            .x_bounds([-180.0, 180.0])
            .y_bounds([-90.0, 90.0])
            .paint(|ctx| {
                self.draw_grid(ctx);
                self.draw_nodes(ctx);
            })
            .render(inner_area, buf);
    }
}

impl<'a> NetworkRadar<'a> {
    fn draw_grid(&self, ctx: &mut Context) {
        ctx.draw(&CanvasLine {
            x1: -180.0,
            y1: 0.0,
            x2: 180.0,
            y2: 0.0,
            color: Color::DarkGray,
        });
        ctx.draw(&CanvasLine {
            x1: 0.0,
            y1: -90.0,
            x2: 0.0,
            y2: 90.0,
            color: Color::DarkGray,
        });
    }

    fn draw_nodes(&self, ctx: &mut Context) {
        let now = std::time::Instant::now();

        for (net_id, last_seen) in self.nodes {
            let bytes = net_id.0.to_bytes();
            let len = bytes.len();

            // Map PeerID hash to X/Y coordinates
            let b_x = if len > 0 { bytes[len - 1] } else { 0 };
            let b_y = if len > 1 { bytes[len - 2] } else { 0 };

            let angle = (b_x as f64 / 255.0) * 360.0 - 180.0;
            let lat = (b_y as f64 / 255.0) * 180.0 - 90.0;

            let mode = self.node_states.get(net_id).unwrap_or(&ChaosMode::Stable);
            let role = self.node_roles.get(net_id).unwrap_or(&NodeRole::Guardian);

            let color = match mode {
                ChaosMode::Hyperactive => Color::Magenta,
                ChaosMode::Byzantine => Color::Red,
                ChaosMode::PacketLoss(_) => Color::Blue,
                ChaosMode::Stable | ChaosMode::HighLatency(_) => {
                    let age = now.duration_since(*last_seen).as_secs_f32();
                    if age < 2.0 {
                        // Strongholds are Cyan when healthy, Guardians are Green
                        if *role == NodeRole::Stronghold {
                            Color::Cyan
                        } else {
                            Color::Green
                        }
                    } else if age < 10.0 {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    }
                }
            };

            // RENDER DIFFERENT SHAPES
            match role {
                NodeRole::Stronghold => {
                    // Draw a Box for the Stronghold (Bastion)
                    // We make it fairly large (10x10 units)
                    ctx.draw(&Rectangle {
                        x: angle - 5.0,
                        y: lat - 5.0,
                        width: 10.0,
                        height: 10.0,
                        color,
                    });
                    // Optional: Put a label next to it
                    ctx.print(
                        angle + 6.0,
                        lat,
                        Span::styled("STRONGHOLD", Style::default().fg(color)),
                    );
                }
                NodeRole::Guardian => {
                    // Standard Dot for Guardians
                    ctx.draw(&Points {
                        coords: &[(angle, lat)],
                        color,
                    });
                }
            }
        }
    }
}
