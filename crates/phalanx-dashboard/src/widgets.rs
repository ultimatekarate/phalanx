// crates/phalanx-dashboard/src/widgets.rs

use phalanx_proto::identity::{NetworkId, NodeRole};
use phalanx_proto::telemetry::ChaosMode;
use ratatui::widgets::canvas::{Canvas, Context, Line as CanvasLine, Points, Rectangle};
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    symbols::Marker,
    text::Span,
    widgets::{Block, Borders, Widget},
};
use std::collections::HashMap;

#[derive(PartialEq)]
pub enum VectorStyle {
    Standard,
    Attack,
}

pub struct TrafficVector {
    pub from: NetworkId,
    pub to: NetworkId,
    pub age_seconds: f32,
    pub style: VectorStyle,
}

pub struct NetworkRadar<'a> {
    pub title: &'a str,
    pub nodes: &'a [(NetworkId, std::time::Instant)],
    pub node_states: &'a HashMap<NetworkId, ChaosMode>,
    pub node_roles: &'a HashMap<NetworkId, NodeRole>,
    pub traffic: &'a [TrafficVector],
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
                self.draw_traffic(ctx);
                self.draw_nodes(ctx);
            })
            .render(inner_area, buf);
    }
}

impl<'a> NetworkRadar<'a> {
    fn get_coords(net_id: &NetworkId) -> (f64, f64) {
        let bytes = net_id.0.as_bytes();
        let len = bytes.len();

        let b_x = if len > 0 { bytes[len - 1] } else { 0 };
        let b_y = if len > 1 { bytes[len - 2] } else { 0 };

        let angle = (b_x as f64 / 255.0) * 360.0 - 180.0;
        let lat = (b_y as f64 / 255.0) * 180.0 - 90.0;

        (angle, lat)
    }

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

    fn draw_traffic(&self, ctx: &mut Context) {
        for vector in self.traffic {
            let (x1, y1) = Self::get_coords(&vector.from);
            let (x2, y2) = Self::get_coords(&vector.to);

            if (x1 - x2).abs() < 0.1 && (y1 - y2).abs() < 0.1 {
                continue;
            }

            let line_color = match vector.style {
                VectorStyle::Attack => {
                    if vector.age_seconds < 0.5 {
                        Color::Red
                    } else {
                        Color::Magenta
                    }
                }
                VectorStyle::Standard => {
                    if vector.age_seconds < 0.2 {
                        Color::White
                    } else if vector.age_seconds < 0.8 {
                        Color::Cyan
                    } else if vector.age_seconds < 1.5 {
                        Color::Blue
                    } else {
                        Color::DarkGray
                    }
                }
            };

            ctx.draw(&CanvasLine {
                x1,
                y1,
                x2,
                y2,
                color: line_color,
            });
        }
    }

    fn draw_nodes(&self, ctx: &mut Context) {
        let current_time = std::time::Instant::now();

        for (net_id, last_seen) in self.nodes {
            let (angle, lat) = Self::get_coords(net_id);

            let node_mode = self.node_states.get(net_id).unwrap_or(&ChaosMode::Stable);
            let node_role = self.node_roles.get(net_id).unwrap_or(&NodeRole::Guardian);

            let node_color = match node_mode {
                ChaosMode::Hyperactive => Color::Magenta,
                ChaosMode::Byzantine => Color::Red,
                ChaosMode::PacketLoss(_) => Color::Blue,
                ChaosMode::Stable | ChaosMode::HighLatency(_) => {
                    let idle_duration_seconds =
                        current_time.duration_since(*last_seen).as_secs_f32();
                    if idle_duration_seconds < 2.0 {
                        if *node_role == NodeRole::Stronghold {
                            Color::Cyan
                        } else {
                            Color::Green
                        }
                    } else if idle_duration_seconds < 10.0 {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    }
                }
            };

            match node_role {
                NodeRole::Stronghold => {
                    ctx.draw(&Rectangle {
                        x: angle - 5.0,
                        y: lat - 5.0,
                        width: 10.0,
                        height: 10.0,
                        color: node_color,
                    });
                    ctx.print(
                        angle + 6.0,
                        lat,
                        Span::styled("STRONGHOLD", Style::default().fg(node_color)),
                    );
                }
                NodeRole::Guardian => {
                    ctx.draw(&Points {
                        coords: &[(angle, lat)],
                        color: node_color,
                    });
                }
            }
        }
    }
}
