use ratatui::{
    style::{Color, Style},
    symbols::Marker,
    widgets::{Widget, Block, Borders},
    layout::Rect,
};
use ratatui::widgets::canvas::{Canvas, Points, Line as CanvasLine, Context};
use std::collections::HashMap;
use phalanx_core::primitives::identity::NetworkId;
use phalanx_core::security::telemetry::ChaosMode; // Import ChaosMode

pub struct NetworkRadar<'a> {
    pub title: &'a str,
    pub nodes: &'a [(NetworkId, std::time::Instant)],
    // NEW: Pass in the known states of the nodes
    pub node_states: &'a HashMap<NetworkId, ChaosMode>,
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
            x1: -180.0, y1: 0.0, x2: 180.0, y2: 0.0,
            color: Color::DarkGray,
        });
        ctx.draw(&CanvasLine {
            x1: 0.0, y1: -90.0, x2: 0.0, y2: 90.0,
            color: Color::DarkGray,
        });
    }

    fn draw_nodes(&self, ctx: &mut Context) {
        let now = std::time::Instant::now();

        for (net_id, last_seen) in self.nodes {
            let bytes = net_id.0.to_bytes(); 
            let len = bytes.len();
            
            let b_x = if len > 0 { bytes[len - 1] } else { 0 };
            let b_y = if len > 1 { bytes[len - 2] } else { 0 };

            let angle = (b_x as f64 / 255.0) * 360.0 - 180.0;
            let lat = (b_y as f64 / 255.0) * 180.0 - 90.0;

            // DETERMINE COLOR BASED ON CHAOS MODE
            let mode = self.node_states.get(net_id).unwrap_or(&ChaosMode::Stable);
            
            let color = match mode {
                ChaosMode::Hyperactive => Color::Magenta, // VAMPIRE = PURPLE
                ChaosMode::Byzantine => Color::Red,      // CORRUPT = RED
                ChaosMode::PacketLoss(_) => Color::Blue, // FLAKY = BLUE
                ChaosMode::Stable | ChaosMode::HighLatency(_) => {
                    // Fallback to Vitality (Age)
                    let age = now.duration_since(*last_seen).as_secs_f32();
                    if age < 2.0 {
                        Color::Green 
                    } else if age < 10.0 {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    }
                }
            };

            ctx.draw(&Points {
                coords: &[(angle, lat)],
                color,
            });
        }
    }
}