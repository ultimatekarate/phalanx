use ratatui::{
    style::{Color, Style},
    symbols::Marker, // Added Marker for better visibility
    widgets::{Widget, Block, Borders},
    layout::Rect,
};
use ratatui::widgets::canvas::{Canvas, Points, Line as CanvasLine, Context};
use phalanx_core::primitives::identity::NetworkId;

pub struct NetworkRadar<'a> {
    pub title: &'a str,
    pub nodes: &'a [(NetworkId, std::time::Instant)], 
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
            .block(Block::default()) // Canvas handles its own block if needed, but we drew outer
            .marker(Marker::Block)   // FIX: Use Block marker for high visibility
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
            // FIX: Use TAIL bytes for entropy. 
            // The head bytes of a PeerId are constant headers (0x12, 0x20), 
            // which caused all points to stack on top of each other.
            let bytes = net_id.0.to_bytes(); 
            let len = bytes.len();
            
            // Safety check: ensure we have bytes. If not, map to 0.
            let b_x = if len > 0 { bytes[len - 1] } else { 0 };
            let b_y = if len > 1 { bytes[len - 2] } else { 0 };

            let angle = (b_x as f64 / 255.0) * 360.0 - 180.0;
            let lat = (b_y as f64 / 255.0) * 180.0 - 90.0;

            // Vitality Decay
            let age = now.duration_since(*last_seen).as_secs_f32();
            let color = if age < 2.0 {
                Color::Green // Fresh
            } else if age < 10.0 {
                Color::Yellow // Stale
            } else {
                Color::Red // Ghost
            };

            ctx.draw(&Points {
                coords: &[(angle, lat)],
                color,
            });
        }
    }
}