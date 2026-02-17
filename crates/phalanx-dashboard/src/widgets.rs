use ratatui::{
    style::{Color, Style},
    widgets::{Widget, Block, Borders},
    layout::Rect,
};
use ratatui::widgets::canvas::{Canvas, Points, Line as CanvasLine, Context};
use phalanx_core::primitives::identity::NetworkId;

pub struct NetworkRadar<'a> {
    pub title: &'a str,
    pub nodes: &'a [(NetworkId, std::time::Instant)], // ID + Last Heartbeat
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
            // 1. Deterministic Projection
            // Use the first byte for Angle (-180 to 180)
            // Use the second byte for Radius/Latitude (-90 to 90)
            let bytes = net_id.0.to_bytes(); 
            let angle = (bytes[0] as f64 / 255.0) * 360.0 - 180.0;
            let lat = (bytes[1] as f64 / 255.0) * 180.0 - 90.0;

            // 2. Vitality Decay (Fade out if heartbeat is old)
            let age = now.duration_since(*last_seen).as_secs_f32();
            let color = if age < 1.0 {
                Color::Green // Fresh
            } else if age < 5.0 {
                Color::Yellow // Stale
            } else {
                Color::Red // Dead/Ghost
            };

            ctx.draw(&Points {
                coords: &[(angle, lat)],
                color,
            });
        }
    }
}