use iced::Color;
use super::palette_extension::PaletteExtension;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    pub primary: Color,
    pub secondary: Color,
    pub outgoing: Color,
    pub starred: Color,
    pub text_headers: Color,
    pub text_body: Color,
}

impl Palette {
    pub fn generate_buttons_color(self) -> Color {
        let primary = self.primary;
        let is_nightly = primary.r + primary.g + primary.b <= 1.5;
        if is_nightly {
            Color { r: f32::min(primary.r + 0.15, 1.0), g: f32::min(primary.g + 0.15, 1.0), b: f32::min(primary.b + 0.15, 1.0), a: 1.0 }
        } else {
            Color { r: f32::max(primary.r - 0.15, 0.0), g: f32::max(primary.g - 0.15, 0.0), b: f32::max(primary.b - 0.15, 0.0), a: 1.0 }
        }
    }

    pub fn generate_palette_extension(self) -> PaletteExtension {
        let primary = self.primary;
        let is_nightly = primary.r + primary.g + primary.b <= 1.5;
        let alpha_chart_badge = if is_nightly { 0.3 } else { 0.5 };
        let alpha_round_borders = if is_nightly { 0.3 } else { 0.6 };
        let alpha_round_containers = if is_nightly { 0.12 } else { 0.24 };
        let buttons_color = self.generate_buttons_color();
        let red_alert_color = if is_nightly {
            Color { r: 1.0, g: 0.4, b: 0.4, a: 1.0 }
        } else {
            Color { r: 0.7, g: 0.0, b: 0.0, a: 1.0 }
        };
        PaletteExtension { is_nightly, alpha_chart_badge, alpha_round_borders, alpha_round_containers, buttons_color, red_alert_color }
    }

    pub fn mix_colors(color_1: Color, color_2: Color) -> Color {
        Color {
            r: f32::midpoint(color_1.r, color_2.r),
            g: f32::midpoint(color_1.g, color_2.g),
            b: f32::midpoint(color_1.b, color_2.b),
            a: 1.0,
        }
    }
}
