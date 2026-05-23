use iced::Color;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PaletteExtension {
    pub is_nightly: bool,
    pub alpha_chart_badge: f32,
    pub alpha_round_borders: f32,
    pub alpha_round_containers: f32,
    pub buttons_color: Color,
    pub red_alert_color: Color,
}
