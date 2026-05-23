use iced::Color;

use super::types::style_type::StyleType;

#[derive(Copy, Clone, Default, PartialEq)]
pub enum TextType {
    #[default]
    Standard,
    Incoming,
    Outgoing,
    Title,
    Subtitle,
    Danger,
    Dimmed,
    Custom(iced::Color),
}

impl TextType {
    pub fn color(self) -> Color {
        match self {
            TextType::Custom(c) => c,
            _ => highlight(&StyleType::NordDark, self),
        }
    }
}

impl iced::widget::text::Catalog for StyleType {
    type Class<'a> = TextType;
    fn default<'a>() -> Self::Class<'a> { TextType::default() }
    fn style(&self, class: &Self::Class<'_>) -> iced::widget::text::Style {
        iced::widget::text::Style { color: Some(highlight(self, *class)) }
    }
}

pub fn highlight(style: &StyleType, element: TextType) -> Color {
    let colors = style.get_palette();
    let ext = style.get_extension();
    let secondary = colors.secondary;
    let is_nightly = style.get_extension().is_nightly;
    match element {
        TextType::Title => {
            let (p1, c) = if is_nightly { (0.6, 1.0) } else { (0.9, 0.7) };
            Color { r: c * (1.0 - p1) + secondary.r * p1, g: c * (1.0 - p1) + secondary.g * p1, b: c * (1.0 - p1) + secondary.b * p1, a: 1.0 }
        }
        TextType::Subtitle => {
            let (p1, c) = if is_nightly { (0.4, 1.0) } else { (0.6, 0.7) };
            Color { r: c * (1.0 - p1) + secondary.r * p1, g: c * (1.0 - p1) + secondary.g * p1, b: c * (1.0 - p1) + secondary.b * p1, a: 1.0 }
        }
        TextType::Incoming => colors.secondary,
        TextType::Outgoing => colors.outgoing,
        TextType::Danger => ext.red_alert_color,
        TextType::Standard => colors.text_body,
        TextType::Dimmed => Color { a: ext.alpha_chart_badge, ..colors.text_body },
        TextType::Custom(c) => c,
    }
}
