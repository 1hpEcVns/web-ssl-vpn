use iced::border::Radius;
use iced::widget::container::{Catalog, Style};
use iced::{Background, Border, Color, Shadow};

use super::types::style_type::StyleType;

#[derive(Default, Clone)]
pub enum ContainerType {
    #[default]
    Standard,
    BorderedRound,
    Tooltip,
    Badge,
    Modal,
    SolidColor(iced::Color),
}

impl ContainerType {
    fn appearance(&self, style: &StyleType) -> Style {
        let colors = style.get_palette();
        let ext = style.get_extension();
        Style {
            text_color: match self {
                ContainerType::SolidColor(_) => Some(Color::TRANSPARENT),
                _ => Some(colors.text_body),
            },
            background: Some(match self {
                ContainerType::Tooltip => Background::Color(ext.buttons_color),
                ContainerType::BorderedRound => Background::Color(Color {
                    a: ext.alpha_round_containers,
                    ..ext.buttons_color
                }),
                ContainerType::Badge => Background::Color(Color {
                    a: ext.alpha_chart_badge,
                    ..colors.secondary
                }),
                ContainerType::Modal => Background::Color(colors.primary),
                ContainerType::Standard => Background::Color(Color::TRANSPARENT),
                ContainerType::SolidColor(c) => Background::Color(*c),
            }),
            border: Border {
                radius: match self {
                    ContainerType::BorderedRound => 15.0.into(),
                    ContainerType::Badge => 100.0.into(),
                    ContainerType::Tooltip => 7.0.into(),
                    ContainerType::SolidColor(_) => 4.0.into(),
                    _ => 0.0.into(),
                },
                width: match self {
                    ContainerType::Standard => 0.0,
                    ContainerType::Tooltip => 1.0,
                    ContainerType::BorderedRound => 2.0,
                    _ => 1.0,
                },
                color: Color { a: ext.alpha_round_borders, ..ext.buttons_color },
            },
            shadow: Shadow::default(),
            snap: true,
        }
    }
}

impl Catalog for StyleType {
    type Class<'a> = ContainerType;
    fn default<'a>() -> Self::Class<'a> { Self::Class::default() }
    fn style(&self, class: &Self::Class<'_>) -> Style { class.appearance(self) }
}
