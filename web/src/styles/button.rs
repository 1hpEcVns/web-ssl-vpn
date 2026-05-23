use iced::border::Radius;
use iced::widget::button;
use iced::widget::button::{Catalog, Status, Style};
use iced::{Background, Border, Color, Shadow, Vector};

use super::types::palette::Palette;
use super::types::style_type::StyleType;

#[derive(Default)]
pub enum ButtonType {
    #[default]
    Standard,
    BorderedRound,
    BorderedRoundSelected,
    TabActive,
    TabInactive,
    Neutral,
    Alert,
}

impl ButtonType {
    fn active(&self, style: &StyleType) -> button::Style {
        let colors = style.get_palette();
        let ext = style.get_extension();
        button::Style {
            background: Some(match self {
                ButtonType::TabActive | ButtonType::BorderedRoundSelected => {
                    Background::Color(Palette::mix_colors(colors.primary, ext.buttons_color))
                }
                ButtonType::BorderedRound => Background::Color(Color {
                    a: ext.alpha_round_containers, ..ext.buttons_color
                }),
                ButtonType::Neutral => Background::Color(Color::TRANSPARENT),
                _ => Background::Color(ext.buttons_color),
            }),
            border: Border {
                radius: match self {
                    ButtonType::Neutral => 0.0.into(),
                    ButtonType::TabActive | ButtonType::TabInactive => {
                        Radius::new(0).bottom(30)
                    }
                    ButtonType::BorderedRound | ButtonType::BorderedRoundSelected => 12.0.into(),
                    _ => 180.0.into(),
                },
                width: match self {
                    ButtonType::TabActive | ButtonType::TabInactive | ButtonType::Neutral => 0.0,
                    ButtonType::BorderedRound => 2.0,
                    _ => 1.0,
                },
                color: match self {
                    ButtonType::Alert => ext.red_alert_color,
                    ButtonType::BorderedRound => Color { a: ext.alpha_round_borders, ..ext.buttons_color },
                    _ => colors.secondary,
                },
            },
            text_color: colors.text_body,
            shadow: match self {
                ButtonType::TabActive | ButtonType::TabInactive => Shadow {
                    color: Color::BLACK, offset: Vector::new(3.0, 2.0), blur_radius: 4.0,
                },
                _ => Shadow::default(),
            },
            snap: true,
        }
    }

    fn hovered(&self, style: &StyleType) -> button::Style {
        let colors = style.get_palette();
        let ext = style.get_extension();
        button::Style {
            shadow: match self {
                ButtonType::Neutral => Shadow::default(),
                _ => Shadow {
                    color: Color::BLACK,
                    offset: match self {
                        ButtonType::TabActive | ButtonType::TabInactive => Vector::new(3.0, 3.0),
                        _ => Vector::new(0.0, 2.0),
                    },
                    blur_radius: match self {
                        ButtonType::TabActive | ButtonType::TabInactive => 4.0,
                        _ => 2.0,
                    },
                },
            },
            background: Some(match self {
                ButtonType::Neutral => Background::Color(Color { a: ext.alpha_round_borders, ..ext.buttons_color }),
                ButtonType::BorderedRoundSelected => Background::Color(ext.buttons_color),
                _ => Background::Color(Palette::mix_colors(colors.primary, ext.buttons_color)),
            }),
            border: Border {
                radius: match self {
                    ButtonType::Neutral => 0.0.into(),
                    ButtonType::TabActive | ButtonType::TabInactive => Radius::new(0).bottom(30),
                    ButtonType::BorderedRound | ButtonType::BorderedRoundSelected => 12.0.into(),
                    _ => 180.0.into(),
                },
                width: match self {
                    ButtonType::TabActive | ButtonType::TabInactive | ButtonType::Neutral | ButtonType::BorderedRound => 0.0,
                    _ => 1.0,
                },
                color: match self {
                    ButtonType::Alert => ext.red_alert_color,
                    ButtonType::BorderedRound => Color { a: ext.alpha_round_borders, ..ext.buttons_color },
                    ButtonType::Neutral => ext.buttons_color,
                    _ => colors.secondary,
                },
            },
            text_color: colors.text_body,
            snap: true,
        }
    }

    fn disabled(&self, style: &StyleType) -> button::Style {
        let colors = style.get_palette();
        let ext = style.get_extension();
        let s = self.active(style);
        button::Style {
            background: Some(Background::Color(Color { a: ext.alpha_chart_badge, ..ext.buttons_color })),
            text_color: Color { a: ext.alpha_chart_badge, ..colors.text_body },
            ..s
        }
    }
}

impl Catalog for StyleType {
    type Class<'a> = ButtonType;
    fn default<'a>() -> Self::Class<'a> { Self::Class::default() }
    fn style(&self, class: &Self::Class<'_>, status: Status) -> Style {
        match status {
            Status::Active | Status::Pressed => class.active(self),
            Status::Hovered => class.hovered(self),
            Status::Disabled => class.disabled(self),
        }
    }
}
