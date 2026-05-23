use iced::widget::scrollable::{Catalog, Rail, Scroller, Status, Style};
use iced::{Background, Border, Color, Shadow};

use super::types::style_type::StyleType;

#[derive(Default)]
pub enum ScrollbarType {
    #[default]
    Standard,
}

impl ScrollbarType {
    fn active(&self, style: &StyleType) -> Style {
        let colors = style.get_palette();
        let ext = style.get_extension();
        Style {
            container: iced::widget::container::Style {
                background: Some(Background::Color(Color::TRANSPARENT)),
                border: Border::default(),
                shadow: Shadow::default(),
                snap: true,
                text_color: Some(colors.text_body),
            },
            vertical_rail: Rail {
                background: Some(Background::Color(Color::TRANSPARENT)),
                scroller: Scroller {
                    background: Background::Color(Color { a: ext.alpha_round_borders, ..ext.buttons_color }),
                    border: Border { radius: 15.0.into(), width: 0.0, color: Color::TRANSPARENT },
                },
                border: Border::default(),
            },
            horizontal_rail: Rail {
                background: Some(Background::Color(Color::TRANSPARENT)),
                scroller: Scroller {
                    background: Background::Color(Color { a: ext.alpha_round_borders, ..ext.buttons_color }),
                    border: Border { radius: 15.0.into(), width: 0.0, color: Color::TRANSPARENT },
                },
                border: Border::default(),
            },
            gap: None,
            auto_scroll: iced::widget::scrollable::AutoScroll {
                background: Background::Color(Color { a: 0.8, ..ext.buttons_color }),
                border: Border { radius: 10.0.into(), width: 0.0, color: Color::TRANSPARENT },
                shadow: Shadow::default(),
                icon: colors.text_body,
            },
        }
    }
}

impl Catalog for StyleType {
    type Class<'a> = ScrollbarType;
    fn default<'a>() -> Self::Class<'a> { ScrollbarType::default() }
    fn style(&self, class: &Self::Class<'_>, _status: Status) -> Style { class.active(self) }
}
