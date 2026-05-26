use iced::theme::{Base, Mode, Style};
use iced::color;
use iced::widget::text_input;
use iced::Border;
use std::sync::LazyLock;

use super::palette::Palette;
use super::palette_extension::PaletteExtension;
use super::custom_palette::CustomPalette;

static NORD_DARK_PALETTE: LazyLock<Palette> = LazyLock::new(|| Palette {
    primary: color!(0x0d0f17),
    secondary: color!(0x7aa2f7),
    outgoing: color!(0x9ece6a),
    starred: color!(0xff9e64),
    text_headers: color!(0x0d0f17),
    text_body: color!(0xc0caf5),
});
static NORD_DARK_EXT: LazyLock<PaletteExtension> =
    LazyLock::new(|| NORD_DARK_PALETTE.generate_palette_extension());

static TOKYO_DARK_PALETTE: LazyLock<Palette> = LazyLock::new(|| Palette {
    primary: color!(0x1a1b26),
    secondary: color!(0x7dcfff),
    outgoing: color!(0x9ece6a),
    starred: color!(0xff9e64),
    text_headers: color!(0x1a1b26),
    text_body: color!(0xc0caf5),
});
static TOKYO_DARK_EXT: LazyLock<PaletteExtension> =
    LazyLock::new(|| TOKYO_DARK_PALETTE.generate_palette_extension());

static CATPPUCCIN_DARK_PALETTE: LazyLock<Palette> = LazyLock::new(|| Palette {
    primary: color!(0x1e1e2e),
    secondary: color!(0xcba6f7),
    outgoing: color!(0xa6e3a1),
    starred: color!(0xf9e2af),
    text_headers: color!(0x1e1e2e),
    text_body: color!(0xcdd6f4),
});
static CATPPUCCIN_DARK_EXT: LazyLock<PaletteExtension> =
    LazyLock::new(|| CATPPUCCIN_DARK_PALETTE.generate_palette_extension());

#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub enum StyleType {
    #[default]
    NordDark,
    TokyoDark,
    CatppuccinDark,
    Custom(CustomPalette),
}

impl Base for StyleType {
    fn default(_preference: Mode) -> Self { <Self as Default>::default() }
    fn mode(&self) -> Mode {
        if self.get_extension().is_nightly { Mode::Dark } else { Mode::Light }
    }
    fn base(&self) -> Style {
        let colors = self.get_palette();
        Style { background_color: colors.primary, text_color: colors.text_body }
    }
    fn palette(&self) -> Option<iced::theme::Palette> { None }
    fn name(&self) -> &str {
        match self {
            Self::NordDark => "Nord Dark",
            Self::TokyoDark => "Tokyo Dark",
            Self::CatppuccinDark => "Catppuccin Dark",
            Self::Custom(_) => "Custom",
        }
    }
}

impl StyleType {
    pub fn get_palette(self) -> Palette {
        match self {
            Self::NordDark => *NORD_DARK_PALETTE,
            Self::TokyoDark => *TOKYO_DARK_PALETTE,
            Self::CatppuccinDark => *CATPPUCCIN_DARK_PALETTE,
            Self::Custom(c) => c.palette,
        }
    }

    pub fn get_extension(self) -> PaletteExtension {
        match self {
            Self::NordDark => *NORD_DARK_EXT,
            Self::TokyoDark => *TOKYO_DARK_EXT,
            Self::CatppuccinDark => *CATPPUCCIN_DARK_EXT,
            Self::Custom(c) => c.extension,
        }
    }
}

impl text_input::Catalog for StyleType {
    type Class<'a> = ();

    fn default<'a>() -> Self::Class<'a> {}

    fn style(&self, _class: &Self::Class<'_>, status: text_input::Status) -> text_input::Style {
        let p = self.get_palette();
        let active = text_input::Style {
            background: iced::Background::Color(p.primary),
            border: Border { radius: 6.0.into(), width: 1.0, color: color!(0x333355) },
            icon: p.text_body,
            placeholder: color!(0x555588),
            value: p.text_body,
            selection: color!(0x7aa2f7),
        };
        match status {
            text_input::Status::Active => active,
            text_input::Status::Focused { .. } => text_input::Style {
                border: Border { color: p.secondary, ..active.border },
                ..active
            },
            text_input::Status::Hovered => text_input::Style {
                border: Border { color: color!(0x555577), ..active.border },
                ..active
            },
            text_input::Status::Disabled => text_input::Style {
                background: iced::Background::Color(color!(0x0a0b12)),
                value: color!(0x444466),
                placeholder: color!(0x333344),
                ..active
            },
        }
    }
}
