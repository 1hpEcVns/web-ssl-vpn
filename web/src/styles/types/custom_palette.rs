use super::palette::Palette;
use super::palette_extension::PaletteExtension;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CustomPalette {
    pub palette: Palette,
    pub extension: PaletteExtension,
}

impl CustomPalette {
    pub fn from_palette(palette: Palette) -> Self {
        Self { palette, extension: palette.generate_palette_extension() }
    }
}
