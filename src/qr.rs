use qrcode::QrCode;

/// Render a QR code as a string using Unicode block characters.
/// Uses Dense1x2 encoding (2 vertical pixels per character) for compact display.
/// Inverted colors for dark terminal backgrounds.
pub fn render_qr(data: &str) -> String {
    let code = match QrCode::new(data) {
        Ok(c) => c,
        Err(_) => return String::from("  [QR code generation failed]"),
    };

    let modules = code.to_colors();
    let width = code.width();
    let height = modules.len() / width;

    let mut result = String::new();

    // Add quiet zone (1 row top)
    let full_width = width + 4; // 2 chars padding each side
    let blank_line: String = " ".repeat(full_width);
    result.push_str("  ");
    result.push_str(&blank_line);
    result.push('\n');

    // Process 2 rows at a time using half-block characters
    let mut y = 0;
    while y < height {
        result.push_str("    "); // left padding

        for x in 0..width {
            let top = modules
                .get(y * width + x)
                .copied()
                .unwrap_or(qrcode::Color::Light);
            let bottom = if y + 1 < height {
                modules
                    .get((y + 1) * width + x)
                    .copied()
                    .unwrap_or(qrcode::Color::Light)
            } else {
                qrcode::Color::Light
            };

            // Inverted for dark terminals: Dark QR modules = white terminal pixels
            match (top, bottom) {
                (qrcode::Color::Dark, qrcode::Color::Dark) => result.push('█'),
                (qrcode::Color::Dark, qrcode::Color::Light) => result.push('▀'),
                (qrcode::Color::Light, qrcode::Color::Dark) => result.push('▄'),
                (qrcode::Color::Light, qrcode::Color::Light) => result.push(' '),
            }
        }

        result.push_str("  "); // right padding
        result.push('\n');
        y += 2;
    }

    // Add quiet zone (1 row bottom)
    result.push_str("  ");
    result.push_str(&blank_line);
    result.push('\n');

    result
}
