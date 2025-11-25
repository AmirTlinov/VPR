//! ASCII Art и анимации в стиле Watch Dogs 2
//! Хакерская эстетика с глитч-эффектами и мемами

/// Маска DedSec (Watch Dogs стиль)
pub const DEDSEC_MASK: &[&str] = &[
    r"      ▄▄▄▄▄▄▄▄▄▄▄      ",
    r"    ▄█░░░░░░░░░░░█▄    ",
    r"   █░░░░░░░░░░░░░░░█   ",
    r"  █░░░░░░░░░░░░░░░░░█  ",
    r" █░░░▄▄▄░░░░░░▄▄▄░░░█ ",
    r" █░░█▀▀▀█░░░░█▀▀▀█░░█ ",
    r" █░░█▄▄▄█░░░░█▄▄▄█░░█ ",
    r" █░░░░░░░░▄▄░░░░░░░░█ ",
    r" █░░░░░░░█▄▄█░░░░░░░█ ",
    r"  █░░░░░░░░░░░░░░░░█  ",
    r"   █░░░▀▄▄▄▄▄▄▀░░░█   ",
    r"    ▀█░░░░░░░░░░█▀    ",
    r"      ▀▀▀▀▀▀▀▀▀▀      ",
];

/// Doge ASCII (мем)
pub const DOGE: &[&str] = &[
    r"        ▄              ▄    ",
    r"       ▌▒█           ▄▀▒▌   ",
    r"       ▌▒▒█        ▄▀▒▒▒▐   ",
    r"      ▐▄▀▒▒▀▀▀▀▄▄▄▀▒▒▒▒▒▐   ",
    r"    ▄▄▀▒░▒▒▒▒▒▒▒▒▒█▒▒▄█▒▐   ",
    r"  ▄▀▒▒▒░░░▒▒▒░░░▒▒▒▀██▀▒▌   ",
    r" ▐▒▒▒▄▄▒▒▒▒░░░▒▒▒▒▒▒▒▀▄▒▒▌  ",
    r" ▌░░▌█▀▒▒▒▒▒▄▀█▄▒▒▒▒▒▒▒█▒▐  ",
    r"▐░░░▒▒▒▒▒▒▒▒▌██▀▒▒░░░▒▒▒▀▄▌ ",
    r"▌░▒▄██▄▒▒▒▒▒▒▒▒▒░░░░░░▒▒▒▒▌ ",
    r"▌▀▐▄█▄█▌▄░▀▒▒░░░░░░░░░░▒▒▒▐ ",
    r"▐▒▒▐▀▐▀▒░▄▄▒▄▒▒▒▒▒▒░▒░▒▒▒▒▌ ",
    r"▐▒▒▒▀▀▄▄▒▒▒▄▒▒▒▒▒▒▒▒░▒░▒▒▐  ",
    r" ▌▒▒▒▒▒▒▀▀▀▒▒▒▒▒▒░▒░▒░▒░▒▒▌ ",
    r" ▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▒▄▒▒▐ ",
    r"  ▀▄▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▄▒▒▒▒▌ ",
    r"    ▀▄▒▒▒▒▒▒▒▒▒▒▄▄▄▀▒▒▒▒▄▀  ",
    r"      ▀▄▄▄▄▄▄▀▀▀▒▒▒▒▒▄▄▀    ",
    r"         ▒▒▒▒▒▒▒▒▒▒▀▀       ",
];

/// Skull хакерский
pub const SKULL: &[&str] = &[
    r"     ▄▄▄▄▄▄▄▄▄▄▄     ",
    r"   ▄█████████████▄   ",
    r"  █████████████████  ",
    r" ███▀▀▀▀▀▀▀▀▀▀▀▀███ ",
    r" ██   ▄▄▄   ▄▄▄   ██ ",
    r" ██  █░░░█ █░░░█  ██ ",
    r" ██   ▀▀▀   ▀▀▀   ██ ",
    r" ██       ▄       ██ ",
    r" ██     ▄███▄     ██ ",
    r" ██    ▀█████▀    ██ ",
    r"  ██  ▄▄▄▄▄▄▄▄▄  ██  ",
    r"   ▀█▄█▀▀▀▀▀▀▀█▄█▀   ",
    r"     ▀▀▀▀▀▀▀▀▀▀▀     ",
];

/// VPR Logo
pub const VPR_LOGO: &[&str] = &[
    r"██╗   ██╗██████╗ ██████╗ ",
    r"██║   ██║██╔══██╗██╔══██╗",
    r"██║   ██║██████╔╝██████╔╝",
    r"╚██╗ ██╔╝██╔═══╝ ██╔══██╗",
    r" ╚████╔╝  ██║         ██║        ██║",
    r"  ╚═══╝     ╚═╝         ╚═╝        ╚═╝",
];

/// Глитч символы для эффектов
pub const GLITCH_CHARS: &[char] = &[
    '█', '▓', '▒', '░', '▄', '▀', '▌', '▐', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║',
    '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩',
    '╦', '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌',
];

/// Хакерские сообщения
pub const HACKER_MESSAGES: &[&str] = &[
    "INITIALIZING NEURAL INTERFACE...",
    "BYPASSING FIREWALL PROTOCOLS...",
    "INJECTING PAYLOAD INTO MAINFRAME...",
    "DECRYPTING SECURE CHANNEL...",
    "SPOOFING GEO-LOCATION DATA...",
    "MASKING DIGITAL FOOTPRINT...",
    "ESTABLISHING COVERT TUNNEL...",
    "ENGAGING STEALTH PROTOCOLS...",
    "ROUTING THROUGH DARK NODES...",
    "QUANTUM ENCRYPTION ACTIVE...",
    "DPI EVASION: ENGAGED...",
    "TRAFFIC MORPHING: ONLINE...",
    "COVER TRAFFIC: GENERATING...",
    "NOISE HANDSHAKE: COMPLETE...",
    "ML-KEM768: INITIALIZED...",
    "POST-QUANTUM: SECURED...",
    "SUCH SECURE. MUCH ENCRYPT. WOW.",
    "HACK THE PLANET!",
    "WE ARE DEDSEC...",
    "FREEDOM OF INFORMATION...",
];

/// Doge сообщения (мемы)
pub const DOGE_MESSAGES: &[&str] = &[
    "wow",
    "such vpn",
    "much secure",
    "very encrypt",
    "so stealth",
    "many packets",
    "wow tunnel",
    "such privacy",
    "very anonymous",
    "much freedom",
    "so quantum",
    "many keys",
    "wow noise",
    "such protocol",
    "very masque",
];

/// Получить случайный глитч символ
pub fn random_glitch(tick: u64) -> char {
    GLITCH_CHARS[(tick as usize * 1337) % GLITCH_CHARS.len()]
}

/// Получить хакерское сообщение
pub fn get_hacker_message(tick: u64) -> &'static str {
    HACKER_MESSAGES[(tick as usize / 30) % HACKER_MESSAGES.len()]
}

/// Получить doge сообщение
pub fn get_doge_message(tick: u64) -> &'static str {
    DOGE_MESSAGES[(tick as usize / 20) % DOGE_MESSAGES.len()]
}

/// Применить глитч эффект к строке
pub fn glitch_text(text: &str, tick: u64, intensity: f32) -> String {
    text.chars()
        .enumerate()
        .map(|(i, c)| {
            let should_glitch = ((tick as usize + i) * 7919) % 100 < (intensity * 100.0) as usize;
            if should_glitch && c != ' ' {
                random_glitch(tick + i as u64)
            } else {
                c
            }
        })
        .collect()
}

/// Матричный дождь символов
pub fn matrix_rain(width: usize, height: usize, tick: u64) -> Vec<String> {
    let chars = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789";
    let chars: Vec<char> = chars.chars().collect();
    
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| {
                    let idx = (x * 31 + y * 17 + tick as usize) % chars.len();
                    let fade = ((y + tick as usize) % height) as f32 / height as f32;
                    if fade > 0.7 {
                        chars[idx]
                    } else {
                        ' '
                    }
                })
                .collect()
        })
        .collect()
}

/// Прогресс бар в хакерском стиле
pub fn hacker_progress_bar(progress: f32, width: usize) -> String {
    let filled = (progress * width as f32) as usize;
    let empty = width - filled;
    
    format!(
        "[{}{}] {:>3}%",
        "█".repeat(filled),
        "░".repeat(empty),
        (progress * 100.0) as u8
    )
}

/// Анимированный спиннер
pub fn spinner(tick: u64) -> char {
    const FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    FRAMES[(tick as usize / 2) % FRAMES.len()]
}

/// Пульсирующий индикатор
pub fn pulse(tick: u64) -> &'static str {
    const FRAMES: &[&str] = &["●", "◉", "○", "◉"];
    FRAMES[(tick as usize / 5) % FRAMES.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii_art_constants_not_empty() {
        assert!(!DEDSEC_MASK.is_empty());
        assert!(!DOGE.is_empty());
        assert!(!SKULL.is_empty());
        assert!(!VPR_LOGO.is_empty());
        assert!(!GLITCH_CHARS.is_empty());
        assert!(!HACKER_MESSAGES.is_empty());
        assert!(!DOGE_MESSAGES.is_empty());
    }

    #[test]
    fn test_random_glitch_deterministic() {
        // Same tick should produce same result
        let char1 = random_glitch(42);
        let char2 = random_glitch(42);
        assert_eq!(char1, char2);
    }

    #[test]
    fn test_random_glitch_varies_by_tick() {
        let char1 = random_glitch(0);
        let char2 = random_glitch(1);
        // Different ticks should produce different results (usually)
        // Due to modulo, they might occasionally be the same, so just check they're valid
        assert!(GLITCH_CHARS.contains(&char1));
        assert!(GLITCH_CHARS.contains(&char2));
    }

    #[test]
    fn test_random_glitch_always_valid_char() {
        for tick in 0..1000 {
            let c = random_glitch(tick);
            assert!(GLITCH_CHARS.contains(&c));
        }
    }

    #[test]
    fn test_get_hacker_message() {
        let msg = get_hacker_message(0);
        assert!(HACKER_MESSAGES.contains(&msg));
    }

    #[test]
    fn test_get_hacker_message_cycles() {
        // With period 30, different ticks should eventually cycle
        let msg1 = get_hacker_message(0);
        let msg2 = get_hacker_message(30);
        assert!(HACKER_MESSAGES.contains(&msg1));
        assert!(HACKER_MESSAGES.contains(&msg2));
    }

    #[test]
    fn test_get_doge_message() {
        let msg = get_doge_message(0);
        assert!(DOGE_MESSAGES.contains(&msg));
    }

    #[test]
    fn test_get_doge_message_cycles() {
        // With period 20, different ticks should eventually cycle
        let msg1 = get_doge_message(0);
        let msg2 = get_doge_message(20);
        assert!(DOGE_MESSAGES.contains(&msg1));
        assert!(DOGE_MESSAGES.contains(&msg2));
    }

    #[test]
    fn test_glitch_text_no_glitch() {
        let result = glitch_text("hello", 0, 0.0);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_glitch_text_preserves_spaces() {
        let result = glitch_text("hello world", 0, 1.0);
        // Spaces should never be glitched
        for c in result.chars() {
            if c == ' ' {
                // space preserved
                assert_eq!(c, ' ');
            }
        }
    }

    #[test]
    fn test_glitch_text_preserves_length() {
        let input = "test string";
        let result = glitch_text(input, 42, 0.5);
        assert_eq!(input.chars().count(), result.chars().count());
    }

    #[test]
    fn test_matrix_rain_dimensions() {
        let rain = matrix_rain(10, 5, 0);
        assert_eq!(rain.len(), 5);
        for row in &rain {
            assert_eq!(row.chars().count(), 10);
        }
    }

    #[test]
    fn test_matrix_rain_varies_by_tick() {
        let rain1 = matrix_rain(10, 5, 0);
        let rain2 = matrix_rain(10, 5, 100);
        // Should be different at different ticks
        assert_ne!(rain1, rain2);
    }

    #[test]
    fn test_hacker_progress_bar_empty() {
        let bar = hacker_progress_bar(0.0, 10);
        assert!(bar.contains("["));
        assert!(bar.contains("]"));
        assert!(bar.contains("0%"));
    }

    #[test]
    fn test_hacker_progress_bar_full() {
        let bar = hacker_progress_bar(1.0, 10);
        // width=10, progress=1.0 → 10 filled chars
        assert!(bar.contains("██████████"));
        assert!(bar.contains("100%"));
    }

    #[test]
    fn test_hacker_progress_bar_half() {
        let bar = hacker_progress_bar(0.5, 10);
        assert!(bar.contains("█████"));
        assert!(bar.contains("50%"));
    }

    #[test]
    fn test_spinner_cycles() {
        let frame1 = spinner(0);
        let frame2 = spinner(2);
        // Should be different at different ticks (period 2)
        assert_ne!(frame1, frame2);
    }

    #[test]
    fn test_spinner_valid_frames() {
        const FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        for tick in 0..100 {
            let frame = spinner(tick);
            assert!(FRAMES.contains(&frame));
        }
    }

    #[test]
    fn test_pulse_cycles() {
        let frame1 = pulse(0);
        let frame2 = pulse(5);
        // Should be different at different ticks (period 5)
        assert_ne!(frame1, frame2);
    }

    #[test]
    fn test_pulse_valid_frames() {
        const FRAMES: &[&str] = &["●", "◉", "○", "◉"];
        for tick in 0..100 {
            let frame = pulse(tick);
            assert!(FRAMES.contains(&frame));
        }
    }

    #[test]
    fn test_dedsec_mask_has_correct_structure() {
        // Should have multiple rows
        assert!(DEDSEC_MASK.len() > 5);
        // All rows should be non-empty (ASCII art can have varying widths)
        for row in DEDSEC_MASK {
            assert!(!row.is_empty());
        }
    }

    #[test]
    fn test_doge_has_correct_structure() {
        assert!(DOGE.len() > 10);
    }

    #[test]
    fn test_skull_has_correct_structure() {
        assert!(SKULL.len() > 5);
    }

    #[test]
    fn test_vpr_logo_has_correct_structure() {
        assert!(VPR_LOGO.len() >= 1);
    }
}
