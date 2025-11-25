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
