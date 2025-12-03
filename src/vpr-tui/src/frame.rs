use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

#[derive(Clone, Copy, Debug)]
pub struct Pixel {
    pub ch: char,
    pub color: Color,
    pub depth: f32,
}

pub struct AsciiFrame {
    width: usize,
    height: usize,
    pixels: Vec<Pixel>,
}

impl AsciiFrame {
    pub fn new(width: usize, height: usize) -> Self {
        let blank = Pixel {
            ch: ' ',
            color: Color::Reset,
            depth: f32::NEG_INFINITY,
        };

        Self {
            width,
            height,
            pixels: vec![blank; width * height],
        }
    }

    #[inline]
    fn idx(&self, row: usize, col: usize) -> usize {
        row * self.width + col
    }

    #[inline]
    pub fn put(&mut self, row: usize, col: usize, depth: f32, ch: char, color: Color) {
        if row >= self.height || col >= self.width {
            return;
        }

        let idx = self.idx(row, col);
        if depth > self.pixels[idx].depth {
            self.pixels[idx] = Pixel { ch, color, depth };
        }
    }

    pub fn to_paragraph(&self) -> Paragraph<'static> {
        Paragraph::new(self.to_lines())
    }

    pub fn to_lines(&self) -> Vec<Line<'static>> {
        let mut lines = Vec::with_capacity(self.height);

        for row in 0..self.height {
            let mut spans: Vec<Span<'static>> = Vec::with_capacity(self.width / 2 + 1);
            let mut current_color = self.pixels[self.idx(row, 0)].color;
            let mut buffer = String::new();

            for col in 0..self.width {
                let pixel = self.pixels[self.idx(row, col)];
                if pixel.color == current_color {
                    buffer.push(pixel.ch);
                } else {
                    spans.push(Span::styled(
                        buffer.clone(),
                        Style::default().fg(current_color),
                    ));
                    buffer.clear();
                    buffer.push(pixel.ch);
                    current_color = pixel.color;
                }
            }

            if !buffer.is_empty() {
                spans.push(Span::styled(buffer, Style::default().fg(current_color)));
            }

            lines.push(Line::from(spans));
        }

        lines
    }

    pub fn as_strings(&self) -> Vec<String> {
        let mut rows = Vec::with_capacity(self.height);
        for row in 0..self.height {
            let mut line = String::with_capacity(self.width);
            for col in 0..self.width {
                line.push(self.pixels[self.idx(row, col)].ch);
            }
            rows.push(line);
        }
        rows
    }

    pub fn occupied_ratio(&self) -> f32 {
        let filled = self.pixels.iter().filter(|p| p.ch != ' ').count() as f32;
        filled / self.pixels.len() as f32
    }
}
