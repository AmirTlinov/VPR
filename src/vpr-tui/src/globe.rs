use crate::frame::AsciiFrame;
use ratatui::style::Color;

// Hacker-style gradient
const GRADIENT: [char; 10] = [' ', '.', ':', ';', 'i', '1', '0', 'X', '#', '@'];

#[derive(Clone)]
pub struct GlobeRenderer {
    points: Vec<[f32; 3]>,
    tilt_x: f32,
    angular_step: f32,
}

impl GlobeRenderer {
    pub fn new(point_count: usize, tilt_x: f32, angular_step: f32) -> Self {
        Self {
            points: fibonacci_sphere(point_count),
            tilt_x,
            angular_step,
        }
    }

    pub fn angular_step(&self) -> f32 {
        self.angular_step
    }

    pub fn render_frame(&self, width: usize, height: usize, angle_y: f32, tick: u64) -> AsciiFrame {
        let mut frame = AsciiFrame::new(width, height);

        if width == 0 || height == 0 {
            return frame;
        }

        let radius = (width.min(height) as f32 * 0.42).max(8.0);
        let light_dir = normalize([0.18, 0.34, 1.0]);
        let tick_phase = (tick as f32) * 0.015;

        for base in &self.points {
            let mut p = rotate_y(*base, angle_y);
            p = rotate_x(p, self.tilt_x);

            let normal = normalize(p);
            let lon = p[2].atan2(p[0]);
            let lat = normal[1].asin();

            let is_land = land_mask(lon + tick_phase * 0.05, lat);
            let light = (dot(normal, light_dir)).max(0.0);
            let shading = 0.35 + light * 0.65;
            let depth = p[2];

            let x = p[0] * radius;
            let y = p[1] * radius;

            let col = (x * 1.6 + (width as f32 * 0.5)).round() as isize;
            let row = (-y + (height as f32 * 0.5)).round() as isize;

            if row < 0 || col < 0 {
                continue;
            }

            let ch = shade_char(shading, is_land, tick);
            let color = shade_color(is_land, shading, tick);
            frame.put(row as usize, col as usize, depth, ch, color);
        }

        frame
    }
}

fn shade_char(intensity: f32, is_land: bool, tick: u64) -> char {
    let clamped = intensity.clamp(0.0, 1.0);
    let idx = (clamped * (GRADIENT.len() - 1) as f32).round() as usize;
    let glyph = GRADIENT[idx];

    if is_land && glyph == ' ' {
        // Occasional glitch effect for water
        if tick % 17 == 0 { '.' } else { ' ' }
    } else {
        glyph
    }
}

fn shade_color(is_land: bool, intensity: f32, tick: u64) -> Color {
    // Matrix/Watch Dogs palette: Black background, Cyan/Green foreground
    
    let t = intensity.clamp(0.0, 1.0);

    if is_land {
        // Land is bright Cyan/White
        let r = lerp(0, 100, t);
        let g = lerp(200, 255, t);
        let b = lerp(200, 255, t);
        Color::Rgb(r, g, b)
    } else {
        // Water is Dark Blue/Green or Empty
        if t < 0.2 {
             Color::Rgb(0, 20, 40)
        } else {
             // Glitchy water
             if tick % 9 == 0 {
                 Color::Rgb(0, 100, 0)
             } else {
                 Color::Rgb(0, 50, 100)
             }
        }
    }
}

fn lerp(a: u8, b: u8, t: f32) -> u8 {
    (a as f32 + (b as f32 - a as f32) * t) as u8
}

fn land_mask(lon: f32, lat: f32) -> bool {
    let ridge = (lon * 1.7).sin() + (lon * 0.4).cos() * 0.6;
    let gyre = ((lat * 2.6).sin() * 0.5) + ((lat + lon * 0.5).cos() * 0.4);
    let bands = ((lat * 3.3).cos() * (lon * 0.9).sin()) * 0.35;
    ridge + gyre + bands > 0.55
}

fn fibonacci_sphere(count: usize) -> Vec<[f32; 3]> {
    let phi = std::f32::consts::PI * (3.0 - (5.0f32).sqrt());
    (0..count)
        .map(|i| {
            let y = 1.0 - (2.0 * i as f32) / (count as f32 - 1.0);
            let radius = (1.0 - y * y).sqrt();
            let theta = phi * i as f32;
            [theta.cos() * radius, y, theta.sin() * radius]
        })
        .collect()
}

fn rotate_y(p: [f32; 3], angle: f32) -> [f32; 3] {
    let (s, c) = angle.sin_cos();
    [p[0] * c - p[2] * s, p[1], p[0] * s + p[2] * c]
}

fn rotate_x(p: [f32; 3], angle: f32) -> [f32; 3] {
    let (s, c) = angle.sin_cos();
    [p[0], p[1] * c - p[2] * s, p[1] * s + p[2] * c]
}

fn dot(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn normalize(v: [f32; 3]) -> [f32; 3] {
    let mag = (v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).sqrt().max(1e-6);
    [v[0] / mag, v[1] / mag, v[2] / mag]
}

#[cfg(test)]
mod tests {
    use super::*;
    use approx::assert_abs_diff_eq;

    #[test]
    fn fibonacci_sphere_generates_unit_points() {
        let pts = fibonacci_sphere(128);
        for p in pts {
            let mag = (p[0] * p[0] + p[1] * p[1] + p[2] * p[2]).sqrt();
            assert_abs_diff_eq!(mag, 1.0, epsilon = 1e-3);
        }
    }

    #[test]
    fn land_mask_produces_land_and_sea() {
        let mut land = 0;
        let mut sea = 0;
        for lon_i in -4..4 {
            for lat_i in -2..2 {
                if land_mask(lon_i as f32, lat_i as f32) {
                    land += 1;
                } else {
                    sea += 1;
                }
            }
        }
        assert!(land > 0 && sea > 0);
    }

    #[test]
    fn render_frame_has_nonzero_fill() {
        let globe = GlobeRenderer::new(2000, 0.3, 0.18);
        let frame = globe.render_frame(80, 32, 0.0, 0);
        let ratio = frame.occupied_ratio();
        assert!(ratio > 0.18, "ratio too low: {ratio}");
        assert!(ratio < 0.55, "ratio too high: {ratio}");
    }

    #[test]
    fn render_frame_is_fast_enough() {
        use std::time::Instant;

        let globe = GlobeRenderer::new(2000, 0.3, 0.18);
        let start = Instant::now();
        for i in 0..32 {
            let _ = globe.render_frame(96, 40, i as f32 * 0.1, i as u64);
        }

        assert!(
            start.elapsed().as_millis() < 220,
            "frame rendering too slow"
        );
    }
}
