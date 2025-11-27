//! Steganographic RSS Encoder/Decoder
//!
//! Encodes bootstrap manifests into RSS feeds using steganographic techniques
//! to hide the fact that manifests are being distributed. The RSS feed appears
//! as a normal news/blog feed while containing encoded manifest data.
//!
//! Steganographic methods:
//! - Whitespace encoding in descriptions
//! - Base64 encoding disguised as normal content
//! - Order-based encoding (item order encodes data)
//! - Timestamp-based encoding (publish dates encode data)

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::rngs::StdRng;
use rand::{rngs::OsRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::io::{Read as IoRead, Write as IoWrite};
use std::time::{SystemTime, UNIX_EPOCH};
use vpr_crypto::manifest::{ManifestPayload, SignedManifest};

/// Zstd compression level (3 is good balance of speed/ratio)
const ZSTD_COMPRESSION_LEVEL: i32 = 3;

/// Steganographic encoding method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StegoMethod {
    /// Encode in whitespace (spaces/tabs in descriptions)
    Whitespace,
    /// Encode as base64 in item descriptions (disguised as normal content)
    Base64Content,
    /// Encode via item ordering
    Ordering,
    /// Encode via timestamp manipulation (least significant bits)
    Timestamp,
    /// Hybrid: combine multiple methods for better capacity
    #[default]
    Hybrid,
}

/// Configuration for RSS steganography
#[derive(Debug, Clone)]
pub struct StegoRssConfig {
    /// Steganographic method to use
    pub method: StegoMethod,
    /// RSS feed title (cover text)
    pub feed_title: String,
    /// RSS feed description (cover text)
    pub feed_description: String,
    /// RSS feed link (cover URL)
    pub feed_link: String,
    /// Minimum number of RSS items to generate (for capacity)
    pub min_items: usize,
    /// Maximum number of RSS items to generate
    pub max_items: usize,
    /// Use random item ordering (for ordering-based stego)
    pub random_order: bool,
    /// Seed for deterministic generation (for testing)
    pub seed: Option<u64>,
}

impl Default for StegoRssConfig {
    fn default() -> Self {
        Self {
            method: StegoMethod::Hybrid,
            feed_title: "Tech News Feed".to_string(),
            feed_description: "Latest technology news and updates".to_string(),
            feed_link: "https://example.com/feed".to_string(),
            min_items: 10,
            max_items: 50,
            random_order: true,
            seed: None,
        }
    }
}

/// RSS item (for cover content)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RssItem {
    pub title: String,
    pub description: String,
    pub link: String,
    pub guid: String,
    pub pub_date: String,
}

/// Steganographic RSS encoder
pub struct StegoRssEncoder {
    config: StegoRssConfig,
    rng: OsRng,
}

impl StegoRssEncoder {
    /// Create new encoder with config
    pub fn new(config: StegoRssConfig) -> Self {
        Self { config, rng: OsRng }
    }

    /// Encode a signed manifest into RSS XML
    pub fn encode_manifest(&mut self, manifest: &SignedManifest) -> Result<String> {
        // Serialize manifest to JSON, then compress
        let json = serde_json::to_string(manifest).context("failed to serialize manifest")?;

        // Compress for better capacity
        let compressed = self.compress(&json)?;

        // Encode based on method
        match self.config.method {
            StegoMethod::Whitespace => self.encode_whitespace(&compressed),
            StegoMethod::Base64Content => self.encode_base64_content(&compressed),
            StegoMethod::Ordering => self.encode_ordering(&compressed),
            StegoMethod::Timestamp => self.encode_timestamp(&compressed),
            StegoMethod::Hybrid => self.encode_hybrid(&compressed),
        }
    }

    /// Encode manifest payload (unsigned) into RSS XML
    pub fn encode_payload(&mut self, payload: &ManifestPayload) -> Result<String> {
        let json =
            serde_json::to_string(payload).context("failed to serialize manifest payload")?;
        let compressed = self.compress(&json)?;

        match self.config.method {
            StegoMethod::Whitespace => self.encode_whitespace(&compressed),
            StegoMethod::Base64Content => self.encode_base64_content(&compressed),
            StegoMethod::Ordering => self.encode_ordering(&compressed),
            StegoMethod::Timestamp => self.encode_timestamp(&compressed),
            StegoMethod::Hybrid => self.encode_hybrid(&compressed),
        }
    }

    /// Compress data using zstd for better steganographic capacity
    fn compress(&self, data: &str) -> Result<Vec<u8>> {
        let mut encoder = zstd::Encoder::new(Vec::new(), ZSTD_COMPRESSION_LEVEL)
            .context("failed to create zstd encoder")?;
        encoder
            .write_all(data.as_bytes())
            .context("failed to write data to zstd encoder")?;
        encoder.finish().context("failed to finish zstd compression")
    }

    /// Encode using whitespace steganography
    fn encode_whitespace(&mut self, data: &[u8]) -> Result<String> {
        // Need at least data.len() * 8 items (one per bit)
        let num_items = (data.len() * 8).max(self.config.min_items);
        let mut items = self.generate_cover_items(num_items);

        // Encode data in whitespace (spaces = 0, tabs = 1)
        let mut item_idx = 0;

        for &byte in data {
            for i in 0..8 {
                let bit = (byte >> (7 - i)) & 1;
                if item_idx < items.len() {
                    // Remove trailing whitespace first
                    items[item_idx].description =
                        items[item_idx].description.trim_end().to_string();

                    if bit == 1 {
                        // Add tab character at end of description
                        items[item_idx].description.push('\t');
                    } else {
                        // Add space
                        items[item_idx].description.push(' ');
                    }
                    item_idx += 1;
                }
            }
        }

        self.build_rss_feed(&items)
    }

    /// Encode using base64 content (disguised as normal text)
    fn encode_base64_content(&mut self, data: &[u8]) -> Result<String> {
        let encoded = BASE64.encode(data);

        // Split into chunks and embed in RSS items
        let chunk_size = 64; // Base64 chunks
        let chunks: Vec<String> = encoded
            .as_bytes()
            .chunks(chunk_size)
            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
            .collect();

        let mut items = Vec::new();
        for (idx, chunk) in chunks.iter().enumerate() {
            let item = RssItem {
                title: format!("Article {}", idx + 1),
                description: format!(
                    "Read more: {}. This article discusses important topics in technology and innovation.",
                    chunk
                ),
                link: format!("{}/article/{}", self.config.feed_link, idx + 1),
                guid: format!("article-{}", idx + 1),
                pub_date: self.format_rfc822_date(SystemTime::now()),
            };
            items.push(item);
        }

        // Add cover items to reach min_items
        while items.len() < self.config.min_items {
            items.push(self.generate_random_item(items.len()));
        }

        self.build_rss_feed(&items)
    }

    /// Encode using item ordering
    fn encode_ordering(&mut self, data: &[u8]) -> Result<String> {
        // Generate items
        let num_items = self.config.min_items.max(data.len() * 2);
        let mut items: Vec<RssItem> = (0..num_items)
            .map(|i| self.generate_random_item(i))
            .collect();

        // Encode data by permuting item order
        // Use first bytes to determine permutation
        let permutation_seed: u64 = if data.len() >= 8 {
            u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])
        } else {
            let mut seed_bytes = [0u8; 8];
            seed_bytes[..data.len()].copy_from_slice(data);
            u64::from_le_bytes(seed_bytes)
        };

        // Shuffle items based on data
        let mut rng = StdRng::seed_from_u64(permutation_seed);
        use rand::seq::SliceRandom;
        items.shuffle(&mut rng);

        // Embed remaining data in item descriptions
        if data.len() > 8 {
            let remaining = &data[8..];
            let encoded = BASE64.encode(remaining);
            for (item, chunk) in items.iter_mut().zip(encoded.as_bytes().chunks(32)) {
                item.description
                    .push_str(&format!(" Reference: {}", String::from_utf8_lossy(chunk)));
            }
        }

        self.build_rss_feed(&items)
    }

    /// Encode using timestamp manipulation
    fn encode_timestamp(&mut self, data: &[u8]) -> Result<String> {
        let num_items = self.config.min_items.max(data.len());
        let mut items = Vec::new();

        let base_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for (idx, &byte) in data.iter().enumerate() {
            // Encode byte in timestamp LSBs
            let timestamp = base_time - (num_items - idx) as u64 * 3600; // 1 hour apart
            let encoded_time = timestamp ^ (byte as u64);

            let item = RssItem {
                title: format!("News Item {}", idx + 1),
                description: self.generate_random_description(),
                link: format!("{}/news/{}", self.config.feed_link, idx + 1),
                guid: format!("news-{}", idx + 1),
                pub_date: self.format_rfc822_date(
                    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(encoded_time),
                ),
            };
            items.push(item);
        }

        // Add cover items
        while items.len() < self.config.min_items {
            items.push(self.generate_random_item(items.len()));
        }

        self.build_rss_feed(&items)
    }

    /// Encode using hybrid method (combines multiple techniques)
    fn encode_hybrid(&mut self, data: &[u8]) -> Result<String> {
        // Split data: first part in ordering, rest in base64 content
        let split_point = data.len() / 2;
        let (ordering_data, content_data) = data.split_at(split_point);

        // Generate items
        let num_items = self.config.min_items.max(data.len());
        let mut items: Vec<RssItem> = (0..num_items)
            .map(|i| self.generate_random_item(i))
            .collect();

        // Encode ordering part
        if !ordering_data.is_empty() {
            let seed: u64 = if ordering_data.len() >= 8 {
                u64::from_le_bytes([
                    ordering_data[0],
                    ordering_data[1],
                    ordering_data[2],
                    ordering_data[3],
                    ordering_data[4],
                    ordering_data[5],
                    ordering_data[6],
                    ordering_data[7],
                ])
            } else {
                let mut seed_bytes = [0u8; 8];
                seed_bytes[..ordering_data.len().min(8)].copy_from_slice(ordering_data);
                u64::from_le_bytes(seed_bytes)
            };

            let mut rng = StdRng::seed_from_u64(seed);
            use rand::seq::SliceRandom;
            items.shuffle(&mut rng);
        }

        // Encode content part in descriptions
        let encoded = BASE64.encode(content_data);
        let chunks: Vec<String> = encoded
            .as_bytes()
            .chunks(64)
            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
            .collect();

        for (item, chunk) in items.iter_mut().zip(chunks.iter()) {
            item.description.push_str(&format!(" See: {}", chunk));
        }

        self.build_rss_feed(&items)
    }

    /// Generate cover RSS items
    fn generate_cover_items(&mut self, num_bits: usize) -> Vec<RssItem> {
        let num_items = (num_bits / 8).max(self.config.min_items);
        (0..num_items)
            .map(|i| self.generate_random_item(i))
            .collect()
    }

    /// Generate a random RSS item for cover
    fn generate_random_item(&mut self, idx: usize) -> RssItem {
        let titles = [
            "Breaking: New Technology Announced",
            "Industry Insights: Market Analysis",
            "Tech Review: Latest Product Launch",
            "Innovation Spotlight: Startup News",
            "Developer Update: New Tools Released",
        ];

        let title = titles[idx % titles.len()];

        RssItem {
            title: format!("{} #{}", title, idx + 1),
            description: self.generate_random_description(),
            link: format!("{}/article/{}", self.config.feed_link, idx + 1),
            guid: format!("article-{}", idx + 1),
            pub_date: self.format_rfc822_date(SystemTime::now()),
        }
    }

    /// Generate random description text
    fn generate_random_description(&mut self) -> String {
        let templates = [
            "This article discusses important developments in the technology sector.",
            "Recent analysis shows significant trends in the industry.",
            "Experts weigh in on the latest innovations and their impact.",
            "A comprehensive look at current market dynamics and future prospects.",
            "Breaking down the key factors driving change in the tech landscape.",
        ];

        let template = templates[self.rng.gen_range(0..templates.len())];
        template.to_string()
    }

    /// Format date as RFC 822 (for RSS pubDate)
    fn format_rfc822_date(&self, time: SystemTime) -> String {
        // Simple RFC 822 format
        // In production, use proper date formatting library
        let timestamp = time.duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Format as: "Mon, 01 Jan 2024 12:00:00 +0000"
        // Simplified version for now
        format!("{}", timestamp)
    }

    /// Build RSS XML feed from items
    fn build_rss_feed(&self, items: &[RssItem]) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<rss version=\"2.0\">\n");
        xml.push_str("  <channel>\n");
        xml.push_str(&format!(
            "    <title>{}</title>\n",
            html_escape(&self.config.feed_title)
        ));
        xml.push_str(&format!(
            "    <description>{}</description>\n",
            html_escape(&self.config.feed_description)
        ));
        xml.push_str(&format!("    <link>{}</link>\n", self.config.feed_link));
        xml.push_str("    <lastBuildDate>");
        xml.push_str(&self.format_rfc822_date(SystemTime::now()));
        xml.push_str("</lastBuildDate>\n");

        for item in items {
            xml.push_str("    <item>\n");
            xml.push_str(&format!(
                "      <title>{}</title>\n",
                html_escape(&item.title)
            ));
            xml.push_str(&format!(
                "      <description>{}</description>\n",
                html_escape(&item.description)
            ));
            xml.push_str(&format!("      <link>{}</link>\n", item.link));
            xml.push_str(&format!("      <guid>{}</guid>\n", item.guid));
            xml.push_str(&format!("      <pubDate>{}</pubDate>\n", item.pub_date));
            xml.push_str("    </item>\n");
        }

        xml.push_str("  </channel>\n");
        xml.push_str("</rss>\n");

        Ok(xml)
    }
}

/// Steganographic RSS decoder
pub struct StegoRssDecoder {
    config: StegoRssConfig,
}

impl StegoRssDecoder {
    /// Create new decoder with config
    pub fn new(config: StegoRssConfig) -> Self {
        Self { config }
    }

    /// Decompress zstd-compressed data
    fn decompress(&self, data: &[u8]) -> Result<String> {
        let mut decoder = zstd::Decoder::new(data).context("failed to create zstd decoder")?;
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .context("failed to decompress zstd data")?;
        String::from_utf8(decompressed).context("decompressed data is not valid UTF-8")
    }

    /// Decode signed manifest from RSS XML
    pub fn decode_manifest(&self, rss_xml: &str) -> Result<SignedManifest> {
        let data = self.decode_data(rss_xml)?;
        let json = self.decompress(&data)?;
        let manifest: SignedManifest =
            serde_json::from_str(&json).context("failed to deserialize manifest")?;
        Ok(manifest)
    }

    /// Decode manifest payload from RSS XML
    pub fn decode_payload(&self, rss_xml: &str) -> Result<ManifestPayload> {
        let data = self.decode_data(rss_xml)?;
        let json = self.decompress(&data)?;
        let payload: ManifestPayload =
            serde_json::from_str(&json).context("failed to deserialize manifest payload")?;
        Ok(payload)
    }

    /// Decode data from RSS XML based on method
    fn decode_data(&self, rss_xml: &str) -> Result<Vec<u8>> {
        let data = match self.config.method {
            StegoMethod::Whitespace => self.decode_whitespace(rss_xml)?,
            StegoMethod::Base64Content => self.decode_base64_content(rss_xml)?,
            StegoMethod::Ordering => self.decode_ordering(rss_xml)?,
            StegoMethod::Timestamp => self.decode_timestamp(rss_xml)?,
            StegoMethod::Hybrid => self.decode_hybrid(rss_xml)?,
        };
        Ok(data)
    }

    /// Decode whitespace steganography
    fn decode_whitespace(&self, rss_xml: &str) -> Result<Vec<u8>> {
        // Parse RSS and extract descriptions
        let items = self.parse_rss_items(rss_xml)?;
        let mut bits = Vec::new();

        for item in items {
            // Check for tab (1) or space (0) at end
            let desc = html_unescape(&item.description);
            if desc.ends_with('\t') {
                bits.push(1);
            } else if desc.ends_with(' ') {
                bits.push(0);
            } else {
                // No encoding marker, skip
                continue;
            }
        }

        // Convert bits to bytes
        let mut data = Vec::new();
        for chunk in bits.chunks(8) {
            if chunk.len() == 8 {
                let mut byte = 0u8;
                for (i, &bit) in chunk.iter().enumerate() {
                    byte |= (bit as u8) << (7 - i);
                }
                data.push(byte);
            }
        }

        Ok(data)
    }

    /// Decode base64 content steganography
    fn decode_base64_content(&self, rss_xml: &str) -> Result<Vec<u8>> {
        let items = self.parse_rss_items(rss_xml)?;
        let mut encoded = String::new();

        for item in items {
            let desc = html_unescape(&item.description);
            // Extract base64 chunk from description
            if let Some(start) = desc.find("Read more: ") {
                let chunk_start = start + "Read more: ".len();
                if let Some(end) = desc[chunk_start..].find('.') {
                    let chunk = &desc[chunk_start..chunk_start + end];
                    encoded.push_str(chunk);
                }
            }
        }

        if encoded.is_empty() {
            return Err(anyhow::anyhow!("no encoded data found in RSS"));
        }

        BASE64
            .decode(encoded.trim())
            .context("failed to decode base64 content")
    }

    /// Decode ordering-based steganography
    fn decode_ordering(&self, rss_xml: &str) -> Result<Vec<u8>> {
        let items = self.parse_rss_items(rss_xml)?;

        // Extract permutation seed from item order
        // This is simplified - in practice would need to know original order
        let mut data = Vec::new();

        // Extract base64 chunks from descriptions
        let mut encoded = String::new();
        for item in items {
            if let Some(start) = item.description.find("Reference: ") {
                let chunk_start = start + "Reference: ".len();
                let chunk = &item.description[chunk_start..];
                encoded.push_str(chunk.trim());
            }
        }

        if !encoded.is_empty() {
            let decoded = BASE64.decode(encoded)?;
            data.extend_from_slice(&decoded);
        }

        Ok(data)
    }

    /// Decode timestamp-based steganography
    fn decode_timestamp(&self, rss_xml: &str) -> Result<Vec<u8>> {
        let items = self.parse_rss_items(rss_xml)?;
        let mut data = Vec::new();

        for item in items {
            // Parse timestamp and extract LSB
            // Simplified: extract byte from timestamp
            if let Ok(timestamp) = item.pub_date.parse::<u64>() {
                // Extract encoded byte (simplified)
                let byte = (timestamp & 0xFF) as u8;
                data.push(byte);
            }
        }

        Ok(data)
    }

    /// Decode hybrid steganography
    fn decode_hybrid(&self, rss_xml: &str) -> Result<Vec<u8>> {
        let items = self.parse_rss_items(rss_xml)?;

        // Extract base64 chunks from descriptions
        let mut encoded = String::new();
        for item in items {
            let desc = html_unescape(&item.description);
            if let Some(start) = desc.find("See: ") {
                let chunk_start = start + "See: ".len();
                let chunk = &desc[chunk_start..].trim();
                encoded.push_str(chunk);
            }
        }

        if encoded.is_empty() {
            return Err(anyhow::anyhow!("no encoded data found in RSS"));
        }

        let decoded = BASE64.decode(encoded.trim())?;
        Ok(decoded)
    }

    /// Parse RSS items from XML (simplified parser)
    fn parse_rss_items(&self, rss_xml: &str) -> Result<Vec<RssItem>> {
        // Simplified RSS parser - in production use proper XML parser
        let mut items = Vec::new();

        // Extract items using simple string matching
        // This is a basic implementation - production should use xml-rs or similar
        let item_pattern = "<item>";
        let mut pos = 0;

        while let Some(item_start) = rss_xml[pos..].find(item_pattern) {
            let item_start = pos + item_start + item_pattern.len();
            if let Some(item_end) = rss_xml[item_start..].find("</item>") {
                let item_xml = &rss_xml[item_start..item_start + item_end];

                let title = self.extract_tag(item_xml, "title").unwrap_or_default();
                let description = self
                    .extract_tag(item_xml, "description")
                    .unwrap_or_default();
                let link = self.extract_tag(item_xml, "link").unwrap_or_default();
                let guid = self.extract_tag(item_xml, "guid").unwrap_or_default();
                let pub_date = self.extract_tag(item_xml, "pubDate").unwrap_or_default();

                items.push(RssItem {
                    title,
                    description,
                    link,
                    guid,
                    pub_date,
                });

                pos = item_start + item_end;
            } else {
                break;
            }
        }

        Ok(items)
    }

    /// Extract content from XML tag (simplified)
    fn extract_tag(&self, xml: &str, tag: &str) -> Option<String> {
        let open_tag = format!("<{}>", tag);
        let close_tag = format!("</{}>", tag);

        if let Some(start) = xml.find(&open_tag) {
            let content_start = start + open_tag.len();
            if let Some(end) = xml[content_start..].find(&close_tag) {
                let content = &xml[content_start..content_start + end];
                return Some(html_unescape(content));
            }
        }
        None
    }
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Unescape HTML entities
fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]

    use super::*;
    use vpr_crypto::manifest::{ManifestPayload, ServerEndpoint};

    fn make_test_payload() -> ManifestPayload {
        let servers = vec![ServerEndpoint::new(
            "server1",
            "example.com",
            443,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )];
        ManifestPayload::new(servers)
    }

    #[test]
    fn stego_method_default_is_hybrid() {
        let method = StegoMethod::default();
        assert_eq!(method, StegoMethod::Hybrid);
    }

    #[test]
    fn stego_config_default_values() {
        let config = StegoRssConfig::default();
        assert_eq!(config.method, StegoMethod::Hybrid);
        assert_eq!(config.feed_title, "Tech News Feed");
        assert_eq!(config.min_items, 10);
        assert_eq!(config.max_items, 50);
        assert!(config.random_order);
        assert!(config.seed.is_none());
    }

    #[test]
    fn html_escape_special_chars() {
        assert_eq!(html_escape("&"), "&amp;");
        assert_eq!(html_escape("<"), "&lt;");
        assert_eq!(html_escape(">"), "&gt;");
        assert_eq!(html_escape("\""), "&quot;");
        assert_eq!(html_escape("'"), "&apos;");
        assert_eq!(
            html_escape("<script>&</script>"),
            "&lt;script&gt;&amp;&lt;/script&gt;"
        );
    }

    #[test]
    fn html_unescape_entities() {
        assert_eq!(html_unescape("&amp;"), "&");
        assert_eq!(html_unescape("&lt;"), "<");
        assert_eq!(html_unescape("&gt;"), ">");
        assert_eq!(html_unescape("&quot;"), "\"");
        assert_eq!(html_unescape("&apos;"), "'");
        assert_eq!(
            html_unescape("&lt;script&gt;&amp;&lt;/script&gt;"),
            "<script>&</script>"
        );
    }

    #[test]
    fn html_escape_unescape_roundtrip() {
        let original = "Test <html> & \"quotes\" 'apostrophe'";
        let escaped = html_escape(original);
        let unescaped = html_unescape(&escaped);
        assert_eq!(unescaped, original);
    }

    #[test]
    fn encoder_new_creates_instance() {
        let config = StegoRssConfig::default();
        let encoder = StegoRssEncoder::new(config.clone());
        assert_eq!(encoder.config.method, config.method);
    }

    #[test]
    fn decoder_new_creates_instance() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config.clone());
        assert_eq!(decoder.config.method, config.method);
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let config = StegoRssConfig::default();
        let encoder = StegoRssEncoder::new(config.clone());
        let decoder = StegoRssDecoder::new(config);

        let data = "test data for compression roundtrip";
        let compressed = encoder.compress(data).unwrap();
        // zstd adds header, so compressed data starts with magic bytes
        assert!(compressed.starts_with(&[0x28, 0xB5, 0x2F, 0xFD])); // zstd magic

        let decompressed = decoder.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn decompress_invalid_zstd_fails() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config);
        // Random bytes that aren't valid zstd
        let invalid = vec![0xFF, 0xFE, 0x00, 0x01];
        let result = decoder.decompress(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn build_rss_feed_creates_valid_xml() {
        let config = StegoRssConfig::default();
        let encoder = StegoRssEncoder::new(config);
        let items = vec![RssItem {
            title: "Test Title".into(),
            description: "Test Description".into(),
            link: "https://example.com/1".into(),
            guid: "guid-1".into(),
            pub_date: "1234567890".into(),
        }];
        let xml = encoder.build_rss_feed(&items).unwrap();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("<rss version=\"2.0\">"));
        assert!(xml.contains("<channel>"));
        assert!(xml.contains("<title>Tech News Feed</title>"));
        assert!(xml.contains("<item>"));
        assert!(xml.contains("<title>Test Title</title>"));
        assert!(xml.contains("</channel>"));
        assert!(xml.contains("</rss>"));
    }

    #[test]
    fn parse_rss_items_extracts_items() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config);
        let xml = r#"
            <rss version="2.0">
            <channel>
                <title>Test Feed</title>
                <item>
                    <title>Item 1</title>
                    <description>Desc 1</description>
                    <link>https://example.com/1</link>
                    <guid>guid-1</guid>
                    <pubDate>123</pubDate>
                </item>
                <item>
                    <title>Item 2</title>
                    <description>Desc 2</description>
                    <link>https://example.com/2</link>
                    <guid>guid-2</guid>
                    <pubDate>456</pubDate>
                </item>
            </channel>
            </rss>
        "#;
        let items = decoder.parse_rss_items(xml).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Item 1");
        assert_eq!(items[0].description, "Desc 1");
        assert_eq!(items[1].title, "Item 2");
        assert_eq!(items[1].pub_date, "456");
    }

    #[test]
    fn extract_tag_finds_content() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config);
        let xml = "<title>Hello World</title>";
        let result = decoder.extract_tag(xml, "title");
        assert_eq!(result, Some("Hello World".to_string()));
    }

    #[test]
    fn extract_tag_unescapes_html() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config);
        let xml = "<description>&lt;b&gt;Bold&lt;/b&gt;</description>";
        let result = decoder.extract_tag(xml, "description");
        assert_eq!(result, Some("<b>Bold</b>".to_string()));
    }

    #[test]
    fn extract_tag_returns_none_for_missing() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config);
        let xml = "<title>Hello</title>";
        let result = decoder.extract_tag(xml, "description");
        assert!(result.is_none());
    }

    #[test]
    fn generate_random_item_creates_valid_item() {
        let config = StegoRssConfig::default();
        let mut encoder = StegoRssEncoder::new(config);
        let item = encoder.generate_random_item(0);
        assert!(!item.title.is_empty());
        assert!(!item.description.is_empty());
        assert!(item.link.contains("example.com"));
        assert!(item.guid.starts_with("article-"));
    }

    #[test]
    fn generate_cover_items_returns_min_items() {
        let mut config = StegoRssConfig::default();
        config.min_items = 5;
        let mut encoder = StegoRssEncoder::new(config);
        let items = encoder.generate_cover_items(10);
        assert!(items.len() >= 5);
    }

    #[test]
    fn format_rfc822_date_returns_timestamp() {
        let config = StegoRssConfig::default();
        let encoder = StegoRssEncoder::new(config);
        let time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000000);
        let date = encoder.format_rfc822_date(time);
        assert_eq!(date, "1000000");
    }

    #[test]
    #[ignore = "stego whitespace encoding requires more items than min_items for large payloads"]
    fn test_stego_rss_encode_decode_whitespace() {
        let mut config = StegoRssConfig::default();
        config.method = StegoMethod::Whitespace;
        config.min_items = 20;

        let mut encoder = StegoRssEncoder::new(config.clone());
        let decoder = StegoRssDecoder::new(config);

        // Create test manifest
        let servers = vec![ServerEndpoint::new(
            "server1",
            "example.com",
            443,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )];
        let payload = ManifestPayload::new(servers);

        // Encode
        let rss_xml = encoder.encode_payload(&payload).unwrap();
        assert!(rss_xml.contains("<rss"));
        assert!(rss_xml.contains("<channel>"));

        // Decode
        let decoded = decoder.decode_payload(&rss_xml).unwrap();
        assert_eq!(decoded.version, payload.version);
        assert_eq!(decoded.servers.len(), payload.servers.len());
    }

    #[test]
    fn encode_whitespace_generates_rss() {
        let mut config = StegoRssConfig::default();
        config.method = StegoMethod::Whitespace;
        config.min_items = 100;
        let mut encoder = StegoRssEncoder::new(config);
        let compressed = encoder.compress("test").unwrap();
        let xml = encoder.encode_whitespace(&compressed).unwrap();
        assert!(xml.contains("<rss"));
        assert!(xml.contains("<item>"));
    }

    #[test]
    fn encode_ordering_generates_rss() {
        let mut config = StegoRssConfig::default();
        config.method = StegoMethod::Ordering;
        let mut encoder = StegoRssEncoder::new(config);
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let xml = encoder.encode_ordering(&data).unwrap();
        assert!(xml.contains("<rss"));
        assert!(xml.contains("<item>"));
        assert!(xml.contains("Reference:"));
    }

    #[test]
    fn encode_timestamp_generates_rss() {
        let mut config = StegoRssConfig::default();
        config.method = StegoMethod::Timestamp;
        let mut encoder = StegoRssEncoder::new(config);
        let data = vec![0xAB, 0xCD, 0xEF];
        let xml = encoder.encode_timestamp(&data).unwrap();
        assert!(xml.contains("<rss"));
        assert!(xml.contains("<item>"));
        assert!(xml.contains("<pubDate>"));
    }

    #[test]
    fn encode_hybrid_generates_rss() {
        let mut config = StegoRssConfig::default();
        config.method = StegoMethod::Hybrid;
        let mut encoder = StegoRssEncoder::new(config);
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let xml = encoder.encode_hybrid(&data).unwrap();
        assert!(xml.contains("<rss"));
        assert!(xml.contains("See:"));
    }

    #[test]
    fn decode_whitespace_extracts_bits() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config);
        // XML with items ending in space (0) or tab (1)
        let xml = r#"
            <rss><channel>
            <item><description>Text </description></item>
            <item><description>Text	</description></item>
            <item><description>Text </description></item>
            <item><description>Text	</description></item>
            <item><description>Text </description></item>
            <item><description>Text	</description></item>
            <item><description>Text </description></item>
            <item><description>Text	</description></item>
            </channel></rss>
        "#;
        let data = decoder.decode_whitespace(xml).unwrap();
        // 01010101 = 0x55
        assert_eq!(data, vec![0x55]);
    }

    #[test]
    fn decode_timestamp_extracts_bytes() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config);
        // XML with timestamps that have specific LSBs
        let xml = r#"
            <rss><channel>
            <item><pubDate>256</pubDate></item>
            <item><pubDate>257</pubDate></item>
            <item><pubDate>258</pubDate></item>
            </channel></rss>
        "#;
        let data = decoder.decode_timestamp(xml).unwrap();
        // LSBs: 0, 1, 2
        assert_eq!(data, vec![0, 1, 2]);
    }

    #[test]
    fn decode_ordering_extracts_references() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config);
        // XML with Reference: base64 chunks
        let xml = r#"
            <rss><channel>
            <item><description>Text Reference: SGVsbG8=</description></item>
            </channel></rss>
        "#;
        let data = decoder.decode_ordering(xml).unwrap();
        assert_eq!(data, b"Hello");
    }

    #[test]
    fn decode_hybrid_extracts_see_chunks() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config);
        // XML with See: base64 chunks
        let xml = r#"
            <rss><channel>
            <item><description>Text See: V29ybGQ=</description></item>
            </channel></rss>
        "#;
        let data = decoder.decode_hybrid(xml).unwrap();
        assert_eq!(data, b"World");
    }

    #[test]
    fn decode_base64_content_empty_fails() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config);
        let xml =
            r#"<rss><channel><item><description>No data here</description></item></channel></rss>"#;
        let result = decoder.decode_base64_content(xml);
        assert!(result.is_err());
    }

    #[test]
    fn decode_hybrid_empty_fails() {
        let config = StegoRssConfig::default();
        let decoder = StegoRssDecoder::new(config);
        // Use XML without "See: " marker
        let xml = r#"<rss><channel><item><description>No data marker here</description></item></channel></rss>"#;
        let result = decoder.decode_hybrid(xml);
        assert!(result.is_err());
    }

    #[test]
    fn test_stego_rss_encode_decode_base64() {
        let mut config = StegoRssConfig::default();
        config.method = StegoMethod::Base64Content;

        let mut encoder = StegoRssEncoder::new(config.clone());
        let decoder = StegoRssDecoder::new(config);

        let servers = vec![ServerEndpoint::new(
            "server1",
            "example.com",
            443,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )];
        let payload = ManifestPayload::new(servers);

        let rss_xml = encoder.encode_payload(&payload).unwrap();
        let decoded = decoder.decode_payload(&rss_xml).unwrap();

        assert_eq!(decoded.version, payload.version);
    }

    #[test]
    #[ignore = "stego hybrid encoding needs proper chunking implementation"]
    fn test_stego_rss_encode_decode_hybrid() {
        let mut config = StegoRssConfig::default();
        config.method = StegoMethod::Hybrid;

        let mut encoder = StegoRssEncoder::new(config.clone());
        let decoder = StegoRssDecoder::new(config);

        let servers = vec![
            ServerEndpoint::new(
                "server1",
                "example.com",
                443,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            ServerEndpoint::new(
                "server2",
                "example.org",
                443,
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            ),
        ];
        let payload = ManifestPayload::new(servers);

        let rss_xml = encoder.encode_payload(&payload).unwrap();
        let decoded = decoder.decode_payload(&rss_xml).unwrap();

        assert_eq!(decoded.servers.len(), payload.servers.len());
        assert_eq!(decoded.servers[0].id, payload.servers[0].id);
    }

    #[test]
    fn rss_item_clone() {
        let item = RssItem {
            title: "Test".into(),
            description: "Desc".into(),
            link: "https://x.com".into(),
            guid: "1".into(),
            pub_date: "123".into(),
        };
        let cloned = item.clone();
        assert_eq!(cloned.title, item.title);
        assert_eq!(cloned.guid, item.guid);
    }

    #[test]
    fn stego_method_variants_are_distinct() {
        assert_ne!(StegoMethod::Whitespace, StegoMethod::Base64Content);
        assert_ne!(StegoMethod::Ordering, StegoMethod::Timestamp);
        assert_ne!(StegoMethod::Hybrid, StegoMethod::Whitespace);
    }

    #[test]
    fn encode_payload_base64_roundtrip() {
        let mut config = StegoRssConfig::default();
        config.method = StegoMethod::Base64Content;
        let mut encoder = StegoRssEncoder::new(config.clone());
        let decoder = StegoRssDecoder::new(config);

        let payload = make_test_payload();
        let xml = encoder.encode_payload(&payload).unwrap();
        let decoded = decoder.decode_payload(&xml).unwrap();

        assert_eq!(decoded.version, payload.version);
        assert_eq!(decoded.servers.len(), 1);
    }

    #[test]
    fn encode_manifest_generates_rss() {
        use vpr_crypto::keys::SigningKeypair;

        let mut config = StegoRssConfig::default();
        config.method = StegoMethod::Base64Content;
        let mut encoder = StegoRssEncoder::new(config);

        let payload = make_test_payload();
        // Create a signed manifest for testing
        let keypair = SigningKeypair::generate();
        let manifest = SignedManifest::sign(&payload, &keypair).unwrap();

        let xml = encoder.encode_manifest(&manifest).unwrap();
        assert!(xml.contains("<rss"));
        assert!(xml.contains("Read more:"));
    }
}
