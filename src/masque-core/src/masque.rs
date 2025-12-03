//! MASQUE CONNECT-UDP implementation (RFC 9298)
//!
//! Provides HTTP/3 Extended CONNECT handling for UDP proxying.

use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::warn;

/// Maximum UDP payload size per RFC 9298
pub const MAX_UDP_PAYLOAD: usize = 65_527;

/// Maximum hostname length (DNS limit)
const MAX_HOSTNAME_LEN: usize = 255;

/// Maximum label length in hostname (DNS limit)
const MAX_LABEL_LEN: usize = 63;

/// Blocked ports to prevent abuse (SMTP, etc.)
const BLOCKED_PORTS: &[u16] = &[
    25,  // SMTP
    465, // SMTPS
    587, // SMTP Submission
];

/// CONNECT-UDP Context ID for raw UDP payloads (RFC 9298)
pub const CONTEXT_ID_UDP: u64 = 0;

/// CONNECT-UDP Context ID for handshake capsules
pub const CONTEXT_ID_HANDSHAKE: u64 = 1;

/// Context ID for Address Request capsule (RFC 9297)
pub const CONTEXT_ID_ADDRESS_REQUEST: u64 = 2;

/// Context ID for Address Assign capsule (RFC 9297)
pub const CONTEXT_ID_ADDRESS_ASSIGN: u64 = 3;

/// Context ID for Close capsule (RFC 9297)
pub const CONTEXT_ID_CLOSE: u64 = 4;

/// Parsed CONNECT-UDP request target
#[derive(Debug, Clone)]
pub struct ConnectUdpTarget {
    pub host: String,
    pub port: u16,
}

impl ConnectUdpTarget {
    /// Parse target from MASQUE URI template path
    /// Expected format: `/.well-known/masque/udp/{host}/{port}/`
    pub fn from_path(path: &str) -> Result<Self> {
        let path = path.trim_matches('/');
        let parts: Vec<&str> = path.split('/').collect();

        // Expected: [".well-known", "masque", "udp", "{host}", "{port}"]
        if parts.len() < 5 {
            // Try simple format: /udp/{host}/{port}
            if parts.len() >= 3 && parts[0] == "udp" {
                let host = parts[1].to_string();
                let port: u16 = parts[2]
                    .parse()
                    .with_context(|| format!("invalid port: {}", parts[2]))?;
                return Ok(Self { host, port });
            }
            bail!("invalid CONNECT-UDP path: {}", path);
        }

        if parts[0] != ".well-known" || parts[1] != "masque" || parts[2] != "udp" {
            bail!("invalid CONNECT-UDP path prefix: {}", path);
        }

        let host = parts[3].to_string();
        let port: u16 = parts[4]
            .parse()
            .with_context(|| format!("invalid port: {}", parts[4]))?;

        Ok(Self { host, port })
    }

    /// Validate target is safe to proxy to
    ///
    /// # Security Checks
    /// - Port must be valid (1-65535) and not blocked (SMTP ports)
    /// - Hostname length must be within DNS limits (255 chars, labels 63 chars)
    /// - Hostname must contain only valid characters
    /// - IP addresses must not be in forbidden ranges (localhost, private, link-local)
    /// - Localhost by name is rejected
    pub fn validate(&self) -> Result<()> {
        // Port validation
        if self.port == 0 {
            bail!("port 0 is not allowed");
        }

        // Block dangerous ports (SMTP to prevent spam relay)
        if BLOCKED_PORTS.contains(&self.port) {
            bail!(
                "port {} is blocked to prevent abuse (SMTP/mail relay protection)",
                self.port
            );
        }

        // Hostname length validation (DNS limits)
        if self.host.is_empty() {
            bail!("hostname cannot be empty");
        }
        if self.host.len() > MAX_HOSTNAME_LEN {
            bail!(
                "hostname exceeds DNS limit of {} bytes: {} bytes",
                MAX_HOSTNAME_LEN,
                self.host.len()
            );
        }

        // Try to parse as IP address to check for forbidden ranges
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            if is_forbidden_ip(&ip) {
                bail!("target IP {} is forbidden", ip);
            }
        } else {
            // Validate hostname format (DNS name)
            validate_hostname(&self.host)?;
        }

        // Block localhost by name
        let host_lower = self.host.to_lowercase();
        if host_lower == "localhost"
            || host_lower == "localhost.localdomain"
            || host_lower.ends_with(".localhost")
        {
            bail!("localhost targets are forbidden");
        }

        Ok(())
    }

    /// Get socket address string for connection
    pub fn to_socket_addr_str(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Validate hostname format according to DNS rules
///
/// Checks:
/// - Labels are 1-63 characters
/// - Labels contain only alphanumeric and hyphen
/// - Labels don't start or end with hyphen
/// - Total length is within DNS limit
fn validate_hostname(host: &str) -> Result<()> {
    if host.is_empty() {
        bail!("hostname cannot be empty");
    }

    for label in host.split('.') {
        if label.is_empty() {
            bail!("hostname contains empty label (double dots)");
        }
        if label.len() > MAX_LABEL_LEN {
            bail!(
                "hostname label exceeds {} bytes: '{}'",
                MAX_LABEL_LEN,
                label
            );
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("hostname label cannot start or end with hyphen: '{}'", label);
        }

        // Check all characters are valid
        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                // Allow underscore for SRV records compatibility
                if ch == '_' {
                    continue;
                }
                bail!(
                    "hostname contains invalid character '{}' in label '{}'",
                    ch,
                    label
                );
            }
        }
    }

    Ok(())
}

/// Check if IP is in forbidden range (localhost, link-local, multicast, broadcast)
fn is_forbidden_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || is_private_v4(v4)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_multicast() || v6.is_unspecified(),
    }
}

/// Check if IPv4 is in private range (for security)
fn is_private_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    octets[0] == 10
        // 172.16.0.0/12
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        // 192.168.0.0/16
        || (octets[0] == 192 && octets[1] == 168)
        // 127.0.0.0/8
        || octets[0] == 127
}

/// Encode a variable-length integer (QUIC varint format)
pub fn encode_varint(value: u64) -> BytesMut {
    let mut buf = BytesMut::new();
    if value < 64 {
        buf.put_u8(value as u8);
    } else if value < 16384 {
        buf.put_u16(0x4000 | value as u16);
    } else if value < 1_073_741_824 {
        buf.put_u32(0x8000_0000 | value as u32);
    } else {
        buf.put_u64(0xC000_0000_0000_0000 | value);
    }
    buf
}

/// Decode a variable-length integer from bytes
pub fn decode_varint(buf: &mut impl Buf) -> Result<u64> {
    if !buf.has_remaining() {
        bail!("empty buffer for varint");
    }

    let first = buf.get_u8();
    let prefix = first >> 6;

    match prefix {
        0 => Ok(first as u64),
        1 => {
            if buf.remaining() < 1 {
                bail!("truncated 2-byte varint");
            }
            let second = buf.get_u8();
            Ok((((first & 0x3F) as u64) << 8) | second as u64)
        }
        2 => {
            if buf.remaining() < 3 {
                bail!("truncated 4-byte varint");
            }
            let b1 = buf.get_u8() as u64;
            let b2 = buf.get_u8() as u64;
            let b3 = buf.get_u8() as u64;
            Ok((((first & 0x3F) as u64) << 24) | (b1 << 16) | (b2 << 8) | b3)
        }
        3 => {
            if buf.remaining() < 7 {
                bail!("truncated 8-byte varint");
            }
            let mut val = ((first & 0x3F) as u64) << 56;
            for shift in (0..7).rev() {
                val |= (buf.get_u8() as u64) << (shift * 8);
            }
            Ok(val)
        }
        _ => unreachable!(),
    }
}

/// Capsule types according to RFC 9297
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleType {
    /// UDP payload capsule
    Udp,
    /// Handshake capsule
    Handshake,
    /// Address Request capsule
    AddressRequest,
    /// Address Assign capsule
    AddressAssign,
    /// Close capsule
    Close,
    /// Unknown/unsupported capsule type
    Unknown(u64),
}

impl CapsuleType {
    /// Get context ID for this capsule type
    pub fn context_id(&self) -> u64 {
        match self {
            CapsuleType::Udp => CONTEXT_ID_UDP,
            CapsuleType::Handshake => CONTEXT_ID_HANDSHAKE,
            CapsuleType::AddressRequest => CONTEXT_ID_ADDRESS_REQUEST,
            CapsuleType::AddressAssign => CONTEXT_ID_ADDRESS_ASSIGN,
            CapsuleType::Close => CONTEXT_ID_CLOSE,
            CapsuleType::Unknown(id) => *id,
        }
    }

    /// Create from context ID
    pub fn from_context_id(id: u64) -> Self {
        match id {
            CONTEXT_ID_UDP => CapsuleType::Udp,
            CONTEXT_ID_HANDSHAKE => CapsuleType::Handshake,
            CONTEXT_ID_ADDRESS_REQUEST => CapsuleType::AddressRequest,
            CONTEXT_ID_ADDRESS_ASSIGN => CapsuleType::AddressAssign,
            CONTEXT_ID_CLOSE => CapsuleType::Close,
            _ => CapsuleType::Unknown(id),
        }
    }
}

/// UDP Datagram capsule for CONNECT-UDP (RFC 9298)
#[derive(Debug, Clone)]
pub struct UdpCapsule {
    pub context_id: u64,
    pub payload: Bytes,
    pub capsule_type: CapsuleType,
}

impl UdpCapsule {
    /// Create a new UDP capsule with raw payload
    pub fn new(payload: Bytes) -> Self {
        Self {
            context_id: CONTEXT_ID_UDP,
            payload,
            capsule_type: CapsuleType::Udp,
        }
    }

    /// Create a new handshake capsule
    pub fn new_handshake(payload: Bytes) -> Self {
        Self {
            context_id: CONTEXT_ID_HANDSHAKE,
            payload,
            capsule_type: CapsuleType::Handshake,
        }
    }

    /// Create a new Address Request capsule
    pub fn new_address_request(payload: Bytes) -> Self {
        Self {
            context_id: CONTEXT_ID_ADDRESS_REQUEST,
            payload,
            capsule_type: CapsuleType::AddressRequest,
        }
    }

    /// Create a new Address Assign capsule
    pub fn new_address_assign(payload: Bytes) -> Self {
        Self {
            context_id: CONTEXT_ID_ADDRESS_ASSIGN,
            payload,
            capsule_type: CapsuleType::AddressAssign,
        }
    }

    /// Create a new Close capsule
    pub fn new_close(payload: Bytes) -> Self {
        Self {
            context_id: CONTEXT_ID_CLOSE,
            payload,
            capsule_type: CapsuleType::Close,
        }
    }

    /// Create capsule with custom context ID
    pub fn with_context_id(context_id: u64, payload: Bytes) -> Self {
        Self {
            context_id,
            payload,
            capsule_type: CapsuleType::from_context_id(context_id),
        }
    }

    /// Check if this is a handshake capsule
    pub fn is_handshake(&self) -> bool {
        self.capsule_type == CapsuleType::Handshake
    }

    /// Check if this is a UDP payload capsule
    pub fn is_udp(&self) -> bool {
        self.capsule_type == CapsuleType::Udp
    }

    /// Check if this is a Close capsule
    pub fn is_close(&self) -> bool {
        self.capsule_type == CapsuleType::Close
    }

    /// Get capsule type
    pub fn capsule_type(&self) -> CapsuleType {
        self.capsule_type
    }

    /// Encode capsule for transmission
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_varint(self.context_id));
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    /// Decode capsule from bytes
    pub fn decode(mut data: Bytes) -> Result<Self> {
        let context_id = decode_varint(&mut data)?;
        let payload = data;
        let capsule_type = CapsuleType::from_context_id(context_id);

        // Validate payload size based on capsule type
        match capsule_type {
            CapsuleType::Udp => {
                if payload.len() > MAX_UDP_PAYLOAD {
                    bail!(
                        "UDP payload too large: {} > {}",
                        payload.len(),
                        MAX_UDP_PAYLOAD
                    );
                }
            }
            CapsuleType::Close => {
                // Close capsule should have minimal payload (optional error code)
                if payload.len() > 8 {
                    warn!(
                        "Close capsule has unusually large payload: {} bytes",
                        payload.len()
                    );
                }
            }
            _ => {
                // Other capsule types don't have strict size limits
            }
        }

        Ok(Self {
            context_id,
            payload,
            capsule_type,
        })
    }
}

/// Check if HTTP request is Extended CONNECT for CONNECT-UDP
pub fn is_connect_udp(method: &http::Method, protocol: Option<&str>) -> bool {
    method == http::Method::CONNECT && protocol == Some("connect-udp")
}

/// Extract target from CONNECT-UDP request headers
pub fn extract_connect_udp_target(
    headers: &http::HeaderMap,
    path: &str,
) -> Result<ConnectUdpTarget> {
    // First try path
    if let Ok(target) = ConnectUdpTarget::from_path(path) {
        return Ok(target);
    }

    // Fall back to custom header
    if let Some(target) = headers.get("x-masque-udp-target") {
        let value = target.to_str().context("invalid target header")?;
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() == 2 {
            let host = parts[0].to_string();
            let port: u16 = parts[1].parse().context("invalid port in header")?;
            return Ok(ConnectUdpTarget { host, port });
        }
    }

    bail!("could not extract CONNECT-UDP target from request")
}

/// Read a capsule from an async stream
///
/// Reads length-prefixed capsule data (u32 BE length, then capsule bytes)
pub async fn read_capsule<R: AsyncRead + Unpin>(reader: &mut R) -> Result<UdpCapsule> {
    // Read length prefix (u32 BE)
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("reading capsule length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Limit capsule size to prevent memory exhaustion
    const MAX_CAPSULE_SIZE: usize = 65536; // 64KB max
    if len > MAX_CAPSULE_SIZE {
        bail!("capsule too large: {} > {}", len, MAX_CAPSULE_SIZE);
    }

    // Read capsule data
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .context("reading capsule data")?;

    // Decode capsule
    UdpCapsule::decode(Bytes::from(buf))
}

/// Write a capsule to an async stream
///
/// Writes length-prefixed capsule data (u32 BE length, then capsule bytes)
pub async fn write_capsule<W: AsyncWrite + Unpin>(
    writer: &mut W,
    capsule: &UdpCapsule,
) -> Result<()> {
    let encoded = capsule.encode();
    let len = encoded.len() as u32;

    // Write length prefix
    writer
        .write_all(&len.to_be_bytes())
        .await
        .context("writing capsule length")?;

    // Write capsule data
    writer
        .write_all(&encoded)
        .await
        .context("writing capsule data")?;

    writer.flush().await.context("flushing capsule")?;
    Ok(())
}

/// Helper to read length-prefixed capsule from bytes chunks
///
/// This is used when reading from h3 RequestStream which provides Bytes chunks
pub struct CapsuleBuffer {
    buf: BytesMut,
    expecting_len: Option<usize>,
    /// Maximum buffer size to prevent memory exhaustion attacks
    max_buffer_size: usize,
}

impl Default for CapsuleBuffer {
    fn default() -> Self {
        Self {
            buf: BytesMut::new(),
            expecting_len: None,
            max_buffer_size: 128 * 1024, // 128KB default max buffer size
        }
    }
}

impl CapsuleBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom maximum buffer size
    pub fn with_max_size(max_buffer_size: usize) -> Self {
        Self {
            buf: BytesMut::new(),
            expecting_len: None,
            max_buffer_size,
        }
    }

    /// Add bytes to buffer and try to extract a complete capsule
    ///
    /// Returns Some(capsule) when a complete capsule is available, None otherwise
    /// Returns error if buffer size exceeds maximum allowed size
    pub fn add_bytes(&mut self, data: Bytes) -> Result<Option<UdpCapsule>> {
        // Check if adding data would exceed maximum buffer size
        if self.buf.len() + data.len() > self.max_buffer_size {
            bail!(
                "buffer size exceeded: {} + {} > {}",
                self.buf.len(),
                data.len(),
                self.max_buffer_size
            );
        }

        self.buf.extend_from_slice(&data);

        // If we don't know the length yet, try to read it
        if self.expecting_len.is_none() {
            if self.buf.len() < 4 {
                return Ok(None); // Need more data for length
            }

            let len =
                u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;

            const MAX_CAPSULE_SIZE: usize = 65536;
            if len > MAX_CAPSULE_SIZE {
                bail!("capsule too large: {} > {}", len, MAX_CAPSULE_SIZE);
            }

            self.expecting_len = Some(len);
            self.buf.advance(4);
        }

        // Now we know the length, check if we have enough data
        // SAFETY: expecting_len is guaranteed to be Some(len) here because we just set it
        // in the previous branch. However, we use expect() with a descriptive message
        // for better error reporting in case of logic errors.
        let expected = self.expecting_len.expect(
            "expecting_len should be Some after reading length prefix - this indicates a logic bug",
        );
        if self.buf.len() < expected {
            return Ok(None); // Need more data
        }

        // Extract the capsule
        let capsule_data = self.buf.split_to(expected);
        self.expecting_len = None;

        // Decode capsule
        let capsule = UdpCapsule::decode(capsule_data.freeze())?;
        Ok(Some(capsule))
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty() && self.expecting_len.is_none()
    }
}

/// Context ID manager for MASQUE CONNECT-UDP sessions
///
/// Manages allocation and lifecycle of context IDs for different capsule types.
/// Each CONNECT-UDP session can have multiple contexts (e.g., different UDP targets).
#[derive(Debug, Clone)]
pub struct ContextIdManager {
    /// Base context ID for this session
    base_id: u64,
    /// Next available context ID
    next_id: u64,
    /// Maximum context IDs per session
    max_contexts: u64,
}

impl ContextIdManager {
    /// Create a new context ID manager
    ///
    /// # Arguments
    ///
    /// * `base_id` - Base context ID (typically 0 for UDP, 1 for handshake)
    /// * `max_contexts` - Maximum number of contexts to allocate
    pub fn new(base_id: u64, max_contexts: u64) -> Self {
        Self {
            base_id,
            next_id: base_id,
            max_contexts,
        }
    }

    /// Allocate a new context ID
    ///
    /// Returns None if maximum contexts reached
    pub fn allocate(&mut self) -> Option<u64> {
        if self.next_id - self.base_id >= self.max_contexts {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        Some(id)
    }

    /// Check if a context ID is valid for this manager
    pub fn is_valid(&self, context_id: u64) -> bool {
        context_id >= self.base_id && context_id < self.next_id
    }

    /// Get base context ID
    pub fn base_id(&self) -> u64 {
        self.base_id
    }

    /// Get number of allocated contexts
    pub fn allocated_count(&self) -> u64 {
        self.next_id - self.base_id
    }

    /// Reset the manager (for testing)
    #[cfg(test)]
    pub fn reset(&mut self) {
        self.next_id = self.base_id;
    }
}

/// Optimized UDP forwarding buffer for batching datagrams
///
/// Batches multiple UDP packets before forwarding to reduce overhead.
#[derive(Debug)]
pub struct UdpForwardingBuffer {
    /// Buffered datagrams
    buffer: Vec<(Bytes, std::net::SocketAddr)>,
    /// Maximum buffer size
    max_size: usize,
    /// Maximum batch size
    max_batch: usize,
    /// Flush interval (milliseconds)
    flush_interval_ms: u64,
}

impl UdpForwardingBuffer {
    /// Create a new UDP forwarding buffer
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum total buffer size in bytes
    /// * `max_batch` - Maximum number of datagrams per batch
    /// * `flush_interval_ms` - Flush interval in milliseconds
    pub fn new(max_size: usize, max_batch: usize, flush_interval_ms: u64) -> Self {
        Self {
            buffer: Vec::with_capacity(max_batch),
            max_size,
            max_batch,
            flush_interval_ms,
        }
    }

    /// Add a datagram to the buffer
    ///
    /// Returns true if buffer should be flushed (before adding this datagram).
    /// The datagram is NOT added if flush is needed.
    pub fn add(&mut self, data: Bytes, addr: std::net::SocketAddr) -> bool {
        let data_size = data.len();

        // Check if adding would exceed limits
        let current_size: usize = self.buffer.iter().map(|(d, _)| d.len()).sum();
        let total_size = current_size + data_size;

        if total_size > self.max_size || self.buffer.len() >= self.max_batch {
            return true; // Should flush before adding
        }

        self.buffer.push((data, addr));
        false
    }

    /// Take all buffered datagrams
    pub fn take(&mut self) -> Vec<(Bytes, std::net::SocketAddr)> {
        std::mem::take(&mut self.buffer)
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Get flush interval
    pub fn flush_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.flush_interval_ms)
    }

    /// Get current buffer size
    pub fn size(&self) -> usize {
        self.buffer.iter().map(|(d, _)| d.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_masque_path() {
        let target = ConnectUdpTarget::from_path("/.well-known/masque/udp/example.com/443/")
            .expect("test: failed to parse path");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn parse_simple_path() {
        let target =
            ConnectUdpTarget::from_path("/udp/1.1.1.1/53").expect("test: failed to parse path");
        assert_eq!(target.host, "1.1.1.1");
        assert_eq!(target.port, 53);
    }

    #[test]
    fn validate_localhost_rejected() {
        let target = ConnectUdpTarget {
            host: "localhost".into(),
            port: 8080,
        };
        assert!(target.validate().is_err());
    }

    #[test]
    fn validate_loopback_rejected() {
        let target = ConnectUdpTarget {
            host: "127.0.0.1".into(),
            port: 8080,
        };
        assert!(target.validate().is_err());
    }

    #[test]
    fn validate_external_ok() {
        let target = ConnectUdpTarget {
            host: "8.8.8.8".into(),
            port: 53,
        };
        assert!(target.validate().is_ok());
    }

    #[test]
    fn varint_roundtrip() {
        for val in [0u64, 63, 64, 16383, 16384, 1073741823, 1073741824] {
            let encoded = encode_varint(val);
            let mut buf = encoded.clone();
            let decoded = decode_varint(&mut buf).expect("test: failed to decode varint");
            assert_eq!(val, decoded, "varint roundtrip failed for {}", val);
        }
    }

    #[test]
    fn capsule_roundtrip() {
        let payload = Bytes::from_static(b"hello world");
        let capsule = UdpCapsule::new(payload.clone());
        let encoded = capsule.encode();
        let decoded = UdpCapsule::decode(encoded).expect("test: failed to decode capsule");
        assert_eq!(decoded.context_id, CONTEXT_ID_UDP);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn handshake_capsule_creation() {
        let payload = Bytes::from_static(b"handshake data");
        let capsule = UdpCapsule::new_handshake(payload.clone());
        assert!(capsule.is_handshake());
        assert!(!capsule.is_udp());
        assert_eq!(capsule.context_id, CONTEXT_ID_HANDSHAKE);
        assert_eq!(capsule.payload, payload);
    }

    #[test]
    fn udp_capsule_checks() {
        let payload = Bytes::from_static(b"udp data");
        let capsule = UdpCapsule::new(payload.clone());
        assert!(capsule.is_udp());
        assert!(!capsule.is_handshake());
        assert!(!capsule.is_close());
        assert_eq!(capsule.context_id, CONTEXT_ID_UDP);
        assert_eq!(capsule.capsule_type(), CapsuleType::Udp);
    }

    #[test]
    fn close_capsule_creation() {
        let payload = Bytes::from_static(b"close reason");
        let capsule = UdpCapsule::new_close(payload.clone());
        assert!(capsule.is_close());
        assert!(!capsule.is_udp());
        assert!(!capsule.is_handshake());
        assert_eq!(capsule.context_id, CONTEXT_ID_CLOSE);
        assert_eq!(capsule.capsule_type(), CapsuleType::Close);
    }

    #[test]
    fn address_request_capsule() {
        let payload = Bytes::from_static(b"address request");
        let capsule = UdpCapsule::new_address_request(payload.clone());
        assert_eq!(capsule.context_id, CONTEXT_ID_ADDRESS_REQUEST);
        assert_eq!(capsule.capsule_type(), CapsuleType::AddressRequest);
        assert_eq!(capsule.payload, payload);
    }

    #[test]
    fn address_assign_capsule() {
        let payload = Bytes::from_static(b"address assign");
        let capsule = UdpCapsule::new_address_assign(payload.clone());
        assert_eq!(capsule.context_id, CONTEXT_ID_ADDRESS_ASSIGN);
        assert_eq!(capsule.capsule_type(), CapsuleType::AddressAssign);
        assert_eq!(capsule.payload, payload);
    }

    #[test]
    fn capsule_type_roundtrip() {
        let types = vec![
            CapsuleType::Udp,
            CapsuleType::Handshake,
            CapsuleType::AddressRequest,
            CapsuleType::AddressAssign,
            CapsuleType::Close,
            CapsuleType::Unknown(100),
        ];

        for cap_type in types {
            let id = cap_type.context_id();
            let reconstructed = CapsuleType::from_context_id(id);
            assert_eq!(cap_type.context_id(), reconstructed.context_id());
        }
    }

    #[test]
    fn context_id_manager_allocation() {
        let mut manager = ContextIdManager::new(0, 10);

        // Allocate first few IDs
        assert_eq!(manager.allocate(), Some(0));
        assert_eq!(manager.allocate(), Some(1));
        assert_eq!(manager.allocate(), Some(2));

        assert_eq!(manager.allocated_count(), 3);
        assert!(manager.is_valid(0));
        assert!(manager.is_valid(1));
        assert!(manager.is_valid(2));
        assert!(!manager.is_valid(10));
    }

    #[test]
    fn context_id_manager_max_limit() {
        let mut manager = ContextIdManager::new(0, 3);

        assert_eq!(manager.allocate(), Some(0));
        assert_eq!(manager.allocate(), Some(1));
        assert_eq!(manager.allocate(), Some(2));
        assert_eq!(manager.allocate(), None); // Max reached
    }

    #[test]
    fn udp_forwarding_buffer() {
        let mut buffer = UdpForwardingBuffer::new(1000, 10, 100);
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));

        // Add datagrams
        assert!(!buffer.add(Bytes::from_static(b"data1"), addr));
        assert!(!buffer.add(Bytes::from_static(b"data2"), addr));

        assert_eq!(buffer.size(), 10); // 5 + 5 bytes
        assert!(!buffer.is_empty());

        // Take all
        let batch = buffer.take();
        assert_eq!(batch.len(), 2);
        assert!(buffer.is_empty());
    }

    #[test]
    fn udp_forwarding_buffer_flush_on_limit() {
        let mut buffer = UdpForwardingBuffer::new(10, 5, 100);
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));

        // Add until limit - first packet fits (5 bytes)
        assert!(!buffer.add(Bytes::from_static(b"12345"), addr));
        assert_eq!(buffer.size(), 5);

        // Second packet would exceed size limit (5 + 6 = 11 > 10)
        // So add() should return true indicating flush needed BEFORE adding
        // The packet is NOT added, so buffer size remains 5
        let should_flush = buffer.add(Bytes::from_static(b"123456"), addr); // 6 bytes
        assert!(
            should_flush,
            "Should indicate flush needed when size limit exceeded"
        );

        // Verify buffer still has only first packet (second was not added)
        assert_eq!(buffer.size(), 5);
        let batch = buffer.take();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].0.as_ref(), b"12345");
    }

    #[tokio::test]
    async fn read_write_capsule_roundtrip() {
        use tokio::io::duplex;

        let payload = Bytes::from_static(b"test capsule payload");
        let original = UdpCapsule::new_handshake(payload.clone());
        let original_payload = original.payload.clone();
        let original_context_id = original.context_id;

        let (mut reader, mut writer) = duplex(8192);

        // Write capsule in background
        let write_handle = tokio::spawn(async move {
            write_capsule(&mut writer, &original)
                .await
                .expect("test: failed to write capsule");
        });

        // Read capsule
        let read_handle = tokio::spawn(async move {
            read_capsule(&mut reader)
                .await
                .expect("test: failed to read capsule")
        });

        write_handle.await.expect("write task should complete");
        let decoded = read_handle.await.expect("read task should complete");

        assert_eq!(decoded.context_id, original_context_id);
        assert_eq!(decoded.payload, original_payload);
        assert!(decoded.is_handshake());
    }
}
