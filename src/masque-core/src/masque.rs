//! MASQUE CONNECT-UDP implementation (RFC 9298)
//!
//! Provides HTTP/3 Extended CONNECT handling for UDP proxying.

use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr};

/// Maximum UDP payload size per RFC 9298
pub const MAX_UDP_PAYLOAD: usize = 65_527;

/// CONNECT-UDP Context ID for raw UDP payloads
pub const CONTEXT_ID_UDP: u64 = 0;

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
    pub fn validate(&self) -> Result<()> {
        if self.port == 0 {
            bail!("port 0 is not allowed");
        }

        // Try to parse as IP address to check for forbidden ranges
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            if is_forbidden_ip(&ip) {
                bail!("target IP {} is forbidden", ip);
            }
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

/// UDP Datagram capsule for CONNECT-UDP
#[derive(Debug, Clone)]
pub struct UdpCapsule {
    pub context_id: u64,
    pub payload: Bytes,
}

impl UdpCapsule {
    /// Create a new UDP capsule with raw payload
    pub fn new(payload: Bytes) -> Self {
        Self {
            context_id: CONTEXT_ID_UDP,
            payload,
        }
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

        if context_id == CONTEXT_ID_UDP && payload.len() > MAX_UDP_PAYLOAD {
            bail!(
                "UDP payload too large: {} > {}",
                payload.len(),
                MAX_UDP_PAYLOAD
            );
        }

        Ok(Self {
            context_id,
            payload,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_masque_path() {
        let target =
            ConnectUdpTarget::from_path("/.well-known/masque/udp/example.com/443/").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn parse_simple_path() {
        let target = ConnectUdpTarget::from_path("/udp/1.1.1.1/53").unwrap();
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
            let decoded = decode_varint(&mut buf).unwrap();
            assert_eq!(val, decoded, "varint roundtrip failed for {}", val);
        }
    }

    #[test]
    fn capsule_roundtrip() {
        let payload = Bytes::from_static(b"hello world");
        let capsule = UdpCapsule::new(payload.clone());
        let encoded = capsule.encode();
        let decoded = UdpCapsule::decode(encoded).unwrap();
        assert_eq!(decoded.context_id, CONTEXT_ID_UDP);
        assert_eq!(decoded.payload, payload);
    }
}
