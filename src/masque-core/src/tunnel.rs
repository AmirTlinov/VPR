use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum payload per frame to keep memory predictable.
pub const MAX_FRAME: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp = 0,
    Udp = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub proto: Proto,
    pub host: String,
    pub port: u16,
}

impl ConnectRequest {
    pub fn to_target(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Read a length-prefixed frame (u16 big-endian).
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a length-prefixed frame (u16 big-endian).
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = data.len();
    if len > MAX_FRAME {
        bail!("frame too large: {} bytes", len);
    }
    let len_buf = (len as u16).to_be_bytes();
    writer.write_all(&len_buf).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Parse connect request from a small framed payload.
pub fn parse_connect_frame(frame: &[u8]) -> Result<ConnectRequest> {
    if frame.len() < 5 {
        bail!("connect frame too short");
    }
    let version = frame[0];
    if version != 1 {
        bail!("unsupported connect frame version {version}");
    }
    let proto = match frame[1] {
        0 => Proto::Tcp,
        1 => Proto::Udp,
        other => bail!("unsupported proto {other}"),
    };
    let host_len = frame[2] as usize;
    if frame.len() < 3 + host_len + 2 {
        bail!("connect frame malformed");
    }
    let host = std::str::from_utf8(&frame[3..3 + host_len])?
        .trim()
        .to_string();
    let port_offset = 3 + host_len;
    let port = u16::from_be_bytes([frame[port_offset], frame[port_offset + 1]]);
    if host.is_empty() || port == 0 {
        bail!("connect frame missing host/port");
    }
    Ok(ConnectRequest { proto, host, port })
}

/// Serialize connect request into a frame payload.
pub fn build_connect_frame(req: &ConnectRequest) -> Result<Vec<u8>> {
    if req.host.len() > u8::MAX as usize {
        bail!("hostname too long");
    }
    if req.port == 0 {
        bail!("port must be non-zero");
    }
    let mut buf = Vec::with_capacity(1 + 1 + req.host.len() + 2);
    buf.push(1); // version
    buf.push(match req.proto {
        Proto::Tcp => 0,
        Proto::Udp => 1,
    });
    buf.push(req.host.len() as u8);
    buf.extend_from_slice(req.host.as_bytes());
    buf.extend_from_slice(&req.port.to_be_bytes());
    Ok(buf)
}

/// Helper to read a connect request frame from a stream.
pub async fn read_connect_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<ConnectRequest> {
    let frame = read_frame(reader).await?;
    if frame.is_empty() {
        return Err(anyhow!("empty connect frame"));
    }
    parse_connect_frame(&frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut client, mut server) = duplex(64);
        let payload = b"hello world".to_vec();
        let send_buf = payload.clone();
        tokio::spawn(async move {
            write_frame(&mut client, &send_buf)
                .await
                .expect("test: failed to write frame");
        });
        let got = read_frame(&mut server)
            .await
            .expect("test: failed to read frame");
        assert_eq!(got, payload);
    }

    #[test]
    fn connect_frame_build_parse() {
        let req = ConnectRequest {
            proto: Proto::Tcp,
            host: "example.com".into(),
            port: 443,
        };
        let frame = build_connect_frame(&req).expect("test: failed to build frame");
        let parsed = parse_connect_frame(&frame).expect("test: failed to parse frame");
        assert_eq!(req, parsed);
    }

    #[test]
    fn test_proto_equality() {
        assert_eq!(Proto::Tcp, Proto::Tcp);
        assert_eq!(Proto::Udp, Proto::Udp);
        assert_ne!(Proto::Tcp, Proto::Udp);
    }

    #[test]
    fn test_proto_serialization() {
        let json = serde_json::to_string(&Proto::Tcp).unwrap();
        assert_eq!(json, "\"Tcp\"");
        let json = serde_json::to_string(&Proto::Udp).unwrap();
        assert_eq!(json, "\"Udp\"");
    }

    #[test]
    fn test_connect_request_to_target() {
        let req = ConnectRequest {
            proto: Proto::Tcp,
            host: "example.com".into(),
            port: 8080,
        };
        assert_eq!(req.to_target(), "example.com:8080");
    }

    #[test]
    fn test_connect_request_clone() {
        let req = ConnectRequest {
            proto: Proto::Udp,
            host: "test.local".into(),
            port: 53,
        };
        let cloned = req.clone();
        assert_eq!(req, cloned);
    }

    #[test]
    fn test_connect_request_debug() {
        let req = ConnectRequest {
            proto: Proto::Tcp,
            host: "debug.test".into(),
            port: 443,
        };
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("ConnectRequest"));
        assert!(debug_str.contains("debug.test"));
    }

    #[test]
    fn test_connect_frame_udp() {
        let req = ConnectRequest {
            proto: Proto::Udp,
            host: "dns.example.com".into(),
            port: 53,
        };
        let frame = build_connect_frame(&req).unwrap();
        let parsed = parse_connect_frame(&frame).unwrap();
        assert_eq!(parsed.proto, Proto::Udp);
        assert_eq!(parsed.host, "dns.example.com");
        assert_eq!(parsed.port, 53);
    }

    #[test]
    fn test_parse_connect_frame_too_short() {
        let short_frame = &[1, 0, 5]; // version, proto, host_len but no host
        let result = parse_connect_frame(short_frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_parse_connect_frame_wrong_version() {
        let wrong_version = &[2, 0, 0, 0, 80]; // version 2
        let result = parse_connect_frame(wrong_version);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported"));
    }

    #[test]
    fn test_parse_connect_frame_unsupported_proto() {
        // version=1, proto=99 (unsupported), host_len=1, host='a', port
        let bad_proto = &[1, 99, 1, b'a', 0, 80];
        let result = parse_connect_frame(bad_proto);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported proto"));
    }

    #[test]
    fn test_parse_connect_frame_malformed() {
        // version=1, proto=0, host_len=100 but only 5 bytes of host
        let malformed = &[1, 0, 100, b'a', b'b', b'c', b'd', b'e'];
        let result = parse_connect_frame(malformed);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("malformed"));
    }

    #[test]
    fn test_parse_connect_frame_empty_host() {
        // version=1, proto=0, host_len=0, port=80
        let empty_host = &[1, 0, 0, 0, 80];
        let result = parse_connect_frame(empty_host);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing host"));
    }

    #[test]
    fn test_parse_connect_frame_zero_port() {
        // version=1, proto=0, host_len=4, host="test", port=0
        let zero_port = &[1, 0, 4, b't', b'e', b's', b't', 0, 0];
        let result = parse_connect_frame(zero_port);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing"));
    }

    #[test]
    fn test_build_connect_frame_long_hostname() {
        let long_host = "a".repeat(256);
        let req = ConnectRequest {
            proto: Proto::Tcp,
            host: long_host,
            port: 443,
        };
        let result = build_connect_frame(&req);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("hostname too long"));
    }

    #[test]
    fn test_build_connect_frame_zero_port() {
        let req = ConnectRequest {
            proto: Proto::Tcp,
            host: "example.com".into(),
            port: 0,
        };
        let result = build_connect_frame(&req);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("port must be non-zero"));
    }

    #[tokio::test]
    async fn test_read_frame_empty() {
        let (mut client, mut server) = duplex(16);
        tokio::spawn(async move {
            // Send zero-length frame
            write_frame(&mut client, &[]).await.unwrap();
        });
        let got = read_frame(&mut server).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn test_write_frame_too_large() {
        let (mut client, _server) = duplex(16);
        let large_data = vec![0u8; MAX_FRAME + 1];
        let result = write_frame(&mut client, &large_data).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[tokio::test]
    async fn test_read_connect_request() {
        let req = ConnectRequest {
            proto: Proto::Tcp,
            host: "connect.test".into(),
            port: 9443,
        };
        let frame = build_connect_frame(&req).unwrap();

        let (mut client, mut server) = duplex(64);
        tokio::spawn(async move {
            write_frame(&mut client, &frame).await.unwrap();
        });

        let parsed = read_connect_request(&mut server).await.unwrap();
        assert_eq!(parsed.host, "connect.test");
        assert_eq!(parsed.port, 9443);
    }

    #[tokio::test]
    async fn test_read_connect_request_empty_frame() {
        let (mut client, mut server) = duplex(16);
        tokio::spawn(async move {
            write_frame(&mut client, &[]).await.unwrap();
        });

        let result = read_connect_request(&mut server).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("empty connect frame"));
    }

    #[test]
    fn test_max_frame_constant() {
        assert_eq!(MAX_FRAME, 65535);
    }

    #[test]
    fn test_connect_request_serialization() {
        let req = ConnectRequest {
            proto: Proto::Tcp,
            host: "serial.test".into(),
            port: 8443,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ConnectRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, parsed);
    }
}
