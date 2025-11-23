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
            write_frame(&mut client, &send_buf).await.unwrap();
        });
        let got = read_frame(&mut server).await.unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn connect_frame_build_parse() {
        let req = ConnectRequest {
            proto: Proto::Tcp,
            host: "example.com".into(),
            port: 443,
        };
        let frame = build_connect_frame(&req).unwrap();
        let parsed = parse_connect_frame(&frame).unwrap();
        assert_eq!(req, parsed);
    }
}
