//! Hybrid Post-Quantum Noise handshake integration
//!
//! Wraps vpr-crypto's hybrid Noise (X25519 + ML-KEM768) for use in MASQUE server.
//! Provides both server (responder) and client (initiator) handshake flows.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use vpr_crypto::{
    keys::NoiseKeypair,
    noise::{HybridSecret, NoiseInitiator, NoiseResponder, NoiseTransport},
};

use crate::replay_protection::NonceCache;

/// Server-side hybrid Noise handshake state
pub struct HybridServer {
    keypair: NoiseKeypair,
    /// Optional replay protection cache
    replay_cache: Option<Arc<NonceCache>>,
}

impl HybridServer {
    /// Load server keypair from directory
    pub fn load(dir: &Path, name: &str) -> Result<Self> {
        let keypair = NoiseKeypair::load(dir, name).context("loading server noise keypair")?;
        Ok(Self {
            keypair,
            replay_cache: None,
        })
    }

    /// Create from raw secret key bytes
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let keypair = NoiseKeypair::from_secret_bytes(secret);
        Self {
            keypair,
            replay_cache: None,
        }
    }

    /// Enable replay protection with shared cache
    pub fn with_replay_protection(mut self, cache: Arc<NonceCache>) -> Self {
        self.replay_cache = Some(cache);
        self
    }

    /// Get replay cache metrics (if enabled)
    pub fn replay_metrics(&self) -> Option<crate::replay_protection::ReplayMetricsSnapshot> {
        self.replay_cache.as_ref().map(|c| c.metrics().snapshot())
    }

    /// Get public key bytes for distribution to clients
    pub fn public_key(&self) -> [u8; 32] {
        self.keypair.public_bytes()
    }

    /// Perform IK pattern handshake (client knows server's static key)
    pub async fn handshake_ik<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<(NoiseTransport, HybridSecret)> {
        let mut responder =
            NoiseResponder::new_ik(&self.keypair.secret_bytes()).context("creating responder")?;

        // Read client's first message: [Noise e,es,s,ss] + [HybridPublic]
        let msg1 = read_handshake_msg(stream).await?;

        // Check for replay attack
        if let Some(cache) = &self.replay_cache {
            cache
                .check_and_record(&msg1)
                .map_err(|e| anyhow::anyhow!("replay attack detected: {}", e))?;
        }

        let (_payload, peer_hybrid) = responder
            .read_message(&msg1)
            .context("reading client handshake")?;

        // Write response: [Noise e,ee,se] + [ServerHybridPublic] + [ML-KEM ciphertext]
        let (msg2, hybrid_secret) = responder
            .write_message(b"", &peer_hybrid)
            .context("writing server handshake")?;
        write_handshake_msg(stream, &msg2).await?;

        // Transition to transport mode
        let transport = responder.into_transport().context("transport mode")?;

        Ok((transport, hybrid_secret))
    }

    /// Perform NK pattern handshake (client is anonymous)
    pub async fn handshake_nk<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<(NoiseTransport, HybridSecret)> {
        let mut responder = NoiseResponder::new_nk(&self.keypair.secret_bytes())
            .context("creating NK responder")?;

        let msg1 = read_handshake_msg(stream).await?;

        // Check for replay attack
        if let Some(cache) = &self.replay_cache {
            cache
                .check_and_record(&msg1)
                .map_err(|e| anyhow::anyhow!("replay attack detected: {}", e))?;
        }

        let (_payload, peer_hybrid) = responder
            .read_message(&msg1)
            .context("reading client NK handshake")?;

        let (msg2, hybrid_secret) = responder
            .write_message(b"", &peer_hybrid)
            .context("writing server NK handshake")?;
        write_handshake_msg(stream, &msg2).await?;

        let transport = responder.into_transport().context("NK transport mode")?;

        Ok((transport, hybrid_secret))
    }
}

/// Client-side hybrid Noise handshake
pub struct HybridClient {
    client_keypair: NoiseKeypair,
    server_public: [u8; 32],
}

impl HybridClient {
    /// Create IK client (knows server's static key, has own identity)
    pub fn new_ik(client_secret: &[u8; 32], server_public: &[u8; 32]) -> Self {
        let client_keypair = NoiseKeypair::from_secret_bytes(client_secret);
        Self {
            client_keypair,
            server_public: *server_public,
        }
    }

    /// Create NK client (anonymous, only knows server's public key)
    pub fn new_nk(server_public: &[u8; 32]) -> Self {
        let client_keypair = NoiseKeypair::generate();
        Self {
            client_keypair,
            server_public: *server_public,
        }
    }

    /// Perform IK handshake from client side
    pub async fn handshake_ik<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<(NoiseTransport, HybridSecret)> {
        let mut initiator =
            NoiseInitiator::new_ik(&self.client_keypair.secret_bytes(), &self.server_public)
                .context("creating IK initiator")?;

        // Send first message
        let msg1 = initiator
            .write_message(b"")
            .context("writing client handshake")?;
        write_handshake_msg(stream, &msg1).await?;

        // Read server response
        let msg2 = read_handshake_msg(stream).await?;
        let (_payload, hybrid_secret) = initiator
            .read_message(&msg2)
            .context("reading server handshake")?;

        let transport = initiator
            .into_transport()
            .context("client transport mode")?;

        Ok((transport, hybrid_secret))
    }

    /// Perform NK handshake from client side
    pub async fn handshake_nk<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<(NoiseTransport, HybridSecret)> {
        let mut initiator =
            NoiseInitiator::new_nk(&self.server_public).context("creating NK initiator")?;

        let msg1 = initiator
            .write_message(b"")
            .context("writing NK client handshake")?;
        write_handshake_msg(stream, &msg1).await?;

        let msg2 = read_handshake_msg(stream).await?;
        let (_payload, hybrid_secret) = initiator
            .read_message(&msg2)
            .context("reading NK server response")?;

        let transport = initiator.into_transport().context("NK client transport")?;

        Ok((transport, hybrid_secret))
    }
}

/// Encrypted stream wrapper using Noise transport
pub struct EncryptedStream<S> {
    inner: S,
    transport: NoiseTransport,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> EncryptedStream<S> {
    pub fn new(stream: S, transport: NoiseTransport) -> Self {
        Self {
            inner: stream,
            transport,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    /// Read a decrypted frame
    pub async fn read_frame(&mut self) -> Result<Vec<u8>> {
        let ciphertext = read_handshake_msg(&mut self.inner).await?;
        if ciphertext.is_empty() {
            return Ok(Vec::new());
        }
        let plaintext = self
            .transport
            .decrypt(&ciphertext)
            .context("decrypting frame")?;
        Ok(plaintext)
    }

    /// Write an encrypted frame
    pub async fn write_frame(&mut self, data: &[u8]) -> Result<()> {
        let ciphertext = self.transport.encrypt(data).context("encrypting frame")?;
        write_handshake_msg(&mut self.inner, &ciphertext).await
    }

    /// Trigger rekey for forward secrecy
    pub fn rekey(&mut self) {
        self.transport.rekey_outgoing();
        self.transport.rekey_incoming();
    }

    /// Get mutable reference to inner stream
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume and return inner stream
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Read length-prefixed handshake message (u32 BE for larger PQ messages)
async fn read_handshake_msg<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("reading msg length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > 65536 {
        anyhow::bail!("handshake message too large: {len}");
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .context("reading msg body")?;
    Ok(buf)
}

/// Write length-prefixed handshake message
async fn write_handshake_msg<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .context("writing msg length")?;
    writer.write_all(data).await.context("writing msg body")?;
    writer.flush().await.context("flushing")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay_protection::NonceCache;
    use tokio::io::duplex;
    use vpr_crypto::keys::NoiseKeypair;

    #[tokio::test]
    async fn ik_handshake_roundtrip() {
        let server_kp = NoiseKeypair::generate();
        let client_kp = NoiseKeypair::generate();

        let server = HybridServer::from_secret(&server_kp.secret_bytes());
        let client = HybridClient::new_ik(&client_kp.secret_bytes(), &server.public_key());

        let (mut client_stream, mut server_stream) = duplex(8192);

        let server_handle =
            tokio::spawn(async move { server.handshake_ik(&mut server_stream).await });

        let client_result = client.handshake_ik(&mut client_stream).await;
        let server_result = server_handle.await.unwrap();

        let (client_transport, client_hybrid) = client_result.unwrap();
        let (server_transport, server_hybrid) = server_result.unwrap();

        // Hybrid secrets should match
        assert_eq!(client_hybrid.combined, server_hybrid.combined);
    }

    #[tokio::test]
    async fn encrypted_stream_roundtrip() {
        let server_kp = NoiseKeypair::generate();
        let client_kp = NoiseKeypair::generate();

        let server = HybridServer::from_secret(&server_kp.secret_bytes());
        let client = HybridClient::new_ik(&client_kp.secret_bytes(), &server.public_key());

        let (mut client_stream, mut server_stream) = duplex(8192);

        let server_handle = tokio::spawn(async move {
            let (transport, _) = server.handshake_ik(&mut server_stream).await.unwrap();
            let mut enc = EncryptedStream::new(server_stream, transport);
            let msg = enc.read_frame().await.unwrap();
            enc.write_frame(&msg).await.unwrap();
            msg
        });

        let (transport, _) = client.handshake_ik(&mut client_stream).await.unwrap();
        let mut enc = EncryptedStream::new(client_stream, transport);

        let test_msg = b"hello hybrid PQ world!";
        enc.write_frame(test_msg).await.unwrap();
        let echo = enc.read_frame().await.unwrap();

        assert_eq!(echo, test_msg);

        let server_msg = server_handle.await.unwrap();
        assert_eq!(server_msg, test_msg);
    }

    #[tokio::test]
    async fn replay_protection_blocks_duplicate() {
        let server_kp = NoiseKeypair::generate();
        let client_kp = NoiseKeypair::generate();

        let replay_cache = Arc::new(NonceCache::new());
        let server = HybridServer::from_secret(&server_kp.secret_bytes())
            .with_replay_protection(replay_cache.clone());

        // Create a fake "handshake message" to replay
        let fake_msg = b"fake handshake message for replay test";

        // First time should be recorded
        assert!(replay_cache.check_and_record(fake_msg).is_ok());

        // Second time should be blocked
        assert!(replay_cache.check_and_record(fake_msg).is_err());

        // Verify metrics
        let metrics = server.replay_metrics().unwrap();
        assert_eq!(metrics.messages_processed, 1);
        assert_eq!(metrics.replays_blocked, 1);
    }
}
