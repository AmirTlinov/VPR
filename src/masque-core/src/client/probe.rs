//! Probe protection client-side: PoW solver and challenge handler.

use anyhow::{Context, Result};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::padding::Padder;
use crate::quic_stream::QuicBiStream;
use crate::vpn_common::padding_schedule_bytes;

/// Solve proof-of-work challenge with given nonce and difficulty
///
/// Finds a 32-byte solution where SHA256(nonce || solution) has
/// `difficulty` leading zero bytes.
pub fn solve_pow(nonce: &[u8; 32], difficulty: u8) -> [u8; 32] {
    let mut counter: u64 = 0;
    let mut candidate = [0u8; 32];
    loop {
        candidate[..8].copy_from_slice(&counter.to_be_bytes());
        let mut hasher = Sha256::new();
        use sha2::Digest;
        hasher.update(nonce);
        hasher.update(candidate);
        let hash = hasher.finalize();
        let mut ok = true;
        for i in 0..difficulty as usize {
            if hash[i] != 0 {
                ok = false;
                break;
            }
        }
        if ok {
            return candidate;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Handle probe challenge from server before Noise handshake
///
/// Protocol:
/// 1. Server sends: [len:2][type:1][nonce:32][difficulty:1]
/// 2. Client responds: [len:2][type:1][solution:32][padding...]
pub async fn handle_probe_challenge(stream: &mut QuicBiStream, padder: &Padder) -> Result<()> {
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("reading probe challenge length")?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len != 34 {
        anyhow::bail!("unexpected probe challenge length: {len}");
    }

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("reading probe challenge payload")?;

    if buf[0] != 1 {
        anyhow::bail!("unexpected probe challenge type");
    }

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&buf[1..33]);
    let difficulty = buf[33];

    let solution = solve_pow(&nonce, difficulty);
    let padding_bytes = padding_schedule_bytes(padder);

    let mut resp = Vec::with_capacity(1 + 32 + padding_bytes.len());
    resp.push(2u8);
    resp.extend_from_slice(&solution);
    resp.extend_from_slice(&padding_bytes);

    let len_bytes = (resp.len() as u16).to_be_bytes();
    stream
        .write_all(&len_bytes)
        .await
        .context("writing probe response length")?;
    stream
        .write_all(&resp)
        .await
        .context("writing probe response")?;
    stream.flush().await.ok();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solve_pow_difficulty_1() {
        let nonce = [0u8; 32];
        let solution = solve_pow(&nonce, 1);

        // Verify solution
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(&nonce);
        hasher.update(&solution);
        let hash = hasher.finalize();

        assert_eq!(hash[0], 0, "First byte should be zero");
    }

    #[test]
    fn test_solve_pow_difficulty_2() {
        let nonce = [42u8; 32];
        let solution = solve_pow(&nonce, 2);

        // Verify solution
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(&nonce);
        hasher.update(&solution);
        let hash = hasher.finalize();

        assert_eq!(hash[0], 0, "First byte should be zero");
        assert_eq!(hash[1], 0, "Second byte should be zero");
    }
}
