use crate::{rng, CryptoError, Result};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext, PublicKey, SecretKey as KemSecretKey, SharedSecret as KemSharedSecret,
};
use sha2::Sha256;
use snow::{Builder, HandshakeState, TransportState};
use zeroize::{Zeroize, Zeroizing};

/// Noise pattern for known server (IK)
pub const PATTERN_IK: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
/// Noise pattern for anonymous server (NK)
pub const PATTERN_NK: &str = "Noise_NK_25519_ChaChaPoly_SHA256";

/// Hybrid keypair combining X25519 (classical) and ML-KEM768 (post-quantum)
pub struct HybridKeypair {
    pub x25519_secret: [u8; 32],
    pub x25519_public: [u8; 32],
    pub mlkem_secret: HybridMlKemSecret,
    pub mlkem_public: mlkem768::PublicKey,
}

/// Wrapper to own ML-KEM secret bytes with explicit zeroization on drop.
pub struct HybridMlKemSecret {
    bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl HybridMlKemSecret {
    pub fn from_secret_key(sk: mlkem768::SecretKey) -> Self {
        Self {
            bytes: zeroize::Zeroizing::new(sk.as_bytes().to_vec()),
        }
    }

    pub fn decapsulate(&self, ct: &mlkem768::Ciphertext) -> mlkem768::SharedSecret {
        // Reconstruct secret key from stored bytes for each decapsulation.
        // This avoids keeping the library secret key in memory long-term.
        let sk = mlkem768::SecretKey::from_bytes(&self.bytes)
            .expect("stored ML-KEM secret bytes must be valid");
        mlkem768::decapsulate(ct, &sk)
    }

    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl zeroize::Zeroize for HybridMlKemSecret {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl HybridKeypair {
    /// Generate new hybrid keypair
    pub fn generate() -> Self {
        let mut x25519_secret = [0u8; 32];
        rng::fill(&mut x25519_secret);
        let x25519_public =
            x25519_dalek::x25519(x25519_secret, x25519_dalek::X25519_BASEPOINT_BYTES);

        let (mlkem_public, mlkem_secret) = mlkem768::keypair();

        Self {
            x25519_secret,
            x25519_public,
            mlkem_secret: HybridMlKemSecret::from_secret_key(mlkem_secret),
            mlkem_public,
        }
    }

    /// Export public keys for transmission
    pub fn public_bundle(&self) -> HybridPublic {
        HybridPublic {
            x25519: self.x25519_public,
            mlkem: self.mlkem_public.as_bytes().to_vec(),
        }
    }

    /// Derive hybrid shared secret from peer's public key and ciphertext
    pub fn decapsulate(
        &self,
        peer_x25519: &[u8; 32],
        mlkem_ciphertext: &[u8],
    ) -> Result<HybridSecret> {
        // X25519 DH
        let x25519_shared = x25519_dalek::x25519(self.x25519_secret, *peer_x25519);

        // ML-KEM decapsulation
        let ct = mlkem768::Ciphertext::from_bytes(mlkem_ciphertext)
            .map_err(|_| CryptoError::Decrypt("invalid ML-KEM ciphertext".into()))?;
        let mlkem_shared = self.mlkem_secret.decapsulate(&ct);

        Ok(HybridSecret::combine(
            &x25519_shared,
            mlkem_shared.as_bytes(),
        ))
    }
}

impl Drop for HybridKeypair {
    fn drop(&mut self) {
        self.x25519_secret.zeroize();
        self.mlkem_secret.zeroize();
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Public portion of hybrid keypair
#[derive(Clone)]
pub struct HybridPublic {
    pub x25519: [u8; 32],
    pub mlkem: Vec<u8>, // 1184 bytes for ML-KEM768
}

impl HybridPublic {
    pub fn from_bytes(x25519: &[u8], mlkem: &[u8]) -> Result<Self> {
        if x25519.len() != 32 {
            return Err(CryptoError::InvalidKey(
                "x25519 public must be 32 bytes".into(),
            ));
        }
        if mlkem.len() != 1184 {
            return Err(CryptoError::InvalidKey(
                "ML-KEM768 public must be 1184 bytes".into(),
            ));
        }
        let mut x25519_arr = [0u8; 32];
        x25519_arr.copy_from_slice(x25519);
        Ok(Self {
            x25519: x25519_arr,
            mlkem: mlkem.to_vec(),
        })
    }

    /// Encapsulate: generate ciphertext and shared secret using provided ephemeral
    pub fn encapsulate(&self, local_x25519_secret: &[u8; 32]) -> Result<(Vec<u8>, HybridSecret)> {
        // X25519 DH
        let x25519_shared = x25519_dalek::x25519(*local_x25519_secret, self.x25519);

        // ML-KEM encapsulation
        let pk = mlkem768::PublicKey::from_bytes(&self.mlkem)
            .map_err(|_| CryptoError::InvalidKey("invalid ML-KEM public key".into()))?;
        let (mlkem_shared, ciphertext) = mlkem768::encapsulate(&pk);

        let secret = HybridSecret::combine(&x25519_shared, mlkem_shared.as_bytes());
        Ok((ciphertext.as_bytes().to_vec(), secret))
    }

    /// Serialize for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + self.mlkem.len());
        buf.extend_from_slice(&self.x25519);
        buf.extend_from_slice(&self.mlkem);
        buf
    }
}

/// Combined hybrid shared secret
pub struct HybridSecret {
    pub combined: [u8; 32],
}

impl HybridSecret {
    /// Combine X25519 and ML-KEM shared secrets using HKDF
    pub fn combine(x25519: &[u8; 32], mlkem: &[u8]) -> Self {
        // Use Zeroizing to ensure intermediate key material is cleared
        let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(32 + mlkem.len()));
        ikm.extend_from_slice(x25519);
        ikm.extend_from_slice(mlkem);

        let hk = Hkdf::<Sha256>::new(Some(b"VPR-Hybrid-KEM"), &ikm);
        let mut combined = [0u8; 32];
        hk.expand(b"hybrid-secret", &mut combined)
            .expect("32 bytes is valid output length");

        // ikm is zeroized when dropped here
        Self { combined }
    }
}

impl Drop for HybridSecret {
    fn drop(&mut self) {
        self.combined.zeroize();
    }
}

/// Noise + Hybrid PQ handshake initiator (client)
///
/// Protocol flow:
/// 1. Client sends: [Noise e, es, s, ss] + [HybridPublic]
/// 2. Server sends: [Noise e, ee, se] + [ServerHybridPublic] + [ML-KEM ciphertext for client]
/// 3. Both derive: NoiseKey XOR HybridSecret for final session key
pub struct NoiseInitiator {
    state: HandshakeState,
    hybrid_keypair: HybridKeypair,
}

impl NoiseInitiator {
    /// Create IK pattern initiator (knows server's static key)
    pub fn new_ik(local_static: &[u8; 32], remote_static: &[u8; 32]) -> Result<Self> {
        let keypair = HybridKeypair::generate();
        let builder = Builder::new(PATTERN_IK.parse().unwrap())
            .local_private_key(local_static)
            .remote_public_key(remote_static);
        let state = builder.build_initiator()?;
        Ok(Self {
            state,
            hybrid_keypair: keypair,
        })
    }

    /// Create NK pattern initiator (anonymous to server)
    pub fn new_nk(remote_static: &[u8; 32]) -> Result<Self> {
        let keypair = HybridKeypair::generate();
        let builder = Builder::new(PATTERN_NK.parse().unwrap()).remote_public_key(remote_static);
        let state = builder.build_initiator()?;
        Ok(Self {
            state,
            hybrid_keypair: keypair,
        })
    }

    /// Get our hybrid public for inclusion in handshake
    pub fn hybrid_public(&self) -> HybridPublic {
        self.hybrid_keypair.public_bundle()
    }

    /// Write first handshake message
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        let len = self.state.write_message(payload, &mut buf)?;
        buf.truncate(len);

        // Append our hybrid public bundle
        let bundle = self.hybrid_keypair.public_bundle();
        buf.extend_from_slice(&bundle.to_bytes());

        Ok(buf)
    }

    /// Read handshake response and compute hybrid secret
    /// Message format: [Noise message] + [Server HybridPublic] + [ML-KEM ciphertext]
    pub fn read_message(&mut self, message: &[u8]) -> Result<(Vec<u8>, HybridSecret)> {
        const HYBRID_PUB_LEN: usize = 32 + 1184; // X25519 + ML-KEM768
        const MLKEM_CT_LEN: usize = 1088;
        const SUFFIX_LEN: usize = HYBRID_PUB_LEN + MLKEM_CT_LEN;

        if message.len() < SUFFIX_LEN {
            return Err(CryptoError::Noise("message too short".into()));
        }

        let noise_len = message.len() - SUFFIX_LEN;
        let noise_msg = &message[..noise_len];
        let server_hybrid_bytes = &message[noise_len..noise_len + HYBRID_PUB_LEN];
        let mlkem_ct = &message[noise_len + HYBRID_PUB_LEN..];

        // Process Noise message
        let mut payload = vec![0u8; 65535];
        let len = self.state.read_message(noise_msg, &mut payload)?;
        payload.truncate(len);

        // Parse server's hybrid public
        let server_hybrid =
            HybridPublic::from_bytes(&server_hybrid_bytes[..32], &server_hybrid_bytes[32..])?;

        // Decapsulate using our keypair and server's X25519 public
        let hybrid_secret = self
            .hybrid_keypair
            .decapsulate(&server_hybrid.x25519, mlkem_ct)?;

        Ok((payload, hybrid_secret))
    }

    /// Complete handshake and get transport state
    pub fn into_transport(self) -> Result<NoiseTransport> {
        let transport = self.state.into_transport_mode()?;
        Ok(NoiseTransport { state: transport })
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }
}

/// Noise + Hybrid PQ handshake responder (server)
pub struct NoiseResponder {
    state: HandshakeState,
    hybrid_keypair: HybridKeypair,
}

impl NoiseResponder {
    /// Create IK pattern responder
    pub fn new_ik(local_static: &[u8; 32]) -> Result<Self> {
        let keypair = HybridKeypair::generate();
        let builder = Builder::new(PATTERN_IK.parse().unwrap()).local_private_key(local_static);
        let state = builder.build_responder()?;
        Ok(Self {
            state,
            hybrid_keypair: keypair,
        })
    }

    /// Create NK pattern responder
    pub fn new_nk(local_static: &[u8; 32]) -> Result<Self> {
        let keypair = HybridKeypair::generate();
        let builder = Builder::new(PATTERN_NK.parse().unwrap()).local_private_key(local_static);
        let state = builder.build_responder()?;
        Ok(Self {
            state,
            hybrid_keypair: keypair,
        })
    }

    /// Read first handshake message (includes client's hybrid public bundle)
    pub fn read_message(&mut self, message: &[u8]) -> Result<(Vec<u8>, HybridPublic)> {
        const HYBRID_PUB_LEN: usize = 32 + 1184; // X25519 + ML-KEM768

        if message.len() < HYBRID_PUB_LEN {
            return Err(CryptoError::Noise(
                "message too short for hybrid public".into(),
            ));
        }

        let noise_len = message.len() - HYBRID_PUB_LEN;
        let noise_msg = &message[..noise_len];
        let hybrid_pub_bytes = &message[noise_len..];

        let mut payload = vec![0u8; 65535];
        let len = self.state.read_message(noise_msg, &mut payload)?;
        payload.truncate(len);

        let peer_hybrid =
            HybridPublic::from_bytes(&hybrid_pub_bytes[..32], &hybrid_pub_bytes[32..])?;

        Ok((payload, peer_hybrid))
    }

    /// Write response with our hybrid public and ML-KEM ciphertext
    pub fn write_message(
        &mut self,
        payload: &[u8],
        peer_hybrid: &HybridPublic,
    ) -> Result<(Vec<u8>, HybridSecret)> {
        let mut buf = vec![0u8; 65535];
        let len = self.state.write_message(payload, &mut buf)?;
        buf.truncate(len);

        // Append our hybrid public
        let our_hybrid = self.hybrid_keypair.public_bundle();
        buf.extend_from_slice(&our_hybrid.to_bytes());

        // Encapsulate to peer's hybrid public using our ephemeral X25519
        let (mlkem_ct, hybrid_secret) =
            peer_hybrid.encapsulate(&self.hybrid_keypair.x25519_secret)?;
        buf.extend_from_slice(&mlkem_ct);

        Ok((buf, hybrid_secret))
    }

    /// Complete handshake and get transport state
    pub fn into_transport(self) -> Result<NoiseTransport> {
        let transport = self.state.into_transport_mode()?;
        Ok(NoiseTransport { state: transport })
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }
}

/// Noise transport for encrypted communication
pub struct NoiseTransport {
    state: TransportState,
}

impl NoiseTransport {
    /// Encrypt message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // AEAD tag
        let len = self.state.write_message(plaintext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt message
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self.state.read_message(ciphertext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Rekey (for forward secrecy after data threshold)
    pub fn rekey_outgoing(&mut self) {
        self.state.rekey_outgoing();
    }

    pub fn rekey_incoming(&mut self) {
        self.state.rekey_incoming();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_secret_zeroizes() {
        let mut kp = HybridKeypair::generate();
        // Zeroize explicitly to inspect buffer
        kp.mlkem_secret.zeroize();
        assert!(
            kp.mlkem_secret.as_bytes().iter().all(|&b| b == 0),
            "ML-KEM secret must be zeroized"
        );
    }

    #[test]
    fn hybrid_keypair_generation_hits_osrng() {
        crate::rng::reset_osrng_calls();
        let _ = HybridKeypair::generate();
        assert!(
            crate::rng::osrng_call_count() >= 1,
            "Hybrid key generation must draw from OsRng"
        );
    }

    #[test]
    fn hybrid_keypair_encap_decap() {
        let kp = HybridKeypair::generate();
        let public = kp.public_bundle();

        // Generate ephemeral for encapsulation
        let mut eph_secret = [0u8; 32];
        rng::fill(&mut eph_secret);
        let eph_public = x25519_dalek::x25519(eph_secret, x25519_dalek::X25519_BASEPOINT_BYTES);

        let (ct, secret1) = public.encapsulate(&eph_secret).unwrap();
        let secret2 = kp.decapsulate(&eph_public, &ct).unwrap();

        assert_eq!(secret1.combined, secret2.combined);
    }

    #[test]
    fn noise_ik_handshake() {
        // Generate static keys
        let mut server_static = [0u8; 32];
        rng::fill(&mut server_static);
        let server_public =
            x25519_dalek::x25519(server_static, x25519_dalek::X25519_BASEPOINT_BYTES);

        let mut client_static = [0u8; 32];
        rng::fill(&mut client_static);

        // Handshake
        let mut initiator = NoiseInitiator::new_ik(&client_static, &server_public).unwrap();
        let mut responder = NoiseResponder::new_ik(&server_static).unwrap();

        // -> e, es, s, ss + HybridPublic
        let msg1 = initiator.write_message(b"hello").unwrap();
        let (payload1, peer_hybrid) = responder.read_message(&msg1).unwrap();
        assert_eq!(payload1, b"hello");

        // <- e, ee, se + ServerHybridPublic + ML-KEM CT
        let (msg2, server_hybrid_secret) = responder.write_message(b"world", &peer_hybrid).unwrap();
        let (payload2, client_hybrid_secret) = initiator.read_message(&msg2).unwrap();
        assert_eq!(payload2, b"world");

        // Verify hybrid secrets match
        assert_eq!(server_hybrid_secret.combined, client_hybrid_secret.combined);

        // Transport mode
        let mut client_transport = initiator.into_transport().unwrap();
        let mut server_transport = responder.into_transport().unwrap();

        // Encrypted communication
        let ct = client_transport.encrypt(b"secret message").unwrap();
        let pt = server_transport.decrypt(&ct).unwrap();
        assert_eq!(pt, b"secret message");
    }
}
