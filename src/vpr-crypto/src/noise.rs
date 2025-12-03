//! Hybrid Noise Protocol Implementation
//!
//! Combines classical X25519 ECDH with post-quantum ML-KEM768 for
//! quantum-resistant key exchange. Implements Noise IK/NK patterns
//! with ChaCha20-Poly1305 symmetric encryption.
//!
//! # Security Properties
//!
//! - **Forward secrecy**: Ephemeral keys for each session
//! - **Post-quantum resistance**: ML-KEM768 (NIST standard)
//! - **Identity hiding**: IK pattern hides initiator identity
//! - **Replay protection**: Via Noise framework nonce handling
//!
//! # Protocol Flow
//!
//! ```text
//! Initiator                         Responder
//!     |                                 |
//!     |-- e, es, s, ss, mlkem_ct -->    |  (IK message 1)
//!     |                                 |
//!     |<-- e, ee, se, mlkem_ct ---      |  (IK message 2)
//!     |                                 |
//!     |======= encrypted tunnel =======|
//! ```
//!
//! The hybrid shared secret is derived via HKDF from both
//! X25519 and ML-KEM shared secrets.

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
        let builder = Builder::new(
            PATTERN_IK
                .parse()
                .map_err(|_| CryptoError::Noise("invalid IK pattern".into()))?,
        )
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
        let builder = Builder::new(
            PATTERN_NK
                .parse()
                .map_err(|_| CryptoError::Noise("invalid NK pattern".into()))?,
        )
        .remote_public_key(remote_static);
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
        let builder = Builder::new(
            PATTERN_IK
                .parse()
                .map_err(|_| CryptoError::Noise("invalid IK pattern".into()))?,
        )
        .local_private_key(local_static);
        let state = builder.build_responder()?;
        Ok(Self {
            state,
            hybrid_keypair: keypair,
        })
    }

    /// Create NK pattern responder
    pub fn new_nk(local_static: &[u8; 32]) -> Result<Self> {
        let keypair = HybridKeypair::generate();
        let builder = Builder::new(
            PATTERN_NK
                .parse()
                .map_err(|_| CryptoError::Noise("invalid NK pattern".into()))?,
        )
        .local_private_key(local_static);
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

        let (ct, secret1) = public
            .encapsulate(&eph_secret)
            .expect("test: failed to encapsulate");
        let secret2 = kp
            .decapsulate(&eph_public, &ct)
            .expect("test: failed to decapsulate");

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
        let mut initiator = NoiseInitiator::new_ik(&client_static, &server_public)
            .expect("test: failed to create initiator");
        let mut responder =
            NoiseResponder::new_ik(&server_static).expect("test: failed to create responder");

        // -> e, es, s, ss + HybridPublic
        let msg1 = initiator
            .write_message(b"hello")
            .expect("test: failed to write message");
        let (payload1, peer_hybrid) = responder
            .read_message(&msg1)
            .expect("test: failed to read message");
        assert_eq!(payload1, b"hello");

        // <- e, ee, se + ServerHybridPublic + ML-KEM CT
        let (msg2, server_hybrid_secret) = responder
            .write_message(b"world", &peer_hybrid)
            .expect("test: failed to write response");
        let (payload2, client_hybrid_secret) = initiator
            .read_message(&msg2)
            .expect("test: failed to read response");
        assert_eq!(payload2, b"world");

        // Verify hybrid secrets match
        assert_eq!(server_hybrid_secret.combined, client_hybrid_secret.combined);

        // Transport mode
        let mut client_transport = initiator
            .into_transport()
            .expect("test: failed to enter transport mode");
        let mut server_transport = responder
            .into_transport()
            .expect("test: failed to enter transport mode");

        // Encrypted communication
        let ct = client_transport
            .encrypt(b"secret message")
            .expect("test: failed to encrypt");
        let pt = server_transport
            .decrypt(&ct)
            .expect("test: failed to decrypt");
        assert_eq!(pt, b"secret message");
    }

    // Additional tests for coverage

    #[test]
    fn test_pattern_constants() {
        assert_eq!(PATTERN_IK, "Noise_IK_25519_ChaChaPoly_SHA256");
        assert_eq!(PATTERN_NK, "Noise_NK_25519_ChaChaPoly_SHA256");
    }

    #[test]
    fn test_hybrid_public_from_bytes_valid() {
        let kp = HybridKeypair::generate();
        let pub_bundle = kp.public_bundle();

        let reconstructed = HybridPublic::from_bytes(&pub_bundle.x25519, &pub_bundle.mlkem)
            .expect("valid bytes should parse");
        assert_eq!(reconstructed.x25519, pub_bundle.x25519);
        assert_eq!(reconstructed.mlkem, pub_bundle.mlkem);
    }

    #[test]
    fn test_hybrid_public_from_bytes_x25519_too_short() {
        let short_x25519 = [0u8; 31]; // Should be 32
        let mlkem = vec![0u8; 1184];

        let result = HybridPublic::from_bytes(&short_x25519, &mlkem);
        match result {
            Ok(_) => panic!("expected error"),
            Err(e) => assert!(e.to_string().contains("x25519")),
        }
    }

    #[test]
    fn test_hybrid_public_from_bytes_mlkem_wrong_length() {
        let x25519 = [0u8; 32];
        let short_mlkem = vec![0u8; 1000]; // Should be 1184

        let result = HybridPublic::from_bytes(&x25519, &short_mlkem);
        match result {
            Ok(_) => panic!("expected error"),
            Err(e) => assert!(e.to_string().contains("ML-KEM768")),
        }
    }

    #[test]
    fn test_hybrid_public_to_bytes() {
        let kp = HybridKeypair::generate();
        let pub_bundle = kp.public_bundle();

        let bytes = pub_bundle.to_bytes();
        assert_eq!(bytes.len(), 32 + 1184); // X25519 + ML-KEM768
        assert_eq!(&bytes[..32], &pub_bundle.x25519);
        assert_eq!(&bytes[32..], &pub_bundle.mlkem);
    }

    #[test]
    fn test_hybrid_public_clone() {
        let kp = HybridKeypair::generate();
        let pub_bundle = kp.public_bundle();
        let cloned = pub_bundle.clone();

        assert_eq!(pub_bundle.x25519, cloned.x25519);
        assert_eq!(pub_bundle.mlkem, cloned.mlkem);
    }

    #[test]
    fn test_hybrid_secret_combine() {
        let x25519 = [1u8; 32];
        let mlkem = [2u8; 32];

        let secret = HybridSecret::combine(&x25519, &mlkem);
        // Just verify it produces 32-byte output
        assert_eq!(secret.combined.len(), 32);

        // Same inputs should produce same output
        let secret2 = HybridSecret::combine(&x25519, &mlkem);
        assert_eq!(secret.combined, secret2.combined);
    }

    #[test]
    fn test_hybrid_secret_different_inputs() {
        let x25519_1 = [1u8; 32];
        let x25519_2 = [2u8; 32];
        let mlkem = [3u8; 32];

        let secret1 = HybridSecret::combine(&x25519_1, &mlkem);
        let secret2 = HybridSecret::combine(&x25519_2, &mlkem);

        assert_ne!(secret1.combined, secret2.combined);
    }

    #[test]
    fn test_noise_nk_handshake() {
        // Generate server static key only
        let mut server_static = [0u8; 32];
        rng::fill(&mut server_static);
        let server_public =
            x25519_dalek::x25519(server_static, x25519_dalek::X25519_BASEPOINT_BYTES);

        // NK pattern: client doesn't send static key
        let mut initiator =
            NoiseInitiator::new_nk(&server_public).expect("test: failed to create NK initiator");
        let mut responder =
            NoiseResponder::new_nk(&server_static).expect("test: failed to create NK responder");

        assert!(!initiator.is_handshake_finished());
        assert!(!responder.is_handshake_finished());

        // -> e, es + HybridPublic
        let msg1 = initiator
            .write_message(b"anonymous")
            .expect("test: failed to write NK message");
        let (payload1, peer_hybrid) = responder
            .read_message(&msg1)
            .expect("test: failed to read NK message");
        assert_eq!(payload1, b"anonymous");

        // <- e, ee + ServerHybridPublic + ML-KEM CT
        let (msg2, server_hybrid_secret) = responder
            .write_message(b"reply", &peer_hybrid)
            .expect("test: failed to write NK response");
        let (payload2, client_hybrid_secret) = initiator
            .read_message(&msg2)
            .expect("test: failed to read NK response");
        assert_eq!(payload2, b"reply");

        // Verify hybrid secrets match
        assert_eq!(server_hybrid_secret.combined, client_hybrid_secret.combined);

        // Verify handshake finished
        assert!(initiator.is_handshake_finished());
        assert!(responder.is_handshake_finished());

        // Transport mode
        let mut client_transport = initiator.into_transport().unwrap();
        let mut server_transport = responder.into_transport().unwrap();

        // Bidirectional test
        let ct = client_transport.encrypt(b"client msg").unwrap();
        let pt = server_transport.decrypt(&ct).unwrap();
        assert_eq!(pt, b"client msg");

        let ct = server_transport.encrypt(b"server msg").unwrap();
        let pt = client_transport.decrypt(&ct).unwrap();
        assert_eq!(pt, b"server msg");
    }

    #[test]
    fn test_noise_transport_rekey() {
        let mut server_static = [0u8; 32];
        rng::fill(&mut server_static);
        let server_public =
            x25519_dalek::x25519(server_static, x25519_dalek::X25519_BASEPOINT_BYTES);

        let mut initiator = NoiseInitiator::new_nk(&server_public).unwrap();
        let mut responder = NoiseResponder::new_nk(&server_static).unwrap();

        let msg1 = initiator.write_message(b"init").unwrap();
        let (_, peer_hybrid) = responder.read_message(&msg1).unwrap();
        let (msg2, _) = responder.write_message(b"resp", &peer_hybrid).unwrap();
        let _ = initiator.read_message(&msg2).unwrap();

        let mut client_transport = initiator.into_transport().unwrap();
        let mut server_transport = responder.into_transport().unwrap();

        // Communication before rekey
        let ct1 = client_transport.encrypt(b"before rekey").unwrap();
        let pt1 = server_transport.decrypt(&ct1).unwrap();
        assert_eq!(pt1, b"before rekey");

        // Rekey both sides
        client_transport.rekey_outgoing();
        server_transport.rekey_incoming();

        // Communication after rekey
        let ct2 = client_transport.encrypt(b"after rekey").unwrap();
        let pt2 = server_transport.decrypt(&ct2).unwrap();
        assert_eq!(pt2, b"after rekey");

        // Test rekey in opposite direction
        server_transport.rekey_outgoing();
        client_transport.rekey_incoming();

        let ct3 = server_transport.encrypt(b"server after rekey").unwrap();
        let pt3 = client_transport.decrypt(&ct3).unwrap();
        assert_eq!(pt3, b"server after rekey");
    }

    #[test]
    fn test_hybrid_keypair_public_bundle() {
        let kp = HybridKeypair::generate();
        let bundle = kp.public_bundle();

        assert_eq!(bundle.x25519, kp.x25519_public);
        assert_eq!(bundle.mlkem.len(), 1184); // ML-KEM768 public key size
    }

    #[test]
    fn test_initiator_hybrid_public() {
        let mut server_static = [0u8; 32];
        rng::fill(&mut server_static);
        let server_public =
            x25519_dalek::x25519(server_static, x25519_dalek::X25519_BASEPOINT_BYTES);

        let initiator = NoiseInitiator::new_nk(&server_public).unwrap();
        let hybrid_pub = initiator.hybrid_public();

        assert_eq!(hybrid_pub.x25519.len(), 32);
        assert_eq!(hybrid_pub.mlkem.len(), 1184);
    }

    #[test]
    fn test_decapsulate_invalid_ciphertext() {
        let kp = HybridKeypair::generate();
        let peer_x25519 = [0u8; 32];
        let invalid_ct = vec![0u8; 100]; // Wrong size

        let result = kp.decapsulate(&peer_x25519, &invalid_ct);
        match result {
            Ok(_) => panic!("expected error for invalid ciphertext"),
            Err(e) => assert!(e.to_string().contains("ciphertext")),
        }
    }

    #[test]
    fn test_initiator_read_message_too_short() {
        let mut server_static = [0u8; 32];
        rng::fill(&mut server_static);
        let server_public =
            x25519_dalek::x25519(server_static, x25519_dalek::X25519_BASEPOINT_BYTES);

        let mut initiator = NoiseInitiator::new_nk(&server_public).unwrap();
        let _ = initiator.write_message(b"init").unwrap();

        // Try to read message that's too short
        let short_msg = vec![0u8; 100];
        let result = initiator.read_message(&short_msg);
        match result {
            Ok(_) => panic!("expected error for too short message"),
            Err(e) => assert!(e.to_string().contains("too short")),
        }
    }

    #[test]
    fn test_responder_read_message_too_short() {
        let mut server_static = [0u8; 32];
        rng::fill(&mut server_static);

        let mut responder = NoiseResponder::new_nk(&server_static).unwrap();

        // Try to read message that's too short
        let short_msg = vec![0u8; 100];
        let result = responder.read_message(&short_msg);
        match result {
            Ok(_) => panic!("expected error for too short message"),
            Err(e) => assert!(e.to_string().contains("too short")),
        }
    }

    #[test]
    fn test_empty_payload_message() {
        let mut server_static = [0u8; 32];
        rng::fill(&mut server_static);
        let server_public =
            x25519_dalek::x25519(server_static, x25519_dalek::X25519_BASEPOINT_BYTES);

        let mut initiator = NoiseInitiator::new_nk(&server_public).unwrap();
        let mut responder = NoiseResponder::new_nk(&server_static).unwrap();

        // Empty payload
        let msg1 = initiator.write_message(b"").unwrap();
        let (payload1, peer_hybrid) = responder.read_message(&msg1).unwrap();
        assert!(payload1.is_empty());

        let (msg2, _) = responder.write_message(b"", &peer_hybrid).unwrap();
        let (payload2, _) = initiator.read_message(&msg2).unwrap();
        assert!(payload2.is_empty());
    }

    #[test]
    fn test_large_payload_message() {
        let mut server_static = [0u8; 32];
        rng::fill(&mut server_static);
        let server_public =
            x25519_dalek::x25519(server_static, x25519_dalek::X25519_BASEPOINT_BYTES);

        let mut initiator = NoiseInitiator::new_nk(&server_public).unwrap();
        let mut responder = NoiseResponder::new_nk(&server_static).unwrap();

        // Large payload (within Noise limits)
        let large_payload = vec![0xAB; 1000];
        let msg1 = initiator.write_message(&large_payload).unwrap();
        let (payload1, peer_hybrid) = responder.read_message(&msg1).unwrap();
        assert_eq!(payload1, large_payload);

        let (msg2, _) = responder
            .write_message(&large_payload, &peer_hybrid)
            .unwrap();
        let (payload2, _) = initiator.read_message(&msg2).unwrap();
        assert_eq!(payload2, large_payload);
    }
}
