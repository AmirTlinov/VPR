use anyhow::{bail, Context, Result};
use snow::Keypair;
use std::{fs, path::Path};

pub fn load_keypair(priv_path: &Path) -> Result<Keypair> {
    let sk = fs::read(priv_path).with_context(|| format!("reading noise key {priv_path:?}"))?;
    if sk.len() != 32 {
        bail!("noise key must be 32 bytes");
    }
    let pk = x25519_public(&sk)?;
    Ok(Keypair {
        private: sk,
        public: pk,
    })
}

pub fn load_public(pub_path: &Path) -> Result<Vec<u8>> {
    let pk = fs::read(pub_path).with_context(|| format!("reading noise pub {pub_path:?}"))?;
    if pk.len() != 32 {
        bail!("noise pub must be 32 bytes");
    }
    Ok(pk)
}

pub fn x25519_public(sk: &[u8]) -> Result<Vec<u8>> {
    if sk.len() != 32 {
        bail!("private key must be 32 bytes");
    }
    let mut pk = [0u8; 32];
    let out = x25519_dalek::x25519(sk.try_into().unwrap(), x25519_dalek::X25519_BASEPOINT_BYTES);
    pk.copy_from_slice(&out);
    Ok(pk.to_vec())
}
