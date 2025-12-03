use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use vpr_crypto::keys::SigningKeypair;
use vpr_crypto::manifest::{ManifestPayload, SignedManifest};

#[derive(Parser, Debug)]
#[command(name = "manifest-tool", about = "Sign and verify bootstrap manifests")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Sign manifest.json with signing key (Ed25519)
    Sign {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        key_dir: PathBuf,
        #[arg(long, default_value = "manifest")]
        key_name: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify signed_manifest.json against expected pubkey
    Verify {
        #[arg(long)]
        signed: PathBuf,
        #[arg(long)]
        pubkey: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Sign {
            manifest,
            key_dir,
            key_name,
            out,
        } => sign_manifest(&manifest, &key_dir, &key_name, &out),
        Command::Verify { signed, pubkey } => verify_manifest(&signed, &pubkey),
    }
}

fn sign_manifest(
    manifest: &std::path::Path,
    key_dir: &std::path::Path,
    key_name: &str,
    out: &std::path::Path,
) -> Result<()> {
    let payload_bytes = fs::read(manifest).context("reading manifest")?;
    let payload: ManifestPayload =
        serde_json::from_slice(&payload_bytes).context("parsing manifest payload")?;

    let kp = SigningKeypair::load(key_dir, key_name).context("loading signing key")?;
    let signed = SignedManifest::sign(&payload, &kp).context("signing manifest")?;
    let json = signed.to_json()?;
    fs::write(out, json)?;
    println!("signed manifest -> {}", out.display());
    Ok(())
}

fn verify_manifest(signed: &std::path::Path, pubkey: &std::path::Path) -> Result<()> {
    let signed_bytes = fs::read(signed).context("reading signed manifest")?;
    let signed: SignedManifest =
        serde_json::from_slice(&signed_bytes).context("parsing signed manifest")?;

    let pk_bytes = fs::read(pubkey).context("reading pubkey")?;
    if pk_bytes.len() != 32 {
        return Err(anyhow!("pubkey must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pk_bytes);

    let payload = signed.verify(&arr)?;
    println!(
        "verified manifest version={} created_at={} servers={}",
        payload.version,
        payload.created_at,
        payload.servers.len()
    );
    Ok(())
}
