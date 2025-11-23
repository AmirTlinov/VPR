use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vpr_crypto::{keys, pki, seal};

#[derive(Parser)]
#[command(name = "vpr-keygen")]
#[command(about = "VPR key and certificate management")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize PKI: generate root CA (offline)
    InitRoot {
        /// Output directory for root CA
        #[arg(short, long, default_value = "secrets/pki/root")]
        output: PathBuf,
        /// Organization name
        #[arg(long, default_value = "VPR")]
        org: String,
        /// Validity in days
        #[arg(long, default_value = "3650")]
        validity_days: i64,
    },

    /// Generate intermediate CA for a node (signed by root)
    InitIntermediate {
        /// Root CA directory
        #[arg(short, long, default_value = "secrets/pki/root")]
        root: PathBuf,
        /// Output directory
        #[arg(short, long)]
        output: PathBuf,
        /// Node name
        #[arg(short, long)]
        name: String,
        /// Validity in days
        #[arg(long, default_value = "365")]
        validity_days: i64,
    },

    /// Generate service certificate (signed by intermediate)
    GenServiceCert {
        /// Intermediate CA directory
        #[arg(short, long)]
        intermediate: PathBuf,
        /// Output directory
        #[arg(short, long)]
        output: PathBuf,
        /// Service name (masque, doh, etc.)
        #[arg(short, long)]
        service: String,
        /// DNS names (comma-separated)
        #[arg(short, long)]
        dns: String,
        /// Validity in days
        #[arg(long, default_value = "90")]
        validity_days: i64,
    },

    /// Generate Noise static keypair
    GenNoiseKey {
        /// Output directory
        #[arg(short, long)]
        output: PathBuf,
        /// Key name
        #[arg(short, long)]
        name: String,
    },

    /// Generate signing keypair (Ed25519)
    GenSigningKey {
        /// Output directory
        #[arg(short, long)]
        output: PathBuf,
        /// Key name
        #[arg(short, long)]
        name: String,
    },

    /// Generate age identity for secrets encryption
    GenAgeIdentity {
        /// Output directory
        #[arg(short, long)]
        output: PathBuf,
        /// Identity name
        #[arg(short, long)]
        name: String,
    },

    /// Encrypt file with age
    Seal {
        /// Input file
        #[arg(short, long)]
        input: PathBuf,
        /// Output file
        #[arg(short, long)]
        output: PathBuf,
        /// Age public key file
        #[arg(short, long)]
        recipient: PathBuf,
    },

    /// Decrypt file with age
    Unseal {
        /// Input file (encrypted)
        #[arg(short, long)]
        input: PathBuf,
        /// Output file
        #[arg(short, long)]
        output: PathBuf,
        /// Age secret key file
        #[arg(short, long)]
        identity: PathBuf,
    },

    /// Show certificate fingerprint
    Fingerprint {
        /// Certificate file (PEM)
        #[arg(short, long)]
        cert: PathBuf,
    },

    /// Bootstrap complete PKI hierarchy for a new node
    Bootstrap {
        /// Secrets directory
        #[arg(short, long, default_value = "secrets")]
        secrets_dir: PathBuf,
        /// Node name
        #[arg(short, long)]
        node: String,
        /// Primary domain
        #[arg(short, long)]
        domain: String,
        /// Organization name
        #[arg(long, default_value = "VPR")]
        org: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::InitRoot {
            output,
            org,
            validity_days,
        } => {
            println!("Generating root CA...");
            let config = pki::PkiConfig {
                org_name: org,
                root_cn: "VPR Root CA".to_string(),
                root_validity_days: validity_days,
                ..Default::default()
            };
            let bundle = pki::generate_root_ca(&config)?;
            pki::save_ca_bundle(&bundle, &output, "root")?;
            let fp = pki::cert_fingerprint(&bundle.cert_pem)?;
            println!("Root CA generated at: {}", output.display());
            println!("Fingerprint: {fp}");
            println!("\n⚠️  Keep root.key OFFLINE and secure!");
        }

        Commands::InitIntermediate {
            root,
            output,
            name,
            validity_days,
        } => {
            println!("Loading root CA...");
            let (root_cert_pem, root_key_pem) = pki::load_ca_bundle(&root, "root")?;
            let (root_cert, root_key) = pki::parse_ca_for_signing(&root_cert_pem, &root_key_pem)?;

            println!("Generating intermediate CA for node '{name}'...");
            let config = pki::PkiConfig {
                intermediate_validity_days: validity_days,
                ..Default::default()
            };
            let bundle = pki::generate_intermediate_ca(&config, &name, &root_cert, &root_key)?;
            pki::save_ca_bundle(&bundle, &output, "intermediate")?;
            let fp = pki::cert_fingerprint(&bundle.cert_pem)?;
            println!("Intermediate CA generated at: {}", output.display());
            println!("Fingerprint: {fp}");
        }

        Commands::GenServiceCert {
            intermediate,
            output,
            service,
            dns,
            validity_days,
        } => {
            println!("Loading intermediate CA...");
            let (int_cert_pem, int_key_pem) = pki::load_ca_bundle(&intermediate, "intermediate")?;
            let (int_cert, int_key) = pki::parse_ca_for_signing(&int_cert_pem, &int_key_pem)?;

            let dns_names: Vec<String> = dns.split(',').map(|s| s.trim().to_string()).collect();
            println!("Generating service certificate for '{service}'...");
            println!("DNS names: {:?}", dns_names);

            let config = pki::PkiConfig {
                service_validity_days: validity_days,
                ..Default::default()
            };
            let cert =
                pki::generate_service_cert(&config, &service, &dns_names, &int_cert, &int_key)?;
            pki::save_service_cert(&cert, &output, &service)?;
            let fp = pki::cert_fingerprint(&cert.cert_pem)?;
            println!("Service certificate generated at: {}", output.display());
            println!("Fingerprint: {fp}");
        }

        Commands::GenNoiseKey { output, name } => {
            println!("Generating Noise keypair '{name}'...");
            let kp = keys::NoiseKeypair::generate();
            kp.save(&output, &name)?;
            let meta = keys::KeyMetadata::new(&name, keys::KeyRole::Noise, &kp.public_bytes());
            meta.save(&output)?;
            println!("Noise keypair saved to: {}", output.display());
            println!("Fingerprint: {}", meta.fingerprint);
        }

        Commands::GenSigningKey { output, name } => {
            println!("Generating signing keypair '{name}'...");
            let kp = keys::SigningKeypair::generate();
            kp.save(&output, &name)?;
            let meta = keys::KeyMetadata::new(&name, keys::KeyRole::Signing, &kp.public_bytes());
            meta.save(&output)?;
            println!("Signing keypair saved to: {}", output.display());
            println!("Fingerprint: {}", meta.fingerprint);
        }

        Commands::GenAgeIdentity { output, name } => {
            println!("Generating age identity '{name}'...");
            std::fs::create_dir_all(&output)?;
            let id = seal::SealIdentity::generate();
            let recipient = id.recipient();
            id.save(&output.join(format!("{name}.age.key")))?;
            recipient.save(&output.join(format!("{name}.age.pub")))?;
            println!("Age identity saved to: {}", output.display());
            println!("Public key: {}", recipient.to_string());
        }

        Commands::Seal {
            input,
            output,
            recipient,
        } => {
            let r = seal::SealRecipient::load(&recipient)?;
            seal::seal_file(&input, &output, &r)?;
            println!("Encrypted: {} -> {}", input.display(), output.display());
        }

        Commands::Unseal {
            input,
            output,
            identity,
        } => {
            let id = seal::SealIdentity::load(&identity)?;
            seal::unseal_file(&input, &output, &id)?;
            println!("Decrypted: {} -> {}", input.display(), output.display());
        }

        Commands::Fingerprint { cert } => {
            let pem = std::fs::read_to_string(&cert)?;
            let fp = pki::cert_fingerprint(&pem)?;
            println!("{fp}");
        }

        Commands::Bootstrap {
            secrets_dir,
            node,
            domain,
            org,
        } => {
            println!("Bootstrapping complete PKI for node '{node}'...\n");

            let pki_dir = secrets_dir.join("pki");
            let root_dir = pki_dir.join("root");
            let node_dir = pki_dir.join(&node);

            // 1. Generate root CA if not exists
            if !root_dir.join("root.crt").exists() {
                println!("1. Generating root CA...");
                let config = pki::PkiConfig {
                    org_name: org.clone(),
                    root_cn: "VPR Root CA".to_string(),
                    ..Default::default()
                };
                let bundle = pki::generate_root_ca(&config)?;
                pki::save_ca_bundle(&bundle, &root_dir, "root")?;
                println!("   Root CA created at: {}", root_dir.display());
            } else {
                println!("1. Root CA already exists");
            }

            // 2. Generate intermediate CA
            println!("2. Generating intermediate CA for node...");
            let (root_cert_pem, root_key_pem) = pki::load_ca_bundle(&root_dir, "root")?;
            let (root_cert, root_key) = pki::parse_ca_for_signing(&root_cert_pem, &root_key_pem)?;

            let config = pki::PkiConfig {
                org_name: org,
                ..Default::default()
            };
            let int_bundle = pki::generate_intermediate_ca(&config, &node, &root_cert, &root_key)?;
            pki::save_ca_bundle(&int_bundle, &node_dir, "intermediate")?;
            println!("   Intermediate CA created");

            // 3. Generate service certificates
            println!("3. Generating service certificates...");
            let services = [
                ("masque", vec![domain.clone(), format!("*.{domain}")]),
                ("doh", vec![format!("doh.{domain}")]),
            ];

            for (service, dns_names) in services {
                let cert = pki::generate_service_cert(
                    &config,
                    service,
                    &dns_names,
                    &int_bundle.cert,
                    &int_bundle.key,
                )?;
                pki::save_service_cert(&cert, &node_dir, service)?;
                println!("   {} certificate created", service);
            }

            // 4. Generate Noise keys
            println!("4. Generating Noise keypair...");
            let noise_kp = keys::NoiseKeypair::generate();
            noise_kp.save(&node_dir, "server")?;
            let noise_meta =
                keys::KeyMetadata::new("server", keys::KeyRole::Noise, &noise_kp.public_bytes());
            noise_meta.save(&node_dir)?;
            println!("   Noise keypair created");

            // 5. Generate signing key
            println!("5. Generating signing keypair...");
            let sign_kp = keys::SigningKeypair::generate();
            sign_kp.save(&node_dir, "manifest")?;
            let sign_meta =
                keys::KeyMetadata::new("manifest", keys::KeyRole::Signing, &sign_kp.public_bytes());
            sign_meta.save(&node_dir)?;
            println!("   Signing keypair created");

            // 6. Generate age identity
            println!("6. Generating age identity...");
            let age_id = seal::SealIdentity::generate();
            let age_recipient = age_id.recipient();
            age_id.save(&node_dir.join("secrets.age.key"))?;
            age_recipient.save(&node_dir.join("secrets.age.pub"))?;
            println!("   Age identity created");

            println!("\n✓ Bootstrap complete!");
            println!("\nGenerated files in: {}", node_dir.display());
            println!("  - intermediate.crt/key (Intermediate CA)");
            println!("  - masque.crt/key/chain.crt (MASQUE service)");
            println!("  - doh.crt/key/chain.crt (DoH service)");
            println!("  - server.noise.key/pub (Noise static key)");
            println!("  - manifest.sign.key/pub (Manifest signing)");
            println!("  - secrets.age.key/pub (Secrets encryption)");
            println!(
                "\n⚠️  Move {} OFFLINE!",
                root_dir.join("root.key").display()
            );
        }
    }

    Ok(())
}
