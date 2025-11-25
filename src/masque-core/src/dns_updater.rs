//! DNS Updater
//!
//! Provides automatic DNS record updates for ACME DNS-01 challenges.
//! Supports multiple DNS providers: Cloudflare, Route53, and generic API-based providers.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// DNS provider type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsProvider {
    /// Cloudflare DNS
    Cloudflare,
    /// AWS Route53
    Route53,
    /// Generic HTTP API provider
    HttpApi,
    /// Manual (no automatic updates)
    Manual,
}

impl DnsProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cloudflare" | "cf" => Some(Self::Cloudflare),
            "route53" | "aws" => Some(Self::Route53),
            "http" | "api" => Some(Self::HttpApi),
            "manual" => None,
            _ => None,
        }
    }
}

impl FromStr for DnsProvider {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DnsProvider::parse(s).ok_or(())
    }
}

/// DNS updater configuration
#[derive(Debug, Clone)]
pub struct DnsUpdaterConfig {
    /// Provider type
    pub provider: DnsProvider,
    /// Provider-specific credentials/config
    pub credentials: HashMap<String, String>,
    /// Timeout for DNS operations
    pub timeout: Duration,
    /// Propagation wait time after update
    pub propagation_delay: Duration,
}

impl Default for DnsUpdaterConfig {
    fn default() -> Self {
        Self {
            provider: DnsProvider::Manual,
            credentials: HashMap::new(),
            timeout: Duration::from_secs(30),
            propagation_delay: Duration::from_secs(10),
        }
    }
}

/// DNS Updater trait
#[async_trait::async_trait]
pub trait DnsUpdater: Send + Sync {
    /// Create or update a TXT record
    async fn set_txt_record(&self, name: &str, value: &str, ttl: u32) -> Result<()>;

    /// Delete a TXT record
    async fn delete_txt_record(&self, name: &str) -> Result<()>;

    /// Check if a TXT record exists and matches value
    async fn verify_txt_record(&self, name: &str, expected_value: &str) -> Result<bool>;
}

/// Cloudflare DNS Updater
pub struct CloudflareUpdater {
    api_token: String,
    zone_id: Option<String>,
    client: reqwest::Client,
}

impl CloudflareUpdater {
    pub fn new(api_token: String, zone_id: Option<String>) -> Result<Self> {
        Ok(Self {
            api_token,
            zone_id,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
        })
    }

    async fn get_zone_id(&self, domain: &str) -> Result<String> {
        if let Some(ref zone_id) = self.zone_id {
            return Ok(zone_id.clone());
        }

        // Extract root domain (e.g., example.com from _acme-challenge.sub.example.com)
        let root_domain = extract_root_domain(domain);

        let url = "https://api.cloudflare.com/client/v4/zones";
        let response = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let zones: serde_json::Value = response.json().await?;

        if let Some(zones_array) = zones.get("result").and_then(|r| r.as_array()) {
            for zone in zones_array {
                if let Some(zone_name) = zone.get("name").and_then(|n| n.as_str()) {
                    if root_domain.ends_with(zone_name) || zone_name == root_domain {
                        if let Some(id) = zone.get("id").and_then(|i| i.as_str()) {
                            return Ok(id.to_string());
                        }
                    }
                }
            }
        }

        anyhow::bail!("Zone not found for domain: {}", domain);
    }

    async fn find_record(&self, zone_id: &str, name: &str) -> Result<Option<String>> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=TXT&name={}",
            zone_id, name
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let records: serde_json::Value = response.json().await?;

        if let Some(records_array) = records.get("result").and_then(|r| r.as_array()) {
            if let Some(record) = records_array.first() {
                if let Some(id) = record.get("id").and_then(|i| i.as_str()) {
                    return Ok(Some(id.to_string()));
                }
            }
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl DnsUpdater for CloudflareUpdater {
    async fn set_txt_record(&self, name: &str, value: &str, ttl: u32) -> Result<()> {
        let zone_id = self.get_zone_id(name).await?;

        // Check if record exists
        if let Some(record_id) = self.find_record(&zone_id, name).await? {
            // Update existing record
            let url = format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                zone_id, record_id
            );

            let payload = json!({
                "type": "TXT",
                "name": name,
                "content": value,
                "ttl": ttl
            });

            let response = self
                .client
                .put(&url)
                .header("Authorization", format!("Bearer {}", self.api_token))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if !response.status().is_success() {
                let error_text = response.text().await?;
                anyhow::bail!("Failed to update DNS record: {}", error_text);
            }

            info!("Updated TXT record {} = {}", name, value);
        } else {
            // Create new record
            let url = format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
                zone_id
            );

            let payload = json!({
                "type": "TXT",
                "name": name,
                "content": value,
                "ttl": ttl
            });

            let response = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.api_token))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if !response.status().is_success() {
                let error_text = response.text().await?;
                anyhow::bail!("Failed to create DNS record: {}", error_text);
            }

            info!("Created TXT record {} = {}", name, value);
        }

        Ok(())
    }

    async fn delete_txt_record(&self, name: &str) -> Result<()> {
        let zone_id = self.get_zone_id(name).await?;

        if let Some(record_id) = self.find_record(&zone_id, name).await? {
            let url = format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                zone_id, record_id
            );

            let response = self
                .client
                .delete(&url)
                .header("Authorization", format!("Bearer {}", self.api_token))
                .header("Content-Type", "application/json")
                .send()
                .await?;

            if !response.status().is_success() {
                let error_text = response.text().await?;
                warn!("Failed to delete DNS record: {}", error_text);
            } else {
                info!("Deleted TXT record: {}", name);
            }
        }

        Ok(())
    }

    async fn verify_txt_record(&self, name: &str, expected_value: &str) -> Result<bool> {
        // Wait for DNS propagation
        sleep(Duration::from_secs(5)).await;

        // Use DNS resolver to verify TXT record
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        // Lookup TXT record
        let response = resolver
            .txt_lookup(name)
            .await
            .context("DNS lookup failed")?;

        // Check if any TXT record matches expected value
        for record in response.iter() {
            for txt in record.iter() {
                let txt_str = String::from_utf8_lossy(txt);
                if txt_str.trim_matches('"') == expected_value.trim_matches('"') {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

/// AWS Route53 DNS Updater
pub struct Route53Updater {
    access_key_id: String,
    secret_access_key: String,
    region: String,
    client: reqwest::Client,
}

impl Route53Updater {
    pub fn new(access_key_id: String, secret_access_key: String, region: String) -> Result<Self> {
        Ok(Self {
            access_key_id,
            secret_access_key,
            region,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
        })
    }

    async fn get_hosted_zone_id(&self, domain: &str) -> Result<String> {
        // Extract root domain
        let root_domain = extract_root_domain(domain);

        // Route53 API endpoint
        let url = format!(
            "https://route53.{}.amazonaws.com/2013-04-01/hostedzone",
            self.region
        );

        // Create AWS Signature V4 signed request
        // Using aws-sigv4 crate for proper signing
        let now = chrono::Utc::now();
        let date_str = now.format("%Y%m%d").to_string();
        let datetime_str = now.format("%Y%m%dT%H%M%SZ").to_string();

        // AWS Signature V4 requires proper signing of the request
        // For now, we'll use a simplified approach that works with proper credentials
        // Full implementation would use aws-sigv4 crate properly

        // Create canonical request
        let host = format!("route53.{}.amazonaws.com", self.region);
        let canonical_uri = "/2013-04-01/hostedzone";
        let canonical_querystring = "";
        let canonical_headers = format!("host:{}\nx-amz-date:{}\n", host, datetime_str);
        let signed_headers = "host;x-amz-date";
        let payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // SHA256 of empty string

        let canonical_request = format!(
            "GET\n{}\n{}\n{}\n{}\n{}",
            canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash
        );

        // Create string to sign
        let algorithm = "AWS4-HMAC-SHA256";
        let credential_scope = format!("{}/{}/route53/aws4_request", date_str, self.region);
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            algorithm,
            datetime_str,
            credential_scope,
            sha2::Sha256::digest(canonical_request.as_bytes())
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        // Calculate signature using AWS Signature V4 algorithm
        type HmacSha256 = Hmac<Sha256>;

        let k_date = {
            let mut mac =
                HmacSha256::new_from_slice(format!("AWS4{}", self.secret_access_key).as_bytes())
                    .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(date_str.as_bytes());
            mac.finalize().into_bytes()
        };

        let k_region = {
            let mut mac = HmacSha256::new_from_slice(&k_date)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(self.region.as_bytes());
            mac.finalize().into_bytes()
        };

        let k_service = {
            let mut mac = HmacSha256::new_from_slice(&k_region)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(b"route53");
            mac.finalize().into_bytes()
        };

        let k_signing = {
            let mut mac = HmacSha256::new_from_slice(&k_service)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(b"aws4_request");
            mac.finalize().into_bytes()
        };

        let signature = {
            let mut mac = HmacSha256::new_from_slice(&k_signing)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(string_to_sign.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        };

        // Create authorization header
        let authorization = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm, self.access_key_id, credential_scope, signed_headers, signature
        );

        // Make signed request
        let response = self
            .client
            .get(&url)
            .header("Host", &host)
            .header("X-Amz-Date", &datetime_str)
            .header("Authorization", &authorization)
            .send()
            .await?;

        // Parse XML response to find hosted zone
        let body = response.text().await?;

        // Extract zone ID from XML
        if let Some(zone_start) = body.find(&format!("<Name>{}</Name>", root_domain)) {
            if let Some(id_start) = body[..zone_start].rfind("<Id>/hostedzone/") {
                let id_end = body[id_start + 15..].find('<').unwrap_or(20);
                return Ok(body[id_start + 15..id_start + 15 + id_end].to_string());
            }
        }

        anyhow::bail!("Hosted zone not found for domain: {}", domain);
    }

    async fn find_record(&self, zone_id: &str, name: &str) -> Result<Option<String>> {
        let url = format!(
            "https://route53.{}.amazonaws.com/2013-04-01/hostedzone/{}/rrset?name={}&type=TXT",
            self.region, zone_id, name
        );

        // Sign request with AWS Signature V4 (same as get_hosted_zone_id)
        let now = chrono::Utc::now();
        let date_str = now.format("%Y%m%d").to_string();
        let datetime_str = now.format("%Y%m%dT%H%M%SZ").to_string();
        let host = format!("route53.{}.amazonaws.com", self.region);
        let canonical_uri = format!("/2013-04-01/hostedzone/{}/rrset", zone_id);
        let canonical_querystring = format!("name={}&type=TXT", name);
        let canonical_headers = format!("host:{}\nx-amz-date:{}\n", host, datetime_str);
        let signed_headers = "host;x-amz-date";
        let payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let canonical_request = format!(
            "GET\n{}\n{}\n{}\n{}\n{}",
            canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash
        );

        let algorithm = "AWS4-HMAC-SHA256";
        let credential_scope = format!("{}/{}/route53/aws4_request", date_str, self.region);
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            algorithm,
            datetime_str,
            credential_scope,
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        type HmacSha256 = Hmac<Sha256>;
        let k_date = {
            let mut mac =
                HmacSha256::new_from_slice(format!("AWS4{}", self.secret_access_key).as_bytes())
                    .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(date_str.as_bytes());
            mac.finalize().into_bytes()
        };
        let k_region = {
            let mut mac = HmacSha256::new_from_slice(&k_date)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(self.region.as_bytes());
            mac.finalize().into_bytes()
        };
        let k_service = {
            let mut mac = HmacSha256::new_from_slice(&k_region)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(b"route53");
            mac.finalize().into_bytes()
        };
        let k_signing = {
            let mut mac = HmacSha256::new_from_slice(&k_service)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(b"aws4_request");
            mac.finalize().into_bytes()
        };
        let signature = {
            let mut mac = HmacSha256::new_from_slice(&k_signing)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(string_to_sign.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        };
        let authorization = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm, self.access_key_id, credential_scope, signed_headers, signature
        );

        let response = self
            .client
            .get(&url)
            .header("Host", &host)
            .header("X-Amz-Date", &datetime_str)
            .header("Authorization", &authorization)
            .send()
            .await?;

        let body = response.text().await?;

        // Parse XML to find record and extract value
        if let Some(record_start) = body.find(&format!("<Name>{}</Name>", name)) {
            // Look for Value tag after Name
            if let Some(value_start) = body[record_start..].find("<Value>") {
                let value_end = body[record_start + value_start + 7..]
                    .find("</Value>")
                    .ok_or_else(|| anyhow::anyhow!("malformed XML response"))?;
                let value = body
                    [record_start + value_start + 7..record_start + value_start + 7 + value_end]
                    .trim_matches('"');
                return Ok(Some(value.to_string()));
            }
            return Ok(Some(name.to_string())); // Record exists but no value extracted
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl DnsUpdater for Route53Updater {
    async fn set_txt_record(&self, name: &str, value: &str, ttl: u32) -> Result<()> {
        let zone_id = self.get_hosted_zone_id(name).await?;

        // Check if record exists
        let record_exists = self.find_record(&zone_id, name).await?.is_some();

        // Route53 API requires XML format
        let change_batch = if record_exists {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
    <ChangeBatch>
        <Changes>
            <Change>
                <Action>UPSERT</Action>
                <ResourceRecordSet>
                    <Name>{}</Name>
                    <Type>TXT</Type>
                    <TTL>{}</TTL>
                    <ResourceRecords>
                        <ResourceRecord>
                            <Value>"{}"</Value>
                        </ResourceRecord>
                    </ResourceRecords>
                </ResourceRecordSet>
            </Change>
        </Changes>
    </ChangeBatch>
</ChangeResourceRecordSetsRequest>"#,
                name, ttl, value
            )
        } else {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
    <ChangeBatch>
        <Changes>
            <Change>
                <Action>CREATE</Action>
                <ResourceRecordSet>
                    <Name>{}</Name>
                    <Type>TXT</Type>
                    <TTL>{}</TTL>
                    <ResourceRecords>
                        <ResourceRecord>
                            <Value>"{}"</Value>
                        </ResourceRecord>
                    </ResourceRecords>
                </ResourceRecordSet>
            </Change>
        </Changes>
    </ChangeBatch>
</ChangeResourceRecordSetsRequest>"#,
                name, ttl, value
            )
        };

        let url = format!(
            "https://route53.{}.amazonaws.com/2013-04-01/hostedzone/{}/rrset",
            self.region, zone_id
        );

        // Sign request with AWS Signature V4
        let now = chrono::Utc::now();
        let date_str = now.format("%Y%m%d").to_string();
        let datetime_str = now.format("%Y%m%dT%H%M%SZ").to_string();
        let host = format!("route53.{}.amazonaws.com", self.region);
        let canonical_uri = format!("/2013-04-01/hostedzone/{}/rrset", zone_id);
        let canonical_querystring = "";
        let canonical_headers = format!(
            "content-type:application/xml\nhost:{}\nx-amz-date:{}\n",
            host, datetime_str
        );
        let signed_headers = "content-type;host;x-amz-date";
        let payload_hash = hex::encode(Sha256::digest(change_batch.as_bytes()));

        let canonical_request = format!(
            "POST\n{}\n{}\n{}\n{}\n{}",
            canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash
        );

        let algorithm = "AWS4-HMAC-SHA256";
        let credential_scope = format!("{}/{}/route53/aws4_request", date_str, self.region);
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            algorithm,
            datetime_str,
            credential_scope,
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        type HmacSha256 = Hmac<Sha256>;
        let k_date = {
            let mut mac =
                HmacSha256::new_from_slice(format!("AWS4{}", self.secret_access_key).as_bytes())
                    .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(date_str.as_bytes());
            mac.finalize().into_bytes()
        };
        let k_region = {
            let mut mac = HmacSha256::new_from_slice(&k_date)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(self.region.as_bytes());
            mac.finalize().into_bytes()
        };
        let k_service = {
            let mut mac = HmacSha256::new_from_slice(&k_region)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(b"route53");
            mac.finalize().into_bytes()
        };
        let k_signing = {
            let mut mac = HmacSha256::new_from_slice(&k_service)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(b"aws4_request");
            mac.finalize().into_bytes()
        };
        let signature = {
            let mut mac = HmacSha256::new_from_slice(&k_signing)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(string_to_sign.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        };
        let authorization = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm, self.access_key_id, credential_scope, signed_headers, signature
        );

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/xml")
            .header("Host", &host)
            .header("X-Amz-Date", &datetime_str)
            .header("Authorization", &authorization)
            .body(change_batch)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("Failed to update Route53 DNS record: {}", error_text);
        }

        info!("Updated Route53 TXT record {} = {}", name, value);
        Ok(())
    }

    async fn delete_txt_record(&self, name: &str) -> Result<()> {
        let zone_id = self.get_hosted_zone_id(name).await?;

        // Fetch current record to get its value (required for DELETE)
        let current_value = if let Some(value) = self.find_record(&zone_id, name).await? {
            value
        } else {
            // Record doesn't exist, nothing to delete
            return Ok(());
        };

        // Route53 DELETE requires current record value
        let change_batch = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
    <ChangeBatch>
        <Changes>
            <Change>
                <Action>DELETE</Action>
                <ResourceRecordSet>
                    <Name>{}</Name>
                    <Type>TXT</Type>
                    <TTL>60</TTL>
                    <ResourceRecords>
                        <ResourceRecord>
                            <Value>"{}"</Value>
                        </ResourceRecord>
                    </ResourceRecords>
                </ResourceRecordSet>
            </Change>
        </Changes>
    </ChangeBatch>
</ChangeResourceRecordSetsRequest>"#,
            name, current_value
        );

        let url = format!(
            "https://route53.{}.amazonaws.com/2013-04-01/hostedzone/{}/rrset",
            self.region, zone_id
        );

        // Sign request with AWS Signature V4
        let now = chrono::Utc::now();
        let date_str = now.format("%Y%m%d").to_string();
        let datetime_str = now.format("%Y%m%dT%H%M%SZ").to_string();
        let host = format!("route53.{}.amazonaws.com", self.region);
        let canonical_uri = format!("/2013-04-01/hostedzone/{}/rrset", zone_id);
        let canonical_querystring = "";
        let canonical_headers = format!(
            "content-type:application/xml\nhost:{}\nx-amz-date:{}\n",
            host, datetime_str
        );
        let signed_headers = "content-type;host;x-amz-date";
        let payload_hash = hex::encode(Sha256::digest(change_batch.as_bytes()));

        let canonical_request = format!(
            "POST\n{}\n{}\n{}\n{}\n{}",
            canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash
        );

        let algorithm = "AWS4-HMAC-SHA256";
        let credential_scope = format!("{}/{}/route53/aws4_request", date_str, self.region);
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            algorithm,
            datetime_str,
            credential_scope,
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        type HmacSha256 = Hmac<Sha256>;
        let k_date = {
            let mut mac =
                HmacSha256::new_from_slice(format!("AWS4{}", self.secret_access_key).as_bytes())
                    .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(date_str.as_bytes());
            mac.finalize().into_bytes()
        };
        let k_region = {
            let mut mac = HmacSha256::new_from_slice(&k_date)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(self.region.as_bytes());
            mac.finalize().into_bytes()
        };
        let k_service = {
            let mut mac = HmacSha256::new_from_slice(&k_region)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(b"route53");
            mac.finalize().into_bytes()
        };
        let k_signing = {
            let mut mac = HmacSha256::new_from_slice(&k_service)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(b"aws4_request");
            mac.finalize().into_bytes()
        };
        let signature = {
            let mut mac = HmacSha256::new_from_slice(&k_signing)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(string_to_sign.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        };
        let authorization = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm, self.access_key_id, credential_scope, signed_headers, signature
        );

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/xml")
            .header("Host", &host)
            .header("X-Amz-Date", &datetime_str)
            .header("Authorization", &authorization)
            .body(change_batch)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            warn!("Failed to delete Route53 DNS record: {}", error_text);
        } else {
            info!("Deleted Route53 TXT record: {}", name);
        }

        Ok(())
    }

    async fn verify_txt_record(&self, name: &str, expected_value: &str) -> Result<bool> {
        // Use DNS resolver to verify TXT record
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        // Lookup TXT record
        let response = resolver
            .txt_lookup(name)
            .await
            .context("DNS lookup failed")?;

        // Check if any TXT record matches expected value
        for record in response.iter() {
            for txt in record.iter() {
                let txt_str = String::from_utf8_lossy(txt);
                if txt_str.trim_matches('"') == expected_value.trim_matches('"') {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

/// HTTP API DNS Updater (generic)
pub struct HttpApiUpdater {
    api_url: String,
    #[allow(dead_code)] // Будет использоваться для расширенной авторизации
    api_key: Option<String>,
    headers: HashMap<String, String>,
    client: reqwest::Client,
}

impl HttpApiUpdater {
    pub fn new(
        api_url: String,
        api_key: Option<String>,
        headers: HashMap<String, String>,
    ) -> Result<Self> {
        let mut client_builder = reqwest::Client::builder().timeout(Duration::from_secs(30));

        if let Some(ref key) = api_key {
            client_builder = client_builder.default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", key).parse().unwrap(),
                );
                h
            });
        }

        Ok(Self {
            api_url,
            api_key,
            headers,
            client: client_builder.build()?,
        })
    }
}

#[async_trait::async_trait]
impl DnsUpdater for HttpApiUpdater {
    async fn set_txt_record(&self, name: &str, value: &str, _ttl: u32) -> Result<()> {
        let payload = json!({
            "name": name,
            "type": "TXT",
            "value": value
        });

        let mut request = self
            .client
            .post(&self.api_url)
            .header("Content-Type", "application/json");

        for (key, val) in &self.headers {
            request = request.header(key.as_str(), val.as_str());
        }

        let response = request.json(&payload).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("Failed to set DNS record via HTTP API: {}", error_text);
        }

        info!("Set TXT record via HTTP API: {} = {}", name, value);
        Ok(())
    }

    async fn delete_txt_record(&self, name: &str) -> Result<()> {
        let url = format!("{}/{}", self.api_url.trim_end_matches('/'), name);

        let mut request = self.client.delete(&url);

        for (key, val) in &self.headers {
            request = request.header(key.as_str(), val.as_str());
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            warn!("Failed to delete DNS record via HTTP API: {}", name);
        } else {
            info!("Deleted TXT record via HTTP API: {}", name);
        }

        Ok(())
    }

    async fn verify_txt_record(&self, name: &str, expected_value: &str) -> Result<bool> {
        // Wait for DNS propagation
        sleep(Duration::from_secs(5)).await;

        // Use DNS resolver to verify TXT record
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        // Lookup TXT record
        let response = resolver
            .txt_lookup(name)
            .await
            .context("DNS lookup failed")?;

        // Check if any TXT record matches expected value
        for record in response.iter() {
            for txt in record.iter() {
                let txt_str = String::from_utf8_lossy(txt);
                if txt_str.trim_matches('"') == expected_value.trim_matches('"') {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

/// DNS Updater factory
pub struct DnsUpdaterFactory;

impl DnsUpdaterFactory {
    pub fn create(config: &DnsUpdaterConfig) -> Result<Box<dyn DnsUpdater>> {
        match config.provider {
            DnsProvider::Cloudflare => {
                let api_token = config
                    .credentials
                    .get("api_token")
                    .ok_or_else(|| anyhow::anyhow!("Cloudflare API token required"))?;
                let zone_id = config.credentials.get("zone_id").cloned();
                Ok(Box::new(CloudflareUpdater::new(
                    api_token.clone(),
                    zone_id,
                )?))
            }
            DnsProvider::HttpApi => {
                let api_url = config
                    .credentials
                    .get("api_url")
                    .ok_or_else(|| anyhow::anyhow!("HTTP API URL required"))?;
                let api_key = config.credentials.get("api_key").cloned();
                let headers = config.credentials.clone();
                Ok(Box::new(HttpApiUpdater::new(
                    api_url.clone(),
                    api_key,
                    headers,
                )?))
            }
            DnsProvider::Route53 => {
                let access_key_id = config
                    .credentials
                    .get("access_key_id")
                    .ok_or_else(|| anyhow::anyhow!("Route53 access_key_id required"))?;
                let secret_access_key = config
                    .credentials
                    .get("secret_access_key")
                    .ok_or_else(|| anyhow::anyhow!("Route53 secret_access_key required"))?;
                let region = config
                    .credentials
                    .get("region")
                    .cloned()
                    .unwrap_or_else(|| "us-east-1".to_string());
                Ok(Box::new(Route53Updater::new(
                    access_key_id.clone(),
                    secret_access_key.clone(),
                    region,
                )?))
            }
            DnsProvider::Manual => {
                anyhow::bail!("Manual DNS provider does not support automatic updates");
            }
        }
    }
}

/// Extract root domain from subdomain
fn extract_root_domain(domain: &str) -> String {
    // Remove _acme-challenge. prefix if present
    let domain = domain.strip_prefix("_acme-challenge.").unwrap_or(domain);

    // Simple extraction - in production, use proper domain parsing
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        domain.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_root_domain() {
        assert_eq!(
            extract_root_domain("_acme-challenge.example.com"),
            "example.com"
        );
        assert_eq!(
            extract_root_domain("_acme-challenge.sub.example.com"),
            "example.com"
        );
        assert_eq!(extract_root_domain("example.com"), "example.com");
    }

    #[test]
    fn test_dns_provider_from_str() {
        assert_eq!(
            DnsProvider::parse("cloudflare"),
            Some(DnsProvider::Cloudflare)
        );
        assert_eq!(DnsProvider::parse("cf"), Some(DnsProvider::Cloudflare));
        assert_eq!(DnsProvider::parse("route53"), Some(DnsProvider::Route53));
        assert_eq!(DnsProvider::parse("http"), Some(DnsProvider::HttpApi));
        assert_eq!(DnsProvider::parse("manual"), None);

        // FromStr impl returns Result
        assert!(matches!(
            DnsProvider::from_str("cf"),
            Ok(DnsProvider::Cloudflare)
        ));
    }
}
