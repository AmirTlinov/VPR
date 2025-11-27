//! Routing configuration for VPN tunnel
//!
//! Provides routing policy types and configuration structures.

use anyhow::{bail, Result};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// Routing policy for VPN tunnel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPolicy {
    /// Full tunnel - all traffic through VPN
    Full,
    /// Split tunnel - only specified networks through VPN
    Split,
    /// Bypass tunnel - specified networks bypass VPN
    Bypass,
}

/// Route rule for routing configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteRule {
    /// Target network (CIDR notation as string)
    #[serde(with = "ipnetwork_serde")]
    pub destination: IpNetwork,
    /// Gateway (optional)
    pub gateway: Option<IpAddr>,
    /// Route metric
    pub metric: u32,
    /// Routing table ID (optional)
    pub table: Option<u32>,
}

/// Routing configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoutingConfig {
    /// Routing policy
    #[serde(with = "routing_policy_serde")]
    pub policy: RoutingPolicy,
    /// List of routing rules
    pub routes: Vec<RouteRule>,
    /// DNS servers
    pub dns_servers: Vec<IpAddr>,
    /// IPv6 support enabled
    pub ipv6_enabled: bool,
}

impl RoutingConfig {
    /// Validate routing configuration
    pub fn validate(&self) -> Result<()> {
        // Validate policy and routes consistency
        match self.policy {
            RoutingPolicy::Split | RoutingPolicy::Bypass => {
                if self.routes.is_empty() {
                    bail!(
                        "Routing policy {:?} requires at least one route",
                        self.policy
                    );
                }
            }
            RoutingPolicy::Full => {
                // Full tunnel doesn't require routes, but if provided, they should be valid
            }
        }

        // Validate routes
        for (idx, route) in self.routes.iter().enumerate() {
            // Check if gateway matches network family
            if let Some(gateway) = route.gateway {
                match (route.destination, gateway) {
                    (IpNetwork::V4(_), IpAddr::V6(_)) => {
                        bail!("Route {}: IPv4 destination with IPv6 gateway", idx);
                    }
                    (IpNetwork::V6(_), IpAddr::V4(_)) => {
                        bail!("Route {}: IPv6 destination with IPv4 gateway", idx);
                    }
                    _ => {}
                }
            }
        }

        // Validate DNS servers
        for dns in &self.dns_servers {
            match dns {
                IpAddr::V4(_) | IpAddr::V6(_) => {} // Valid
            }
        }

        Ok(())
    }

    /// Check if configuration has IPv6 routes
    pub fn has_ipv6_routes(&self) -> bool {
        self.routes
            .iter()
            .any(|r| matches!(r.destination, IpNetwork::V6(_)))
    }

    /// Get IPv6 routes
    pub fn ipv6_routes(&self) -> Vec<&RouteRule> {
        self.routes
            .iter()
            .filter(|r| matches!(r.destination, IpNetwork::V6(_)))
            .collect()
    }

    /// Get IPv4 routes
    pub fn ipv4_routes(&self) -> Vec<&RouteRule> {
        self.routes
            .iter()
            .filter(|r| matches!(r.destination, IpNetwork::V4(_)))
            .collect()
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            policy: RoutingPolicy::Full,
            routes: vec![],
            dns_servers: vec![],
            ipv6_enabled: false,
        }
    }
}

// Serde helpers for IpNetwork
mod ipnetwork_serde {
    use ipnetwork::IpNetwork;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(network: &IpNetwork, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        network.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<IpNetwork, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// Serde helpers for RoutingPolicy
mod routing_policy_serde {
    use super::RoutingPolicy;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(policy: &RoutingPolicy, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match policy {
            RoutingPolicy::Full => "full".serialize(serializer),
            RoutingPolicy::Split => "split".serialize(serializer),
            RoutingPolicy::Bypass => "bypass".serialize(serializer),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RoutingPolicy, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "full" => Ok(RoutingPolicy::Full),
            "split" => Ok(RoutingPolicy::Split),
            "bypass" => Ok(RoutingPolicy::Bypass),
            _ => Err(serde::de::Error::custom(format!(
                "Unknown routing policy: {}",
                s
            ))),
        }
    }
}
