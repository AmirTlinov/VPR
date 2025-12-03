//! Routing state management for VPN tunnel
//!
//! Tracks added routes, policy rules, and NAT rules for cleanup.

use ipnetwork::IpNetwork;

/// State for tracking added routes and NAT rules for cleanup
#[derive(Debug, Clone, Default)]
pub struct RoutingState {
    /// Added routes (destination -> command args for deletion)
    routes: Vec<(IpNetwork, Vec<String>)>,
    /// Added policy rules (priority -> command args for deletion)
    policy_rules: Vec<(u32, Vec<String>)>,
    /// NAT rules added (for cleanup)
    nat_rules: Vec<Vec<String>>,
}

impl RoutingState {
    /// Create new empty routing state
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a route with its deletion arguments
    pub fn add_route(&mut self, destination: IpNetwork, delete_args: Vec<String>) {
        self.routes.push((destination, delete_args));
    }

    /// Add a policy rule with its deletion arguments
    pub fn add_policy_rule(&mut self, priority: u32, delete_args: Vec<String>) {
        self.policy_rules.push((priority, delete_args));
    }

    /// Add a NAT rule with its deletion arguments
    pub fn add_nat_rule(&mut self, delete_args: Vec<String>) {
        self.nat_rules.push(delete_args);
    }

    /// Get number of routes
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Get number of policy rules
    pub fn policy_rule_count(&self) -> usize {
        self.policy_rules.len()
    }

    /// Get number of NAT rules
    pub fn nat_rule_count(&self) -> usize {
        self.nat_rules.len()
    }

    /// Check if has any routes
    pub fn has_routes(&self) -> bool {
        !self.routes.is_empty()
    }

    /// Check if has any policy rules
    pub fn has_policy_rules(&self) -> bool {
        !self.policy_rules.is_empty()
    }

    /// Check if has any NAT rules
    pub fn has_nat_rules(&self) -> bool {
        !self.nat_rules.is_empty()
    }

    /// Get routes for iteration
    pub fn routes(&self) -> &[(IpNetwork, Vec<String>)] {
        &self.routes
    }

    /// Get policy rules for iteration
    pub fn policy_rules(&self) -> &[(u32, Vec<String>)] {
        &self.policy_rules
    }

    /// Get NAT rules for iteration
    pub fn nat_rules(&self) -> &[Vec<String>] {
        &self.nat_rules
    }

    /// Clear routes
    pub fn clear_routes(&mut self) {
        self.routes.clear();
    }

    /// Clear policy rules
    pub fn clear_policy_rules(&mut self) {
        self.policy_rules.clear();
    }

    /// Clear NAT rules
    pub fn clear_nat_rules(&mut self) {
        self.nat_rules.clear();
    }
}
