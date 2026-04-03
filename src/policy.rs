//! Declarative policy evaluation — reads OWS policy files from /ows/policies/.
//! Executable policies are NOT supported in WASM (no std::process::Command).

use ows_core::{Policy, PolicyContext, PolicyResult, PolicyRule};
use std::fs;
use std::path::Path;

const POLICIES_DIR: &str = "/ows/policies";

/// Load a policy by ID from the vault.
pub fn load_policy(id: &str) -> Result<Policy, String> {
    let path = Path::new(POLICIES_DIR).join(format!("{id}.json"));
    if !path.exists() {
        return Err(format!("policy not found: {id}"));
    }
    let data = fs::read_to_string(&path).map_err(|e| format!("failed to read policy: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("failed to parse policy: {e}"))
}

/// Load all policies referenced by a key.
pub fn load_policies(policy_ids: &[String]) -> Result<Vec<Policy>, String> {
    let mut policies = Vec::with_capacity(policy_ids.len());
    for id in policy_ids {
        policies.push(load_policy(id)?);
    }
    Ok(policies)
}

/// Evaluate all policies. AND semantics: short-circuits on first denial.
pub fn evaluate(policies: &[Policy], context: &PolicyContext) -> PolicyResult {
    for policy in policies {
        for rule in &policy.rules {
            let result = evaluate_rule(rule, &policy.id, context);
            if !result.allow {
                return result;
            }
        }
        // Executable policies are skipped in WASM — only declarative rules apply.
    }
    PolicyResult::allowed()
}

fn evaluate_rule(rule: &PolicyRule, policy_id: &str, ctx: &PolicyContext) -> PolicyResult {
    match rule {
        PolicyRule::AllowedChains { chain_ids } => {
            if chain_ids.iter().any(|c| c == &ctx.chain_id) {
                PolicyResult::allowed()
            } else {
                PolicyResult::denied(
                    policy_id,
                    format!("chain {} not in allowlist", ctx.chain_id),
                )
            }
        }
        PolicyRule::ExpiresAt { timestamp } => {
            if ctx.timestamp.as_str() > timestamp.as_str() {
                PolicyResult::denied(policy_id, format!("policy expired at {timestamp}"))
            } else {
                PolicyResult::allowed()
            }
        }
    }
}
