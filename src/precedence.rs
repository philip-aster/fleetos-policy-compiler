//! Policy precedence resolution.

use crate::{CompiledPolicyEntry, PolicyDecision};

/// Resolve precedence conflicts in the compiled entry set.
pub fn resolve_precedence(mut entries: Vec<CompiledPolicyEntry>) -> Vec<CompiledPolicyEntry> {
    // Step 1: Remove Allow entries overridden by Deny entries.
    entries = remove_overridden_allows(entries);

    // Step 2: Sort for deterministic streaming order.
    entries.sort_by(|a, b| {
        entry_tier(a)
            .cmp(&entry_tier(b))
            .then_with(|| decision_order(a).cmp(&decision_order(b)))
            .then_with(|| fingerprint_order(a).cmp(&fingerprint_order(b)))
    });

    entries
}

/// Remove Allow entries that are overridden by a Deny for the same key.
fn remove_overridden_allows(entries: Vec<CompiledPolicyEntry>) -> Vec<CompiledPolicyEntry> {
    use std::collections::HashSet;

    let deny_keys: HashSet<Vec<u8>> = entries
        .iter()
        .filter(|e| entry_decision(e) == PolicyDecision::Deny)
        .map(entry_key_bytes)
        .collect();

    entries
        .into_iter()
        .filter(|e| {
            if entry_decision(e) == PolicyDecision::Allow {
                !deny_keys.contains(&entry_key_bytes(e))
            } else {
                true
            }
        })
        .collect()
}

/// Get the decision from an entry.
fn entry_decision(entry: &CompiledPolicyEntry) -> PolicyDecision {
    match entry {
        CompiledPolicyEntry::Wildcard { decision, .. } => PolicyDecision::from_raw(*decision),
        CompiledPolicyEntry::Exact { decision, .. } => PolicyDecision::from_raw(*decision),
    }
}

/// Get a deterministic key for Deny-overrides-Allow matching.
fn entry_key_bytes(entry: &CompiledPolicyEntry) -> Vec<u8> {
    match entry {
        CompiledPolicyEntry::Wildcard {
            src_fingerprint,
            dst_fingerprint,
            ..
        } => {
            let mut key = Vec::with_capacity(32);
            key.extend_from_slice(src_fingerprint);
            key.extend_from_slice(dst_fingerprint);
            key
        }
        CompiledPolicyEntry::Exact {
            src_fingerprint,
            dst_fingerprint,
            protocol,
            dst_port,
            ..
        } => {
            let mut key = Vec::with_capacity(35);
            key.extend_from_slice(src_fingerprint);
            key.extend_from_slice(dst_fingerprint);
            key.push(*protocol);
            key.extend_from_slice(&dst_port.to_be_bytes());
            key
        }
    }
}

/// Tier for sorting: Exact (0) before Wildcard (1).
fn entry_tier(entry: &CompiledPolicyEntry) -> u8 {
    match entry {
        CompiledPolicyEntry::Exact { .. } => 0,
        CompiledPolicyEntry::Wildcard { .. } => 1,
    }
}

/// Decision order for sorting: Deny (0) before Allow (1).
fn decision_order(entry: &CompiledPolicyEntry) -> u8 {
    match entry_decision(entry) {
        PolicyDecision::Deny => 0,
        PolicyDecision::Allow => 1,
    }
}

/// Fingerprint order for deterministic sorting within same tier+decision.
fn fingerprint_order(entry: &CompiledPolicyEntry) -> Vec<u8> {
    entry_key_bytes(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_wildcard(src: u8, dst: u8, decision: u8) -> CompiledPolicyEntry {
        CompiledPolicyEntry::Wildcard {
            src_fingerprint: [src; 16],
            dst_fingerprint: [dst; 16],
            decision,
            sag_version: 1,
        }
    }

    fn make_exact(src: u8, dst: u8, proto: u8, port: u16, decision: u8) -> CompiledPolicyEntry {
        CompiledPolicyEntry::Exact {
            src_fingerprint: [src; 16],
            dst_fingerprint: [dst; 16],
            protocol: proto,
            dst_port: port,
            decision,
            sag_version: 1,
        }
    }

    #[test]
    fn deny_overrides_allow_for_same_key() {
        let entries = vec![
            make_wildcard(1, 2, 1), // Allow
            make_wildcard(1, 2, 0), // Deny (same key)
        ];

        let resolved = resolve_precedence(entries);
        assert_eq!(resolved.len(), 1);
        assert_eq!(entry_decision(&resolved[0]), PolicyDecision::Deny);
    }

    #[test]
    fn allow_kept_when_no_deny() {
        let entries = vec![
            make_wildcard(1, 2, 1), // Allow
            make_wildcard(3, 4, 0), // Deny (different key)
        ];

        let resolved = resolve_precedence(entries);
        assert_eq!(resolved.len(), 2);
    }

    #[test]
    fn exact_sorted_before_wildcard() {
        let entries = vec![make_wildcard(1, 2, 1), make_exact(1, 2, 6, 80, 1)];

        let resolved = resolve_precedence(entries);
        assert!(matches!(resolved[0], CompiledPolicyEntry::Exact { .. }));
        assert!(matches!(resolved[1], CompiledPolicyEntry::Wildcard { .. }));
    }

    #[test]
    fn exact_deny_and_wildcard_allow_both_kept() {
        let entries = vec![make_wildcard(1, 2, 1), make_exact(1, 2, 6, 80, 0)];

        let resolved = resolve_precedence(entries);
        assert_eq!(resolved.len(), 2);
    }
}
