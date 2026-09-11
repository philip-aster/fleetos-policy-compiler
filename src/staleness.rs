//! Staleness detection for eBPF map entries.
//!
//! Uses the `sag_version` field in `EbpfPolicyValue` (stamped from
//! `MonotonicVersion` at compile time) to allow agents to detect and purge
//! stale entries after a policy update.
//!
//! When an agent receives a new `CompiledPolicySet` with version N, any
//! locally-cached entry with `sag_version < N` is stale and should be purged.

use fleetos_core::MonotonicVersion;

use crate::CompiledPolicyEntry;

/// Check if a cached entry is stale relative to the current policy version.
///
/// An entry is stale if its `sag_version` is less than the current version.
/// Agents use this to decide which local BPF map entries to purge after
/// receiving a policy update.
pub fn is_stale(entry_sag_version: u64, current_version: u64) -> bool {
    entry_sag_version < current_version
}

/// Filter a set of cached entries, returning only the stale ones.
///
/// Agents call this after receiving a new `CompiledPolicySet` to determine
/// which of their locally-cached entries need to be purged from BPF maps.
pub fn find_stale_entries(
    cached_entries: &[CachedEntry],
    current_version: u64,
) -> Vec<&CachedEntry> {
    cached_entries
        .iter()
        .filter(|e| is_stale(e.sag_version, current_version))
        .collect()
}

/// A cached eBPF map entry as tracked by an agent.
///
/// This is the agent-side representation — `fleetos-control` produces
/// `CompiledPolicyEntry` and streams it; `fleetos-agent` caches it locally
/// and uses this type to track staleness.
#[derive(Debug, Clone)]
pub struct CachedEntry {
    /// The key bytes (either 32-byte wildcard or 40-byte exact).
    pub key: Vec<u8>,

    /// The `sag_version` from `EbpfPolicyValue`.
    pub sag_version: u64,

    /// The decision (0=Deny, 1=Allow).
    pub decision: u8,
}

/// Compute the version stamp for a new compilation pass.
///
/// This is called by the state machine when applying a Raft log entry that
/// modifies SAG rules. The returned version is stamped into every
/// `EbpfPolicyValue` produced by this compilation.
pub fn version_stamp(version: MonotonicVersion) -> u64 {
    version.get()
}

/// Extract the sag_version from a compiled entry.
pub fn entry_version(entry: &CompiledPolicyEntry) -> u64 {
    match entry {
        CompiledPolicyEntry::Wildcard { sag_version, .. } => *sag_version,
        CompiledPolicyEntry::Exact { sag_version, .. } => *sag_version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_detection() {
        assert!(is_stale(5, 10)); // version 5 is stale when current is 10
        assert!(!is_stale(10, 10)); // same version is not stale
        assert!(!is_stale(15, 10)); // newer version is not stale (shouldn't happen)
    }

    #[test]
    fn find_stale_entries_filters_correctly() {
        let cached = vec![
            CachedEntry {
                key: vec![1, 2, 3],
                sag_version: 5,
                decision: 1,
            },
            CachedEntry {
                key: vec![4, 5, 6],
                sag_version: 10,
                decision: 0,
            },
            CachedEntry {
                key: vec![7, 8, 9],
                sag_version: 3,
                decision: 1,
            },
        ];

        let stale = find_stale_entries(&cached, 8);

        // Entries with version 5 and 3 are stale (< 8).
        assert_eq!(stale.len(), 2);
        assert_eq!(stale[0].sag_version, 5);
        assert_eq!(stale[1].sag_version, 3);
    }

    #[test]
    fn entry_version_extraction() {
        let wildcard = CompiledPolicyEntry::Wildcard {
            src_fingerprint: [0; 16],
            dst_fingerprint: [0; 16],
            decision: 1,
            sag_version: 42,
        };
        assert_eq!(entry_version(&wildcard), 42);

        let exact = CompiledPolicyEntry::Exact {
            src_fingerprint: [0; 16],
            dst_fingerprint: [0; 16],
            protocol: 6,
            dst_port: 80,
            decision: 0,
            sag_version: 99,
        };
        assert_eq!(entry_version(&exact), 99);
    }
}
