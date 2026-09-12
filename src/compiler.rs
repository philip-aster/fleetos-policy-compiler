//! Core SAG policy compilation: `SagRule` → eBPF map entries.
//!
//! Two-tier logic based on port:
//! - `port: None` → POLICY_WILDCARD (32-byte key: src + dst fingerprints only)
//! - `port: Some(p)` → POLICY_EXACT (40-byte key: fingerprints + protocol + port)
//!
//! Protocol is not in the current `PeerSelector` schema, so exact entries
//! default to TCP (6). If a future version adds a protocol field, this
//! default becomes unnecessary.
//!
//! **EBPF-CR-6 contract:** all eBPF policy-map key/value construction MUST go
//! through the `to_ebpf_*` helpers in this module. They are the only writers
//! that zero the struct padding bytes (`_pad`/`_pad2`); kernel map lookups are
//! exact-byte matches, so a non-zero pad silently misses and turns an Allow
//! into a default-deny. The contract is pinned by
//! `tests/key_padding_contract.rs`.

use fleetos_core::MonotonicVersion;
use fleetos_core::hash::IdentityFingerprint;
use fleetos_core::policy::{SagAction, SagRule};
use fleetos_core::spiffe::{IdKind, SpiffeId};
use fleetos_ebpf_common::{
    DummyIpRouteValue, EbpfPolicyKey, EbpfPolicyValue, EbpfPolicyWildcardKey, HostOrderPort,
};

use crate::fingerprint;
use crate::precedence;
use crate::{CompiledPolicyEntry, CompiledPolicySet, PolicyDecision, PolicyError};

/// Default protocol for exact entries when protocol is not specified in the schema.
/// TCP = 6. The current PeerSelector schema has no protocol field;
/// if a future version adds one, this default becomes unnecessary.
const DEFAULT_PROTOCOL: u8 = 6;

/// Compile a full set of `SagRule`s into eBPF map entries.
pub fn compile_policy_set(
    rules: &[SagRule],
    version: MonotonicVersion,
    data_trust_domain: &str,
) -> Result<CompiledPolicySet, PolicyError> {
    let mut entries: Vec<CompiledPolicyEntry> = Vec::new();
    let mut wildcard_count = 0;
    let mut exact_count = 0;

    for rule in rules {
        let compiled = compile_single_rule(rule, version, data_trust_domain)?;
        match &compiled {
            CompiledPolicyEntry::Wildcard { .. } => wildcard_count += 1,
            CompiledPolicyEntry::Exact { .. } => exact_count += 1,
        }
        entries.push(compiled);
    }

    // Apply precedence resolution:
    // - Explicit Deny overrides Allow (same key)
    // - EXACT wins over WILDCARD at lookup time (agent-side)
    // - Sorted for deterministic streaming order
    entries = precedence::resolve_precedence(entries);

    Ok(CompiledPolicySet {
        version: version.get(),
        entries,
        wildcard_count,
        exact_count,
    })
}

/// Compile a single `SagRule` into a `CompiledPolicyEntry`.
fn compile_single_rule(
    rule: &SagRule,
    version: MonotonicVersion,
    data_trust_domain: &str,
) -> Result<CompiledPolicyEntry, PolicyError> {
    // ServicePattern fields are now public: tenant and name.
    // Construct SpiffeId from ServicePattern components.
    let src_spiffe_id = SpiffeId::new(
        data_trust_domain,
        rule.from.service.tenant.as_str(),
        IdKind::Sa,
        &rule.from.service.name,
    );

    let dst_spiffe_id = SpiffeId::new(
        data_trust_domain,
        rule.to.service.tenant.as_str(),
        IdKind::Sa,
        &rule.to.service.name,
    );

    // Compute fingerprints — returns [u8; 16] for serde compatibility.
    // CRITICAL: Uses IdentityFingerprint::of() ONLY (never of_with_ordinal).
    let src_fingerprint =
        fingerprint::compute_fingerprint(&src_spiffe_id, rule.from.role.as_ref())?;
    let dst_fingerprint = fingerprint::compute_fingerprint(&dst_spiffe_id, rule.to.role.as_ref())?;

    // Determine decision from the rule's action.
    let decision = match rule.action {
        SagAction::Allow => PolicyDecision::Allow,
        SagAction::Deny => PolicyDecision::Deny,
    };

    // Two-tier logic based on port (protocol is not in the current PeerSelector schema).
    // port: None → WILDCARD, port: Some → EXACT with default protocol TCP.
    match rule.to.port {
        None => Ok(CompiledPolicyEntry::Wildcard {
            src_fingerprint,
            dst_fingerprint,
            decision: decision.to_raw(),
            sag_version: version.get(),
        }),
        Some(p) => Ok(CompiledPolicyEntry::Exact {
            src_fingerprint,
            dst_fingerprint,
            protocol: DEFAULT_PROTOCOL,
            dst_port: p,
            decision: decision.to_raw(),
            sag_version: version.get(),
        }),
    }
}

/// Convert a `CompiledPolicyEntry::Exact` into the `fleetos-ebpf-common` struct
/// for actual BPF map insertion (done by `fleetos-agent`, not by us).
///
/// We produce the struct here so the wire format is consistent.
/// `fleetos-agent` receives this via `PolicyService` and writes it into BPF maps.
///
/// Layout (40 bytes):
/// - src_fingerprint: [u8; 16]
/// - dst_fingerprint: [u8; 16]
/// - protocol: u8
/// - _pad: [u8; 3]
/// - dst_port: HostOrderPort (2 bytes)
/// - _pad2: [u8; 2]
pub fn to_ebpf_exact_key(entry: &CompiledPolicyEntry) -> Option<EbpfPolicyKey> {
    match entry {
        CompiledPolicyEntry::Exact {
            src_fingerprint,
            dst_fingerprint,
            protocol,
            dst_port,
            ..
        } => {
            // HostOrderPort is REQUIRED by fleetos-ebpf-common v0.1.1.
            // Raw u16 will be rejected by the compiler.
            let host_port = HostOrderPort::from_network(*dst_port);

            // EbpfPolicyKey uses IdentityFingerprint type (transparent wrapper over [u8; 16]).
            // We stored raw bytes for serde compatibility; reconstruct the wrapper here.
            Some(EbpfPolicyKey {
                src_fingerprint: IdentityFingerprint(*src_fingerprint),
                dst_fingerprint: IdentityFingerprint(*dst_fingerprint),
                protocol: *protocol,
                _pad: [0u8; 3],
                dst_port: host_port,
                _pad2: [0u8; 2],
            })
        }
        CompiledPolicyEntry::Wildcard { .. } => None,
    }
}

/// Convert a `CompiledPolicyEntry::Wildcard` into the `fleetos-ebpf-common` struct.
///
/// Layout (32 bytes):
/// - src_fingerprint: [u8; 16]
/// - dst_fingerprint: [u8; 16]
/// No padding needed — [u8; 16] has alignment 1.
pub fn to_ebpf_wildcard_key(entry: &CompiledPolicyEntry) -> Option<EbpfPolicyWildcardKey> {
    match entry {
        CompiledPolicyEntry::Wildcard {
            src_fingerprint,
            dst_fingerprint,
            ..
        } => Some(EbpfPolicyWildcardKey {
            src_fingerprint: IdentityFingerprint(*src_fingerprint),
            dst_fingerprint: IdentityFingerprint(*dst_fingerprint),
        }),
        CompiledPolicyEntry::Exact { .. } => None,
    }
}

/// Convert a `CompiledPolicyEntry` into the `EbpfPolicyValue` struct.
///
/// Layout (16 bytes):
/// - Bytes 0-7: `sag_version: u64` (stamped from MonotonicVersion at compile time)
/// - Byte 8: `decision: u8` (0=Deny, 1=Allow)
/// - Bytes 9-15: `_pad: [u8; 7]`
pub fn to_ebpf_value(entry: &CompiledPolicyEntry) -> EbpfPolicyValue {
    let (sag_version, decision) = match entry {
        CompiledPolicyEntry::Wildcard {
            sag_version,
            decision,
            ..
        } => (*sag_version, *decision),
        CompiledPolicyEntry::Exact {
            sag_version,
            decision,
            ..
        } => (*sag_version, *decision),
    };

    EbpfPolicyValue {
        sag_version,
        decision,
        _pad: [0u8; 7],
    }
}

/// Convert route components into the `fleetos-ebpf-common` route map value struct.
///
/// Layout (40 bytes, 8-byte aligned):
/// - dst_fp: IdentityFingerprint (16 bytes)
/// - target_agent_fp: IdentityFingerprint (16 bytes)
/// - sag_version: u64 (8 bytes)
///
/// The agent computes `dst_fp` and `target_agent_fp` from the SVID strings
/// streamed via `WatchRoutes` using `IdentityFingerprint::of`. Control emits
/// the full route set at each `MonotonicVersion`; the agent inserts all
/// version-N entries, then purges entries with `sag_version < N`.
pub fn to_ebpf_route_value(
    dst_fp: IdentityFingerprint,
    target_agent_fp: IdentityFingerprint,
    sag_version: u64,
) -> DummyIpRouteValue {
    DummyIpRouteValue {
        dst_fp,
        target_agent_fp,
        sag_version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_decision_raw_values() {
        assert_eq!(PolicyDecision::Deny.to_raw(), 0);
        assert_eq!(PolicyDecision::Allow.to_raw(), 1);
    }

    #[test]
    fn unknown_decision_defaults_to_deny() {
        // Fail-closed: any value other than 1 is Deny.
        assert_eq!(PolicyDecision::from_raw(0), PolicyDecision::Deny);
        assert_eq!(PolicyDecision::from_raw(1), PolicyDecision::Allow);
        assert_eq!(PolicyDecision::from_raw(2), PolicyDecision::Deny);
        assert_eq!(PolicyDecision::from_raw(255), PolicyDecision::Deny);
    }
}
