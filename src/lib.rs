//! Canonical SAG -> eBPF policy compiler.
//!
//! Single source of truth for compiling `SagRule` (fleetos-core) into the
//! `fleetos-ebpf-common` map entries. Both `fleetos-control` and
//! `fleetos-agent` consume this crate; two independent compilers would drift.
//!
//! CRITICAL: this crate calls `IdentityFingerprint::of` ONLY. `of_with_ordinal`
//! must never appear here or in any consumer (see `tests/fingerprint_guard.rs`).

pub mod compiler;
pub mod convert;
pub mod fingerprint;
pub mod port_validation;
pub mod precedence;
pub mod staleness;

use thiserror::Error;

/// Errors from SAG policy compilation / conversion.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("port value {0} exceeds valid u16 range (max 65535)")]
    PortOutOfRange(u32),
    #[error("invalid protocol value: {0}")]
    InvalidProtocol(u8),
    #[error("fingerprint computation failed: {0}")]
    Fingerprint(String),
    #[error("rule compilation failed: {0}")]
    Compilation(String),
    #[error("invalid tenant id: {0}")]
    InvalidTenant(String),
    #[error("invalid role: {0}")]
    InvalidRole(String),
}

/// The decision encoded in `EbpfPolicyValue.decision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Deny = 0,
    Allow = 1,
}

impl PolicyDecision {
    pub fn from_raw(value: u8) -> Self {
        match value {
            1 => PolicyDecision::Allow,
            _ => PolicyDecision::Deny,
        }
    }
    pub fn to_raw(self) -> u8 {
        self as u8
    }
}

/// A compiled policy entry, ready for eBPF map insertion.
///
/// Stores raw `[u8; 16]` fingerprint bytes (not `IdentityFingerprint`) because
/// `IdentityFingerprint` does not implement serde traits. Conversion to
/// `IdentityFingerprint` happens in `compiler.rs` when constructing the eBPF structs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CompiledPolicyEntry {
    Wildcard {
        src_fingerprint: [u8; 16],
        dst_fingerprint: [u8; 16],
        decision: u8,
        sag_version: u64,
    },
    Exact {
        src_fingerprint: [u8; 16],
        dst_fingerprint: [u8; 16],
        protocol: u8,
        dst_port: u16,
        decision: u8,
        sag_version: u64,
    },
}

/// The full compiled policy set for a cluster, at a specific version.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompiledPolicySet {
    pub version: u64,
    pub entries: Vec<CompiledPolicyEntry>,
    pub wildcard_count: usize,
    pub exact_count: usize,
}
