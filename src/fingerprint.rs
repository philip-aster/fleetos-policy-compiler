//! Fingerprint computation wrapper.
//!
//! **CRITICAL:** This module wraps `IdentityFingerprint::of(id, role)` and is the
//! ONLY sanctioned path for computing routing/policy fingerprints in this crate.

use fleetos_core::WorkloadRole;
use fleetos_core::hash::IdentityFingerprint;
use fleetos_core::spiffe::SpiffeId;

use crate::PolicyError;

/// Compute the 16-byte BLAKE3 fingerprint for a (SpiffeId, role) pair.
///
/// Returns raw `[u8; 16]` bytes extracted from `IdentityFingerprint.0`.
/// This is the ONLY fingerprint function in this crate.
pub fn compute_fingerprint(
    id: &SpiffeId,
    role: Option<&WorkloadRole>,
) -> Result<[u8; 16], PolicyError> {
    let fingerprint = IdentityFingerprint::of(id, role);
    Ok(fingerprint.0)
}

pub fn compute_rule_fingerprints(
    src_id: &SpiffeId,
    src_role: Option<&WorkloadRole>,
    dst_id: &SpiffeId,
    dst_role: Option<&WorkloadRole>,
) -> Result<([u8; 16], [u8; 16]), PolicyError> {
    let src = compute_fingerprint(src_id, src_role)?;
    let dst = compute_fingerprint(dst_id, dst_role)?;
    Ok((src, dst))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_service_role_same_fingerprint() {
        let id: SpiffeId = "spiffe://fleet.example.internal/ns/my-tenant/sa/my-service"
            .parse()
            .unwrap();

        let role = WorkloadRole::try_from("replica").unwrap();
        let fp1 = compute_fingerprint(&id, Some(&role)).unwrap();
        let fp2 = compute_fingerprint(&id, Some(&role)).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn different_role_different_fingerprint() {
        let id: SpiffeId = "spiffe://fleet.example.internal/ns/my-tenant/sa/my-service"
            .parse()
            .unwrap();

        let role_primary = WorkloadRole::try_from("primary").unwrap();
        let role_replica = WorkloadRole::try_from("replica").unwrap();

        let fp1 = compute_fingerprint(&id, Some(&role_primary)).unwrap();
        let fp2 = compute_fingerprint(&id, Some(&role_replica)).unwrap();
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn none_role_differs_from_some_role() {
        let id: SpiffeId = "spiffe://fleet.example.internal/ns/my-tenant/sa/my-service"
            .parse()
            .unwrap();

        let role = WorkloadRole::try_from("primary").unwrap();
        let fp_with_role = compute_fingerprint(&id, Some(&role)).unwrap();
        let fp_without_role = compute_fingerprint(&id, None).unwrap();
        assert_ne!(fp_with_role, fp_without_role);
    }

    #[test]
    fn nul_byte_in_role_rejected() {
        // WorkloadRole validates against embedded NUL bytes to protect
        // domain-separated hashing.
        let result = WorkloadRole::try_from("role\0injected");
        assert!(result.is_err());
    }
}
