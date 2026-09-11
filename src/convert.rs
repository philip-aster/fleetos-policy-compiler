//! Proto `SagRule` -> core `SagRule` conversion.
//!
//! The wire format is the proto `SagRule` (see `state.proto`). Compilation
//! operates on core types. This is the single canonical conversion; it runs
//! port validation so out-of-range ports are rejected at the boundary.

use crate::PolicyError;
use crate::port_validation::validate_optional_port;
use fleetos_core::policy::{PeerSelector, SagAction, SagRule, SagRuleId, ServicePattern};
use fleetos_core::proto::state::{PeerSelector as ProtoPeerSelector, SagRule as ProtoSagRule};
use fleetos_core::spiffe::WorkloadRole;
use fleetos_core::tenant::TenantId;

fn convert_peer_selector(ps: &ProtoPeerSelector) -> Result<PeerSelector, PolicyError> {
    let tenant =
        TenantId::new(ps.tenant.clone()).map_err(|e| PolicyError::InvalidTenant(e.to_owned()))?;
    let role = if ps.role.is_empty() {
        None
    } else {
        Some(
            WorkloadRole::try_from(ps.role.as_str())
                .map_err(|e| PolicyError::InvalidRole(e.to_string()))?,
        )
    };
    let port = validate_optional_port(ps.port)?;
    Ok(PeerSelector {
        service: ServicePattern {
            tenant,
            name: ps.service_name.clone(),
        },
        role,
        port,
    })
}

/// Convert a proto `SagRule` to a core `SagRule`, recomputing the canonical
/// content-derived id. Any caller-supplied id is advisory and ignored.
pub fn proto_rule_to_core(rule: &ProtoSagRule) -> Result<SagRule, PolicyError> {
    let from_proto = rule
        .from
        .as_ref()
        .ok_or_else(|| PolicyError::Compilation("rule.from is required".to_owned()))?;
    let to_proto = rule
        .to
        .as_ref()
        .ok_or_else(|| PolicyError::Compilation("rule.to is required".to_owned()))?;

    let action = match rule.action {
        0 => SagAction::Allow,
        1 => SagAction::Deny,
        other => {
            return Err(PolicyError::Compilation(format!(
                "invalid action value: {}",
                other
            )));
        }
    };

    let from = convert_peer_selector(from_proto)?;
    let to = convert_peer_selector(to_proto)?;

    // Cross-tenant rules are prohibited by the TenantCtx contract.
    if from.service.tenant != to.service.tenant {
        return Err(PolicyError::Compilation(
            "cross-tenant rule rejected: from.tenant != to.tenant".to_owned(),
        ));
    }

    let action_str = match action {
        SagAction::Allow => "ALLOW",
        SagAction::Deny => "DENY",
    };
    let id = SagRuleId::of_rule(
        from.service.tenant.as_str(),
        &from.service.name,
        from.role.as_ref(),
        from.port,
        &to.service.name,
        to.role.as_ref(),
        to.port,
        action_str,
    );

    Ok(SagRule {
        id,
        from,
        to,
        action,
    })
}
