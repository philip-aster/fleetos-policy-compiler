//! Port range validation for wire deserialization.
//!
//! **Requirement (Part 1.5):** The wire representation of `PeerSelector.port` is
//! `uint32` (protobuf has no native 16-bit int), carrying what should always be a
//! valid `u16` value. Code that deserializes this field MUST explicitly reject
//! values above 65535 rather than silently truncating on the downcast to `u16`.
//!
//! A malformed or malicious value in that range must surface as a rejected message,
//! not a quietly-wrong port number compiled into a policy map entry.
//!
//! This module is called at the deserialization boundary (AdminService, proto → Rust
//! conversion), NOT inside the compiler. By the time a `SagRule` reaches the compiler,
//! its port is already a validated `Option<u16>`.

use crate::PolicyError;

/// Maximum valid port number.
pub const MAX_VALID_PORT: u32 = 65535;

/// Validate a port value received from the wire (uint32 in protobuf).
///
/// Returns `Ok(u16)` if the value is a valid port, `Err` if it exceeds
/// the u16 range. This MUST be called on every port value deserialized
/// from a gRPC message before it enters the compilation pipeline.
pub fn validate_port(wire_value: u32) -> Result<u16, PolicyError> {
    if wire_value > MAX_VALID_PORT {
        return Err(PolicyError::PortOutOfRange(wire_value));
    }
    // Safe: we've verified the value fits in u16.
    Ok(wire_value as u16)
}

/// Validate an optional port value from the wire.
///
/// `None` means wildcard (no port constraint). `Some(value)` must be validated.
pub fn validate_optional_port(wire_value: Option<u32>) -> Result<Option<u16>, PolicyError> {
    match wire_value {
        None => Ok(None),
        Some(v) => Ok(Some(validate_port(v)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_port_accepted() {
        assert_eq!(validate_port(0).unwrap(), 0);
        assert_eq!(validate_port(80).unwrap(), 80);
        assert_eq!(validate_port(443).unwrap(), 443);
        assert_eq!(validate_port(65535).unwrap(), 65535);
    }

    #[test]
    fn port_above_65535_rejected() {
        assert!(matches!(
            validate_port(65536),
            Err(PolicyError::PortOutOfRange(65536))
        ));
        assert!(matches!(
            validate_port(u32::MAX),
            Err(PolicyError::PortOutOfRange(u32::MAX))
        ));
    }

    #[test]
    fn none_port_is_wildcard() {
        assert_eq!(validate_optional_port(None).unwrap(), None);
    }

    #[test]
    fn some_port_validated() {
        assert_eq!(validate_optional_port(Some(8080)).unwrap(), Some(8080));
        assert!(validate_optional_port(Some(70000)).is_err());
    }
}
