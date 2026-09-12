# fleetos-policy-compiler

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The canonical Service Authorization Graph (SAG) to eBPF policy compiler for FleetOS.

`fleetos-policy-compiler` is the single source of truth for translating high-level `SagRule`s (defined in `fleetos-core`) into the low-level byte-exact map entries consumed by the `fleetos-ebpf` kernel datapath. Both `fleetos-control` (the producer) and `fleetos-agent` (the consumer/cache) rely on this crate. Two independent compilers would inevitably drift and cause silent policy failures.

## Core Invariants

This crate defends several critical security and correctness invariants. Violating these results in silent policy bypasses or kernel lookup misses.

1. **Fingerprint Purity:** This crate calls `IdentityFingerprint::of()` **ONLY**. The experimental `of_with_ordinal()` is strictly prohibited and guarded by a compile-time test (`tests/fingerprint_guard.rs`). Using ordinal routing here would silently convert a load-balanced replica pool into N independently unreachable identities.
2. **Map-Key Zero-Padding Contract (EBPF-CR-6):** Kernel BPF map lookups are exact byte matches. The `EbpfPolicyKey` struct contains padding bytes (`_pad`, `_pad2`) for alignment. If a userspace writer constructs a key without zeroing these pads, the lookup silently misses, turning an Allow rule into a default-deny. **All key construction MUST go through the `to_ebpf_*` helpers in `src/compiler.rs`**, which guarantee zeroed pads. This contract is pinned by `tests/key_padding_contract.rs`.
3. **Wire-Boundary Port Validation:** Protobuf lacks a native 16-bit integer, so ports arrive as `uint32`. The `port_validation` module explicitly rejects values `> 65535` at the deserialization boundary, preventing silent truncation into the eBPF maps.
4. **Precedence Resolution:** The `precedence` module guarantees that explicit Deny overrides Allow for the same key, and that Exact-tier entries are sorted before Wildcard-tier entries for deterministic streaming.

## Module Map

| Module | Purpose |
|---|---|
| `compiler` | Core compilation: `SagRule` -> `CompiledPolicySet`. Contains the `to_ebpf_*` helpers that construct byte-exact, zero-padded eBPF structs. |
| `convert` | Proto `SagRule` -> Core `SagRule` conversion. Runs port validation at the wire boundary. |
| `fingerprint` | Wrapper around `IdentityFingerprint::of()`. The only sanctioned path for computing routing/policy fingerprints in this crate. |
| `port_validation` | Validates `uint32` wire ports into `Option<u16>`, rejecting out-of-range values. |
| `precedence` | Resolves Deny-overrides-Allow conflicts and sorts entries for deterministic agent streaming. |
| `staleness` | Provides `is_stale()` and `find_stale_entries()` to help the agent purge old eBPF map entries based on the `sag_version` stamp. |

## Usage

### For `fleetos-control`
Control uses `compile_policy_set()` to translate the current cluster SAG into a `CompiledPolicySet` at a specific `MonotonicVersion`. It then streams the resulting `CompiledPolicyEntry` list to agents via the `PolicyService` gRPC stream.

### For `fleetos-agent`
The agent receives the compiled entries, caches them locally, and uses the `to_ebpf_*` helpers to construct the exact byte layouts required to insert them into the `POLICY_EXACT` and `POLICY_WILDCARD` BPF maps via Aya. When a new version arrives, the agent uses the `staleness` module to identify and purge entries with `sag_version < N`.

## Testing

```bash
# Run all unit and integration tests
cargo test -p fleetos-policy-compiler

# Specifically verify the EBPF-CR-6 zero-padding contract
cargo test -p fleetos-policy-compiler --test key_padding_contract

# Verify the fingerprint purity invariant
cargo test -p fleetos-policy-compiler --test fingerprint_guard

## Dependencies

- fleetos-core: For SagRule, SpiffeId, IdentityFingerprint, and MonotonicVersion.
- fleetos-ebpf-common: For the `#[repr(C)]` eBPF map structs (EbpfPolicyKey, EbpfPolicyValue, etc.).
- bytemuck: Used in tests to assert byte-exact layout and padding guarantees.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
