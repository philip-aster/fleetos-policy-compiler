//! EBPF-CR-6: map-key zero-padding contract.
//!
//! Kernel policy lookups are exact byte matches. Any userspace writer that
//! constructs an `EbpfPolicyKey`/`EbpfPolicyValue` with non-zero padding
//! silently misses, turning an Allow rule into a default-deny. All key
//! construction MUST go through the `to_ebpf_*` helpers, which zero pads.
//! These tests pin that contract; the dirty-pad regression demonstrates the
//! failure mode (different bytes ⇒ lookup miss).
use bytemuck::bytes_of;
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue, EbpfPolicyWildcardKey};
use fleetos_policy_compiler::CompiledPolicyEntry;
use fleetos_policy_compiler::compiler::{to_ebpf_exact_key, to_ebpf_value, to_ebpf_wildcard_key};

fn exact_entry() -> CompiledPolicyEntry {
    CompiledPolicyEntry::Exact {
        src_fingerprint: [0xAA; 16],
        dst_fingerprint: [0xBB; 16],
        protocol: 6,
        dst_port: 5432,
        decision: 1,
        sag_version: 7,
    }
}

fn wildcard_entry() -> CompiledPolicyEntry {
    CompiledPolicyEntry::Wildcard {
        src_fingerprint: [0xAA; 16],
        dst_fingerprint: [0xBB; 16],
        decision: 0,
        sag_version: 7,
    }
}

#[test]
fn exact_key_pads_are_zeroed() {
    let key = to_ebpf_exact_key(&exact_entry()).expect("exact entry");
    assert_eq!(key._pad, [0u8; 3]);
    assert_eq!(key._pad2, [0u8; 2]);
}

#[test]
fn value_pad_is_zeroed_for_both_tiers() {
    assert_eq!(to_ebpf_value(&exact_entry())._pad, [0u8; 7]);
    assert_eq!(to_ebpf_value(&wildcard_entry())._pad, [0u8; 7]);
}

#[test]
fn wildcard_key_is_full_width() {
    // 32 bytes, [u8; 16] members are align-1 — no pads, no implicit padding.
    let key = to_ebpf_wildcard_key(&wildcard_entry()).expect("wildcard entry");
    assert_eq!(core::mem::size_of::<EbpfPolicyWildcardKey>(), 32);
    assert_eq!(core::mem::size_of_val(&key), 32);
}

#[test]
fn helper_output_is_fully_deterministic() {
    // Two constructions of identical input must be byte-identical — proves
    // pad bytes are written (zeroed), never left uninitialized.
    let a = to_ebpf_exact_key(&exact_entry()).expect("exact");
    let b = to_ebpf_exact_key(&exact_entry()).expect("exact");
    assert_eq!(bytes_of(&a), bytes_of(&b));
    let va = to_ebpf_value(&exact_entry());
    let vb = to_ebpf_value(&exact_entry());
    assert_eq!(bytes_of(&va), bytes_of(&vb));
}

#[test]
fn dirtied_pad_never_matches_clean_key() {
    // The regression the contract exists to prevent: any non-zero pad byte
    // yields a different raw key, and the kernel's exact-byte-match lookup
    // silently misses.
    let clean: EbpfPolicyKey = to_ebpf_exact_key(&exact_entry()).expect("exact");
    let mut dirty = clean;
    dirty._pad[0] = 0xFF;
    assert_ne!(bytes_of(&clean), bytes_of(&dirty));
    let mut dirty2 = clean;
    dirty2._pad2[1] = 0x01;
    assert_ne!(bytes_of(&clean), bytes_of(&dirty2));
    let mut dirty_value: EbpfPolicyValue = to_ebpf_value(&exact_entry());
    let clean_value = dirty_value;
    dirty_value._pad[3] = 0x80;
    assert_ne!(bytes_of(&clean_value), bytes_of(&dirty_value));
}
