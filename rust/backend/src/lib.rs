// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
#![forbid(unsafe_code)]

mod attest_key_store;
mod certificate_wire;
mod crl_wire;
mod keybox_wire;

/// Fuzz-only entry point for the real certificate inspect/rewrite wire parser.
pub fn fuzz_certificate_wire(input: &[u8]) {
    let _ = certificate_wire::inspect_and_encode(input.to_vec());
    if let Ok(response) = certificate_wire::rewrite_and_encode(input.to_vec()) {
        assert!(response.len() <= certificate_wire::MAX_REWRITE_RESPONSE_BYTES);
    }
}

/// Fuzz-only entry point for the real stateful CRL wire parser.
pub fn fuzz_crl_wire(input: &[u8]) {
    let _ = crl_wire::handle(input.to_vec());
}

/// Fuzz-only entry point for the real keybox XML/control wire parser and bounded key store.
pub fn fuzz_keybox_wire(input: &[u8]) {
    if let Ok(response) = keybox_wire::parse_and_encode(input.to_vec()) {
        assert!(response.len() <= keybox_wire::MAX_KEYBOX_RESPONSE_BYTES);
    }
}

/// Fuzz-only entry point for the real attest-key and child-key rewrite wire parsers.
pub fn fuzz_attest_key_wire(input: &[u8]) {
    let _ = certificate_wire::rewrite_attest_key_and_encode(input.to_vec());
    let _ = certificate_wire::rewrite_child_key_and_encode(input.to_vec());
}
