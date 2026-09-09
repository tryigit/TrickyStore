// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod core;
mod derived_key;
mod inspection;

pub use cleverestricky_attestation_core::{
    AttestationIdOverride, CapturedPatchLevels, PatchComponent, PatchLevels,
    MAX_ATTESTATION_ID_BYTES, MAX_MODULE_HASH_BYTES,
};
pub use core::*;
pub use derived_key::derive_ec_p256_keypair;
pub use inspection::{inspect_certificate, CertificateInspection, SecurityLevel};
