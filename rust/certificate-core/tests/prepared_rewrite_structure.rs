// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
mod fixture {
    include!("rewrite.rs");

    pub(super) fn rejects_mismatched_outer_algorithm() {
        let document = parse_keybox_xml_bytes(VALID_EC).expect("fixture XML");
        let key = document.keys.first().expect("fixture key");
        let private_key = normalize_private_key_pkcs8(&key.algorithm, &key.private_key_pem)
            .expect("fixture key DER");
        let issuer = Certificate::from_pem(
            normalized_pem(
                key.certificates_pem
                    .first()
                    .expect("fixture issuer certificate"),
            )
            .as_bytes(),
        )
        .expect("fixture issuer DER");
        let issuer_der = issuer.to_der().expect("issuer DER");
        let prepared = cleverestricky_certificate_core::PreparedIssuer::new(
            &issuer_der,
            private_key.as_slice(),
            cleverestricky_certificate_core::SigningAlgorithm::EcP256Sha256,
        )
        .expect("prepared issuer");
        let genuine = synthetic_genuine_leaf(&issuer);
        let tbs = genuine.tbs_certificate().to_der().expect("TBS DER");
        let outer_signature = genuine.signature().to_der().expect("signature DER");
        let mismatched_algorithm = [
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
            0x05, 0x00,
        ];
        let malformed = x509_sequence([
            tbs.as_slice(),
            mismatched_algorithm.as_slice(),
            outer_signature.as_slice(),
        ]);

        let result = cleverestricky_certificate_core::rewrite_certificate_prepared(
            &cleverestricky_certificate_core::PreparedCertificateRewriteRequest {
                genuine_leaf_der: &malformed,
                issuer: &prepared,
                patch_levels: PatchLevels::default(),
                id_overrides: &[],
                module_hash: None,
                verified_boot_key: &BOOT_KEY,
                verified_boot_hash: &BOOT_HASH,
            },
        );
        assert!(matches!(
            result,
            Err(cleverestricky_certificate_core::Error::InvalidCertificate)
        ));
    }
}

#[test]
fn prepared_rewrite_rejects_mismatched_certificate_signature_algorithm() {
    fixture::rejects_mismatched_outer_algorithm();
}
