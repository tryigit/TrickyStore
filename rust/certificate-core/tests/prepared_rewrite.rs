// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
mod fixture {
    include!("rewrite.rs");

    pub(super) fn run_prepared_fixture(xml: &[u8], algorithm: SigningAlgorithm) {
        let document = parse_keybox_xml_bytes(xml).expect("fixture XML");
        let key = document.keys.first().expect("fixture key");
        let private_key = normalize_private_key_pkcs8(&key.algorithm, &key.private_key_pem)
            .expect("fixture key DER");
        let issuer_pem = key
            .certificates_pem
            .first()
            .expect("fixture issuer certificate");
        let issuer = Certificate::from_pem(normalized_pem(issuer_pem).as_bytes())
            .expect("fixture issuer DER");
        let genuine = synthetic_genuine_leaf(&issuer);
        let genuine_der = genuine.to_der().expect("genuine DER");
        let issuer_der = issuer.to_der().expect("issuer DER");
        let ids = [AttestationIdOverride {
            tag: IMEI_TAG,
            value: b"new-imei",
        }];
        let prepared = cleverestricky_certificate_core::PreparedIssuer::new(
            &issuer_der,
            private_key.as_slice(),
            algorithm,
        )
        .expect("prepared issuer");

        let rewritten = cleverestricky_certificate_core::rewrite_certificate_prepared(
            &cleverestricky_certificate_core::PreparedCertificateRewriteRequest {
                genuine_leaf_der: &genuine_der,
                issuer: &prepared,
                patch_levels: PatchLevels {
                    system: PatchComponent::replace(202512),
                    vendor: PatchComponent::KEEP,
                    boot: PatchComponent::KEEP,
                },
                id_overrides: &ids,
                module_hash: Some(b"new-module-hash"),
                verified_boot_key: &BOOT_KEY,
                verified_boot_hash: &BOOT_HASH,
            },
        )
        .expect("prepared Rust certificate rewrite");

        assert_eq!(
            rewritten.captured_patch_levels,
            CapturedPatchLevels {
                system: Some(202401),
                vendor: None,
                boot: None,
            },
        );
        let output = Certificate::from_der(&rewritten.leaf_der).expect("rewritten certificate DER");
        assert_eq!(
            output.tbs_certificate().subject_public_key_info(),
            genuine.tbs_certificate().subject_public_key_info(),
        );
        assert_eq!(
            output.tbs_certificate().issuer(),
            issuer.tbs_certificate().subject(),
        );
        verify_signature(&output, &issuer, algorithm);
    }

    pub(super) fn synthetic_genuine_leaf_with_critical(
        issuer: &Certificate,
        critical: bool,
    ) -> Certificate {
        let issuer_tbs = issuer.tbs_certificate();
        let version = explicit_x509_tag(0, &2i32.to_der().expect("v3 DER"));
        let serial = 0x80i32.to_der().expect("serial DER");
        let signature = issuer_tbs
            .signature()
            .to_der()
            .expect("signature algorithm DER");
        let issuer_name = issuer_tbs.subject().to_der().expect("issuer name DER");
        let validity = issuer_tbs.validity().to_der().expect("validity DER");
        let subject = issuer_tbs.subject().to_der().expect("subject DER");
        let spki = issuer_tbs
            .subject_public_key_info()
            .to_der()
            .expect("SPKI DER");
        let issuer_unique_id = implicit_unique_id(1, 0xa0);
        let subject_unique_id = implicit_unique_id(2, 0xb0);

        let extension_der = synthetic_attestation_extension();
        let mut extensions = issuer_tbs.extensions().cloned().unwrap_or_default();
        extensions.retain(|extension| extension.extn_id != ANDROID_ATTESTATION_OID);
        extensions.push(Extension {
            extn_id: ANDROID_ATTESTATION_OID,
            critical,
            extn_value: OctetString::new(extension_der).expect("attestation octets"),
        });
        let extensions = extensions.to_der().expect("extensions DER");
        let extensions = explicit_x509_tag(3, &extensions);

        let tbs = x509_sequence([
            version.as_slice(),
            serial.as_slice(),
            signature.as_slice(),
            issuer_name.as_slice(),
            validity.as_slice(),
            subject.as_slice(),
            spki.as_slice(),
            issuer_unique_id.as_slice(),
            subject_unique_id.as_slice(),
            extensions.as_slice(),
        ]);
        let outer_algorithm = issuer
            .signature_algorithm()
            .to_der()
            .expect("outer signature algorithm DER");
        let outer_signature = issuer.signature().to_der().expect("outer signature DER");
        let certificate = x509_sequence([
            tbs.as_slice(),
            outer_algorithm.as_slice(),
            outer_signature.as_slice(),
        ]);
        Certificate::from_der(&certificate).expect("synthetic genuine certificate")
    }

    pub(super) fn run_prepared_critical_fixture(xml: &[u8], algorithm: SigningAlgorithm) {
        let document = parse_keybox_xml_bytes(xml).expect("fixture XML");
        let key = document.keys.first().expect("fixture key");
        let private_key = normalize_private_key_pkcs8(&key.algorithm, &key.private_key_pem)
            .expect("fixture key DER");
        let issuer_pem = key
            .certificates_pem
            .first()
            .expect("fixture issuer certificate");
        let issuer = Certificate::from_pem(normalized_pem(issuer_pem).as_bytes())
            .expect("fixture issuer DER");
        let genuine = synthetic_genuine_leaf_with_critical(&issuer, true);
        let genuine_der = genuine.to_der().expect("genuine DER");
        let issuer_der = issuer.to_der().expect("issuer DER");

        let prepared = cleverestricky_certificate_core::PreparedIssuer::new(
            &issuer_der,
            private_key.as_slice(),
            algorithm,
        )
        .expect("prepared issuer");

        let rewritten = cleverestricky_certificate_core::rewrite_certificate_prepared(
            &cleverestricky_certificate_core::PreparedCertificateRewriteRequest {
                genuine_leaf_der: &genuine_der,
                issuer: &prepared,
                patch_levels: PatchLevels::default(),
                id_overrides: &[],
                module_hash: None,
                verified_boot_key: &BOOT_KEY,
                verified_boot_hash: &BOOT_HASH,
            },
        )
        .expect("rewrite critical attestation extension");

        let output = Certificate::from_der(&rewritten.leaf_der).expect("rewritten certificate DER");
        let rewritten_ext = output
            .tbs_certificate()
            .extensions()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .find(|extension| extension.extn_id == ANDROID_ATTESTATION_OID)
            .expect("rewritten attestation extension");
        assert!(
            rewritten_ext.critical,
            "rewritten extension must preserve critical = true"
        );
        assert_eq!(
            output.tbs_certificate().issuer_unique_id(),
            genuine.tbs_certificate().issuer_unique_id(),
            "issuerUniqueID must survive the hot-path TBS rebuild",
        );
        assert_eq!(
            output.tbs_certificate().subject_unique_id(),
            genuine.tbs_certificate().subject_unique_id(),
            "subjectUniqueID must survive the hot-path TBS rebuild",
        );
        verify_signature(&output, &issuer, algorithm);
    }

    pub(super) fn run_prepared_rejects_extra_outer_field(xml: &[u8], algorithm: SigningAlgorithm) {
        let document = parse_keybox_xml_bytes(xml).expect("fixture XML");
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
            algorithm,
        )
        .expect("prepared issuer");
        let genuine = synthetic_genuine_leaf(&issuer);
        let tbs = genuine.tbs_certificate().to_der().expect("TBS DER");
        let outer_algorithm = genuine
            .signature_algorithm()
            .to_der()
            .expect("outer algorithm DER");
        let outer_signature = genuine.signature().to_der().expect("outer signature DER");
        let extra = 0i32.to_der().expect("extra DER");
        let malformed = x509_sequence([
            tbs.as_slice(),
            outer_algorithm.as_slice(),
            outer_signature.as_slice(),
            extra.as_slice(),
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

    pub(super) fn run_prepared_rejects_v2_with_extensions(xml: &[u8], algorithm: SigningAlgorithm) {
        let document = parse_keybox_xml_bytes(xml).expect("fixture XML");
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
            algorithm,
        )
        .expect("prepared issuer");
        let mut malformed = synthetic_genuine_leaf(&issuer)
            .to_der()
            .expect("genuine DER");
        let v3_marker = [0xa0, 0x03, 0x02, 0x01, 0x02];
        let version_offset = malformed
            .windows(v3_marker.len())
            .position(|window| window == v3_marker)
            .expect("v3 version marker");
        malformed[version_offset + v3_marker.len() - 1] = 0x01;

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

    pub(super) fn ec() -> &'static [u8] {
        VALID_EC
    }

    pub(super) fn rsa() -> &'static [u8] {
        VALID_RSA
    }
}

#[test]
fn prepared_ec_issuer_rewrites_and_signs_without_per_call_key_parse() {
    fixture::run_prepared_fixture(
        fixture::ec(),
        cleverestricky_certificate_core::SigningAlgorithm::EcP256Sha256,
    );
}

#[test]
fn prepared_rsa_issuer_rewrites_and_signs_without_per_call_key_parse() {
    fixture::run_prepared_fixture(
        fixture::rsa(),
        cleverestricky_certificate_core::SigningAlgorithm::RsaPkcs1Sha256,
    );
}

#[test]
fn prepared_rewrite_preserves_critical_attestation_extension_and_unique_ids() {
    fixture::run_prepared_critical_fixture(
        fixture::ec(),
        cleverestricky_certificate_core::SigningAlgorithm::EcP256Sha256,
    );
}

#[test]
fn prepared_rewrite_rejects_extra_outer_certificate_fields() {
    fixture::run_prepared_rejects_extra_outer_field(
        fixture::ec(),
        cleverestricky_certificate_core::SigningAlgorithm::EcP256Sha256,
    );
}

#[test]
fn prepared_rewrite_rejects_extensions_on_v2_certificate() {
    fixture::run_prepared_rejects_v2_with_extensions(
        fixture::ec(),
        cleverestricky_certificate_core::SigningAlgorithm::EcP256Sha256,
    );
}
