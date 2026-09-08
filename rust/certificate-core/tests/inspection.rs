// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
use cleverestricky_attestation_core::CapturedPatchLevels;
use cleverestricky_certificate_core::{inspect_certificate, Error, SecurityLevel};

mod fixture {
    include!("rewrite.rs");

    pub(super) fn genuine_leaf_der() -> Vec<u8> {
        let document = parse_keybox_xml_bytes(VALID_EC).expect("fixture XML");
        let key = document.keys.first().expect("fixture key");
        let issuer_pem = key
            .certificates_pem
            .first()
            .expect("fixture issuer certificate");
        let normalized_issuer = normalized_pem(issuer_pem);
        let issuer =
            Certificate::from_pem(normalized_issuer.as_bytes()).expect("fixture issuer DER");
        synthetic_genuine_leaf(&issuer)
            .to_der()
            .expect("genuine DER")
    }

    pub(super) fn ordinary_certificate_der() -> Vec<u8> {
        let document = parse_keybox_xml_bytes(VALID_EC).expect("fixture XML");
        let key = document.keys.first().expect("fixture key");
        let issuer_pem = key
            .certificates_pem
            .first()
            .expect("fixture issuer certificate");
        let normalized_issuer = normalized_pem(issuer_pem);
        Certificate::from_pem(normalized_issuer.as_bytes())
            .expect("fixture certificate")
            .to_der()
            .expect("fixture DER")
    }

    pub(super) fn zero_boot_key_leaf_der() -> Vec<u8> {
        let document = parse_keybox_xml_bytes(VALID_EC).expect("fixture XML");
        let key = document.keys.first().expect("fixture key");
        let issuer_pem = key
            .certificates_pem
            .first()
            .expect("fixture issuer certificate");
        let normalized_issuer = normalized_pem(issuer_pem);
        let issuer =
            Certificate::from_pem(normalized_issuer.as_bytes()).expect("fixture issuer DER");
        let tee = auth_list([
            explicit_tag_raw(704, &root_of_trust([0u8; 32], [0x31; 32])),
            explicit_integer_raw(706, 202401),
            explicit_octet_raw(714, b"old-imei"),
        ]);
        let software = auth_list([]);
        let ext = encode_sequence([
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            any_octets(&[]).as_slice(),
            any_octets(&[]).as_slice(),
            software.as_slice(),
            tee.as_slice(),
        ]);
        synthetic_leaf_with_ext(&issuer, ext)
            .to_der()
            .expect("genuine DER")
    }

    pub(super) fn leaf_with_ext(extension_der: Vec<u8>) -> Vec<u8> {
        let document = parse_keybox_xml_bytes(VALID_EC).expect("fixture XML");
        let key = document.keys.first().expect("fixture key");
        let issuer_pem = key
            .certificates_pem
            .first()
            .expect("fixture issuer certificate");
        let normalized_issuer = normalized_pem(issuer_pem);
        let issuer =
            Certificate::from_pem(normalized_issuer.as_bytes()).expect("fixture issuer DER");
        synthetic_leaf_with_ext(&issuer, extension_der)
            .to_der()
            .expect("leaf DER")
    }

    pub(super) fn missing_root_leaf_der() -> Vec<u8> {
        let software = auth_list([]);
        let tee = auth_list([]);
        let ext = encode_sequence([
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            any_octets(&[]).as_slice(),
            any_octets(&[]).as_slice(),
            software.as_slice(),
            tee.as_slice(),
        ]);
        leaf_with_ext(ext)
    }

    pub(super) fn duplicate_root_across_lists_leaf_der() -> Vec<u8> {
        let root = explicit_tag_raw(704, &root_of_trust([0x21; 32], [0x31; 32]));
        let software = auth_list([root.clone()]);
        let tee = auth_list([root]);
        let ext = encode_sequence([
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            any_octets(&[]).as_slice(),
            any_octets(&[]).as_slice(),
            software.as_slice(),
            tee.as_slice(),
        ]);
        leaf_with_ext(ext)
    }

    pub(super) fn duplicate_root_in_same_list_leaf_der() -> Vec<u8> {
        let root = explicit_tag_raw(704, &root_of_trust([0x21; 32], [0x31; 32]));
        let software = auth_list([]);
        let tee = auth_list([root.clone(), root]);
        let ext = encode_sequence([
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            any_octets(&[]).as_slice(),
            any_octets(&[]).as_slice(),
            software.as_slice(),
            tee.as_slice(),
        ]);
        leaf_with_ext(ext)
    }

    pub(super) fn malformed_root_leaf_der() -> Vec<u8> {
        let key = any_octets(&[0x21; 32]);
        let verified = attestation_der::Encode::to_der(&true).expect("bool DER");
        let state = any_enumerated(0);
        let bad_root_value =
            encode_sequence([key.as_slice(), verified.as_slice(), state.as_slice()]);
        let bad_root = explicit_tag_raw(704, &bad_root_value);
        let software = auth_list([]);
        let tee = auth_list([bad_root]);
        let ext = encode_sequence([
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            any_octets(&[]).as_slice(),
            any_octets(&[]).as_slice(),
            software.as_slice(),
            tee.as_slice(),
        ]);
        leaf_with_ext(ext)
    }

    pub(super) fn implicit_root_leaf_der() -> Vec<u8> {
        let key = any_octets(&[0x21; 32]);
        let verified = attestation_der::Encode::to_der(&true).expect("bool DER");
        let state = any_enumerated(0);
        let hash = any_octets(&[0x31; 32]);
        let raw_fields = [
            key.as_slice(),
            verified.as_slice(),
            state.as_slice(),
            hash.as_slice(),
        ]
        .concat();
        let implicit_root = explicit_tag_raw(704, &raw_fields);
        let software = auth_list([]);
        let tee = auth_list([implicit_root]);
        let ext = encode_sequence([
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            any_octets(&[]).as_slice(),
            any_octets(&[]).as_slice(),
            software.as_slice(),
            tee.as_slice(),
        ]);
        leaf_with_ext(ext)
    }

    pub(super) fn mismatched_signature_algorithm_leaf_der() -> Vec<u8> {
        let genuine = Certificate::from_der(&genuine_leaf_der()).expect("genuine certificate");
        let tbs = genuine.tbs_certificate().to_der().expect("TBS DER");
        let outer_signature = genuine.signature().to_der().expect("signature DER");
        let rsa_sha256_algorithm = [
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
            0x00,
        ];
        x509_sequence([
            tbs.as_slice(),
            rsa_sha256_algorithm.as_slice(),
            outer_signature.as_slice(),
        ])
    }

    pub(super) fn misordered_unique_ids_leaf_der() -> Vec<u8> {
        let mut der = genuine_leaf_der();
        let issuer_uid = implicit_unique_id(1, 0xa0);
        let subject_uid = implicit_unique_id(2, 0xb0);
        assert_eq!(issuer_uid.len(), subject_uid.len());
        let issuer_offset = der
            .windows(issuer_uid.len())
            .position(|window| window == issuer_uid.as_slice())
            .expect("issuerUniqueID marker");
        let subject_offset = der
            .windows(subject_uid.len())
            .position(|window| window == subject_uid.as_slice())
            .expect("subjectUniqueID marker");
        assert!(issuer_offset < subject_offset);
        der[issuer_offset..issuer_offset + issuer_uid.len()].copy_from_slice(&subject_uid);
        der[subject_offset..subject_offset + subject_uid.len()].copy_from_slice(&issuer_uid);
        der
    }

    pub(super) fn v2_with_extensions_leaf_der() -> Vec<u8> {
        let mut der = genuine_leaf_der();
        let v3_marker = [0xa0, 0x03, 0x02, 0x01, 0x02];
        let version_offset = der
            .windows(v3_marker.len())
            .position(|window| window == v3_marker)
            .expect("v3 version marker");
        der[version_offset + v3_marker.len() - 1] = 0x01;
        der
    }

    pub(super) fn extra_outer_field_leaf_der() -> Vec<u8> {
        let genuine = Certificate::from_der(&genuine_leaf_der()).expect("genuine certificate");
        let tbs = genuine.tbs_certificate().to_der().expect("TBS DER");
        let outer_algorithm = genuine
            .signature_algorithm()
            .to_der()
            .expect("outer algorithm DER");
        let outer_signature = genuine.signature().to_der().expect("signature DER");
        let extra = 0i32.to_der().expect("extra DER");
        x509_sequence([
            tbs.as_slice(),
            outer_algorithm.as_slice(),
            outer_signature.as_slice(),
            extra.as_slice(),
        ])
    }

    fn synthetic_leaf_with_ext(issuer: &Certificate, extension_der: Vec<u8>) -> Certificate {
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

        let mut extensions = issuer_tbs.extensions().cloned().unwrap_or_default();
        extensions.retain(|extension| extension.extn_id != ANDROID_ATTESTATION_OID);
        extensions.push(x509_cert::ext::Extension {
            extn_id: ANDROID_ATTESTATION_OID,
            critical: false,
            extn_value: attestation_der::asn1::OctetString::new(extension_der)
                .expect("attestation octets"),
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
}

#[test]
fn inspection_returns_only_policy_inputs_needed_by_android_adapter() {
    let inspected = inspect_certificate(&fixture::genuine_leaf_der()).expect("inspection");
    assert_eq!(
        inspected.captured_patch_levels,
        CapturedPatchLevels {
            system: Some(202401),
            vendor: None,
            boot: None,
        }
    );
    assert_eq!(inspected.present_id_mask, 1 << 4);
    assert!(inspected.supports_module_hash);
    assert_eq!(inspected.original_boot_key, Some([0x21; 32]));
    assert_eq!(inspected.original_boot_hash, Some([0x31; 32]));
    assert_eq!(
        inspected.attestation_security_level,
        SecurityLevel::TrustedEnvironment
    );
    assert_eq!(
        inspected.keymint_security_level,
        SecurityLevel::TrustedEnvironment
    );
}

#[test]
fn inspection_preserves_boot_hash_when_boot_key_is_all_zeros() {
    let inspected = inspect_certificate(&fixture::zero_boot_key_leaf_der()).expect("inspection");
    assert_eq!(inspected.original_boot_key, None);
    assert_eq!(inspected.original_boot_hash, Some([0x31; 32]));
}

#[test]
fn certificate_without_attestation_extension_fails_closed() {
    assert_eq!(
        inspect_certificate(&fixture::ordinary_certificate_der()).unwrap_err(),
        Error::MissingAttestationExtension
    );
}

#[test]
fn inspection_rejects_missing_root_of_trust() {
    assert_eq!(
        inspect_certificate(&fixture::missing_root_leaf_der()).unwrap_err(),
        Error::AttestationRewrite
    );
}

#[test]
fn inspection_rejects_duplicate_root_of_trust_across_lists() {
    assert_eq!(
        inspect_certificate(&fixture::duplicate_root_across_lists_leaf_der()).unwrap_err(),
        Error::AttestationRewrite
    );
}

#[test]
fn inspection_rejects_duplicate_root_of_trust_in_same_list() {
    assert_eq!(
        inspect_certificate(&fixture::duplicate_root_in_same_list_leaf_der()).unwrap_err(),
        Error::AttestationRewrite
    );
}

#[test]
fn inspection_rejects_malformed_root_of_trust_structure() {
    assert_eq!(
        inspect_certificate(&fixture::malformed_root_leaf_der()).unwrap_err(),
        Error::AttestationRewrite
    );
}

#[test]
fn inspection_rejects_implicitly_tagged_root_of_trust() {
    assert_eq!(
        inspect_certificate(&fixture::implicit_root_leaf_der()).unwrap_err(),
        Error::AttestationRewrite
    );
}

#[test]
fn inspection_rejects_mismatched_certificate_signature_algorithm() {
    assert_eq!(
        inspect_certificate(&fixture::mismatched_signature_algorithm_leaf_der()).unwrap_err(),
        Error::InvalidCertificate
    );
}

#[test]
fn inspection_rejects_misordered_unique_ids() {
    assert_eq!(
        inspect_certificate(&fixture::misordered_unique_ids_leaf_der()).unwrap_err(),
        Error::InvalidCertificate
    );
}

#[test]
fn inspection_rejects_extensions_on_v2_certificate() {
    assert_eq!(
        inspect_certificate(&fixture::v2_with_extensions_leaf_der()).unwrap_err(),
        Error::InvalidCertificate
    );
}

#[test]
fn inspection_rejects_extra_outer_certificate_fields() {
    assert_eq!(
        inspect_certificate(&fixture::extra_outer_field_leaf_der()).unwrap_err(),
        Error::InvalidCertificate
    );
}
