// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
use cleverestricky_attestation_core::CapturedPatchLevels;
use cleverestricky_certificate_core::{inspect_certificate, Error};

mod fixture {
    include!("rewrite.rs");

    fn issuer() -> Certificate {
        let document = parse_keybox_xml_bytes(VALID_EC).expect("fixture XML");
        let key = document.keys.first().expect("fixture key");
        let issuer_pem = key
            .certificates_pem
            .first()
            .expect("fixture issuer certificate");
        Certificate::from_pem(normalized_pem(issuer_pem).as_bytes()).expect("fixture issuer DER")
    }

    fn leaf_with_lists(software: Vec<u8>, tee: Vec<u8>) -> Vec<u8> {
        let issuer = issuer();
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
        let attestation = encode_sequence([
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            attestation_i32(400).as_slice(),
            any_enumerated(1).as_slice(),
            any_octets(&[]).as_slice(),
            any_octets(&[]).as_slice(),
            software.as_slice(),
            tee.as_slice(),
        ]);
        let extension = Extension {
            extn_id: ANDROID_ATTESTATION_OID,
            critical: false,
            extn_value: OctetString::new(attestation).expect("attestation octets"),
        };
        let extensions = vec![extension].to_der().expect("extensions DER");
        let extensions = explicit_x509_tag(3, &extensions);
        let tbs = x509_sequence([
            version.as_slice(),
            serial.as_slice(),
            signature.as_slice(),
            issuer_name.as_slice(),
            validity.as_slice(),
            subject.as_slice(),
            spki.as_slice(),
            extensions.as_slice(),
        ]);
        let outer_algorithm = issuer
            .signature_algorithm()
            .to_der()
            .expect("outer signature algorithm DER");
        let outer_signature = issuer.signature().to_der().expect("outer signature DER");
        x509_sequence([
            tbs.as_slice(),
            outer_algorithm.as_slice(),
            outer_signature.as_slice(),
        ])
    }

    pub(super) fn same_duplicate_patch_leaf() -> Vec<u8> {
        let software = auth_list([]);
        let tee = auth_list([
            explicit_tag_raw(704, &root_of_trust([0x21; 32], [0x31; 32])),
            explicit_integer_raw(706, 202401),
            explicit_integer_raw(706, 202401),
        ]);
        leaf_with_lists(software, tee)
    }

    pub(super) fn conflicting_duplicate_patch_leaf() -> Vec<u8> {
        let software = auth_list([]);
        let tee = auth_list([
            explicit_tag_raw(704, &root_of_trust([0x21; 32], [0x31; 32])),
            explicit_integer_raw(706, 202401),
            explicit_integer_raw(706, 202402),
        ]);
        leaf_with_lists(software, tee)
    }

    pub(super) fn conflicting_cross_list_patch_leaf() -> Vec<u8> {
        let software = auth_list([explicit_integer_raw(706, 202401)]);
        let tee = auth_list([
            explicit_tag_raw(704, &root_of_trust([0x21; 32], [0x31; 32])),
            explicit_integer_raw(706, 202402),
        ]);
        leaf_with_lists(software, tee)
    }
}

#[test]
fn inspection_preserves_identical_duplicate_patch_semantics() {
    let inspected = inspect_certificate(&fixture::same_duplicate_patch_leaf()).expect("inspection");
    assert_eq!(
        inspected.captured_patch_levels,
        CapturedPatchLevels {
            system: Some(202401),
            vendor: None,
            boot: None,
        }
    );
}

#[test]
fn inspection_rejects_conflicting_duplicate_patch_in_same_list() {
    assert_eq!(
        inspect_certificate(&fixture::conflicting_duplicate_patch_leaf()).unwrap_err(),
        Error::AttestationRewrite
    );
}

#[test]
fn inspection_rejects_conflicting_patch_across_lists() {
    assert_eq!(
        inspect_certificate(&fixture::conflicting_cross_list_patch_leaf()).unwrap_err(),
        Error::AttestationRewrite
    );
}
