// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
use cleverestricky_attestation_core::{
    inspect_captured_patch_levels, AttestationIdOverride, CapturedPatchLevels, PatchComponent,
    PatchLevels,
};
use cleverestricky_certificate_core::{
    rewrite_certificate, CertificateRewriteRequest, SigningAlgorithm, ANDROID_ATTESTATION_OID,
};
use cleverestricky_keybox_core::normalize_private_key_pkcs8;
use cleverestricky_xml_core::parse_keybox_xml_bytes;
use x509_cert::der::asn1::{Any, OctetString};
use x509_cert::der::{Decode, DecodePem, Encode, Tag, TagNumber};
use x509_cert::ext::Extension;
use x509_cert::Certificate;

const VALID_EC: &[u8] = include_bytes!("../../../service/src/test/resources/keybox/valid_ec.xml");
const VALID_RSA: &[u8] = include_bytes!("../../../service/src/test/resources/keybox/valid_rsa.xml");
const IMEI_TAG: u32 = 714;
const BOOT_KEY: [u8; 32] = [0x51; 32];
const BOOT_HASH: [u8; 32] = [0x61; 32];

#[test]
fn rewrites_and_resigns_ec_leaf_with_managed_builder_semantics() {
    run_fixture(VALID_EC, SigningAlgorithm::EcP256Sha256);
}

#[test]
fn rewrites_and_resigns_rsa_leaf_with_managed_builder_semantics() {
    run_fixture(VALID_RSA, SigningAlgorithm::RsaPkcs1Sha256);
}

#[test]
fn ec_issuer_resigns_rsa_subject_without_changing_subject_spki() {
    let ec_document = parse_keybox_xml_bytes(VALID_EC).expect("EC fixture XML");
    let ec_key = ec_document.keys.first().expect("EC fixture key");
    let ec_private = normalize_private_key_pkcs8(&ec_key.algorithm, &ec_key.private_key_pem)
        .expect("EC fixture key DER");
    let ec_issuer = Certificate::from_pem(
        normalized_pem(
            ec_key
                .certificates_pem
                .first()
                .expect("EC fixture issuer certificate"),
        )
        .as_bytes(),
    )
    .expect("EC fixture issuer DER");

    let rsa_document = parse_keybox_xml_bytes(VALID_RSA).expect("RSA fixture XML");
    let rsa_key = rsa_document.keys.first().expect("RSA fixture key");
    let rsa_subject = Certificate::from_pem(
        normalized_pem(
            rsa_key
                .certificates_pem
                .first()
                .expect("RSA fixture certificate"),
        )
        .as_bytes(),
    )
    .expect("RSA fixture DER");
    let genuine = synthetic_genuine_leaf(&rsa_subject);
    let genuine_der = genuine.to_der().expect("genuine RSA-subject DER");
    let issuer_der = ec_issuer.to_der().expect("EC issuer DER");

    let rewritten = rewrite_certificate(&CertificateRewriteRequest {
        genuine_leaf_der: &genuine_der,
        issuer_certificate_der: &issuer_der,
        issuer_private_key_pkcs8: ec_private.as_slice(),
        signing_algorithm: SigningAlgorithm::EcP256Sha256,
        patch_levels: PatchLevels::default(),
        id_overrides: &[],
        module_hash: None,
        verified_boot_key: &BOOT_KEY,
        verified_boot_hash: &BOOT_HASH,
    })
    .expect("cross-algorithm Rust certificate rewrite");
    let output = Certificate::from_der(&rewritten.leaf_der).expect("rewritten certificate DER");

    assert_eq!(
        output.tbs_certificate().subject_public_key_info(),
        genuine.tbs_certificate().subject_public_key_info(),
    );
    assert_eq!(
        output
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .expect("rewritten subject SPKI DER"),
        genuine
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .expect("genuine subject SPKI DER"),
    );
    assert_eq!(
        output.tbs_certificate().issuer(),
        ec_issuer.tbs_certificate().subject(),
    );
    verify_signature(&output, &ec_issuer, SigningAlgorithm::EcP256Sha256);
}

fn run_fixture(xml: &[u8], algorithm: SigningAlgorithm) {
    let document = parse_keybox_xml_bytes(xml).expect("fixture XML");
    let key = document.keys.first().expect("fixture key");
    let private_key =
        normalize_private_key_pkcs8(&key.algorithm, &key.private_key_pem).expect("fixture key DER");
    let issuer_pem = key
        .certificates_pem
        .first()
        .expect("fixture issuer certificate");
    let normalized_issuer = normalized_pem(issuer_pem);
    let issuer = Certificate::from_pem(normalized_issuer.as_bytes()).expect("fixture issuer DER");
    let genuine = synthetic_genuine_leaf(&issuer);
    let genuine_der = genuine.to_der().expect("genuine DER");
    let issuer_der = issuer.to_der().expect("issuer DER");
    let ids = [AttestationIdOverride {
        tag: IMEI_TAG,
        value: b"new-imei",
    }];

    let rewritten = rewrite_certificate(&CertificateRewriteRequest {
        genuine_leaf_der: &genuine_der,
        issuer_certificate_der: &issuer_der,
        issuer_private_key_pkcs8: private_key.as_slice(),
        signing_algorithm: algorithm,
        patch_levels: PatchLevels {
            system: PatchComponent::replace(202512),
            vendor: PatchComponent::KEEP,
            boot: PatchComponent::KEEP,
        },
        id_overrides: &ids,
        module_hash: Some(b"new-module-hash"),
        verified_boot_key: &BOOT_KEY,
        verified_boot_hash: &BOOT_HASH,
    })
    .expect("Rust certificate rewrite");

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
        output.tbs_certificate().serial_number(),
        genuine.tbs_certificate().serial_number(),
    );
    assert_eq!(
        output
            .tbs_certificate()
            .serial_number()
            .to_der()
            .expect("rewritten serial DER"),
        vec![0x02, 0x02, 0x00, 0x80],
    );
    assert_eq!(
        output.tbs_certificate().validity(),
        genuine.tbs_certificate().validity()
    );
    assert_eq!(
        output.tbs_certificate().subject(),
        genuine.tbs_certificate().subject()
    );
    assert_eq!(
        output.tbs_certificate().subject_public_key_info(),
        genuine.tbs_certificate().subject_public_key_info(),
    );
    assert_eq!(
        output
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .expect("rewritten subject SPKI DER"),
        genuine
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .expect("genuine subject SPKI DER"),
    );
    assert!(genuine.tbs_certificate().issuer_unique_id().is_some());
    assert!(genuine.tbs_certificate().subject_unique_id().is_some());
    assert_eq!(
        output.tbs_certificate().issuer_unique_id(),
        genuine.tbs_certificate().issuer_unique_id(),
    );
    assert_eq!(
        output.tbs_certificate().subject_unique_id(),
        genuine.tbs_certificate().subject_unique_id(),
    );
    assert_eq!(
        output.tbs_certificate().issuer(),
        issuer.tbs_certificate().subject()
    );
    assert_eq!(
        non_attestation_extensions(&output),
        non_attestation_extensions(&genuine),
    );

    let attestation = output
        .tbs_certificate()
        .extensions()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .find(|extension| extension.extn_id == ANDROID_ATTESTATION_OID)
        .expect("rewritten attestation extension");
    assert!(!attestation.critical);
    assert_eq!(
        inspect_captured_patch_levels(attestation.extn_value.as_bytes()).expect("patch parse"),
        CapturedPatchLevels {
            system: Some(202512),
            vendor: None,
            boot: None,
        },
    );

    verify_signature(&output, &issuer, algorithm);
}

fn normalized_pem(value: &str) -> String {
    let mut normalized = value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    normalized.push('\n');
    normalized
}

fn synthetic_genuine_leaf(issuer: &Certificate) -> Certificate {
    let issuer_tbs = issuer.tbs_certificate();
    let version = explicit_x509_tag(0, &2i32.to_der().expect("v3 DER"));
    // 0x80 requires DER's leading 0x00 sign octet when encoded as a positive INTEGER.
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
        critical: false,
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

fn explicit_x509_tag(tag: u32, inner: &[u8]) -> Vec<u8> {
    Any::new(
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber(tag),
        },
        inner.to_vec(),
    )
    .expect("explicit tag")
    .to_der()
    .expect("explicit tag DER")
}

fn implicit_unique_id(tag: u32, value: u8) -> Vec<u8> {
    Any::new(
        Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(tag),
        },
        vec![0, value],
    )
    .expect("unique id")
    .to_der()
    .expect("unique id DER")
}

fn x509_sequence<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut value = Vec::new();
    for part in parts {
        value.extend_from_slice(part);
    }
    Any::new(Tag::Sequence, value)
        .expect("sequence")
        .to_der()
        .expect("sequence DER")
}

fn synthetic_attestation_extension() -> Vec<u8> {
    let tee = auth_list([
        explicit_tag_raw(704, &root_of_trust([0x21; 32], [0x31; 32])),
        explicit_integer_raw(706, 202401),
        explicit_octet_raw(714, b"old-imei"),
    ]);
    let software = auth_list([]);
    encode_sequence([
        attestation_i32(400).as_slice(),
        any_enumerated(1).as_slice(),
        attestation_i32(400).as_slice(),
        any_enumerated(1).as_slice(),
        any_octets(&[]).as_slice(),
        any_octets(&[]).as_slice(),
        software.as_slice(),
        tee.as_slice(),
    ])
}

fn verify_signature(output: &Certificate, issuer: &Certificate, algorithm: SigningAlgorithm) {
    use p256::ecdsa::{Signature as EcSignature, VerifyingKey as EcVerifyingKey};
    use p256::pkcs8::DecodePublicKey as _;
    use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
    use rsa::pkcs8::DecodePublicKey as _;
    use rsa_sha2::Sha256 as RsaSha256;
    use rsa_signature::Verifier as _;
    use signature::Verifier as _;

    let tbs = output.tbs_certificate().to_der().expect("TBS DER");
    let issuer_spki = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .expect("issuer SPKI");
    match algorithm {
        SigningAlgorithm::EcP256Sha256 => {
            let key = EcVerifyingKey::from_public_key_der(&issuer_spki).expect("EC issuer key");
            let signature = EcSignature::from_der(output.signature().raw_bytes()).expect("EC sig");
            key.verify(&tbs, &signature).expect("EC verification");
        }
        SigningAlgorithm::RsaPkcs1Sha256 => {
            let key = rsa::RsaPublicKey::from_public_key_der(&issuer_spki).expect("RSA issuer key");
            let verifying = RsaVerifyingKey::<RsaSha256>::new(key);
            let signature =
                RsaSignature::try_from(output.signature().raw_bytes()).expect("RSA sig");
            verifying
                .verify(&tbs, &signature)
                .expect("RSA verification");
        }
    }
}

fn non_attestation_extensions(certificate: &Certificate) -> Vec<Vec<u8>> {
    certificate
        .tbs_certificate()
        .extensions()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .filter(|extension| extension.extn_id != ANDROID_ATTESTATION_OID)
        .map(|extension| extension.to_der().expect("extension DER"))
        .collect()
}

fn auth_list<const N: usize>(fields: [Vec<u8>; N]) -> Vec<u8> {
    encode_sequence(fields.iter().map(Vec::as_slice))
}

fn explicit_integer_raw(tag: u32, value: i32) -> Vec<u8> {
    explicit_tag_raw(tag, &attestation_i32(value))
}

fn explicit_octet_raw(tag: u32, value: &[u8]) -> Vec<u8> {
    explicit_tag_raw(tag, &any_octets(value))
}

fn root_of_trust(key: [u8; 32], hash: [u8; 32]) -> Vec<u8> {
    encode_sequence([
        any_octets(&key).as_slice(),
        attestation_bool(true).as_slice(),
        any_enumerated(0).as_slice(),
        any_octets(&hash).as_slice(),
    ])
}

fn attestation_i32(value: i32) -> Vec<u8> {
    attestation_der::Encode::to_der(&value).unwrap()
}

fn attestation_bool(value: bool) -> Vec<u8> {
    attestation_der::Encode::to_der(&value).unwrap()
}

fn any_octets(value: &[u8]) -> Vec<u8> {
    let any =
        attestation_der::asn1::Any::new(attestation_der::Tag::OctetString, value.to_vec()).unwrap();
    attestation_der::Encode::to_der(&any).unwrap()
}

fn any_enumerated(value: u8) -> Vec<u8> {
    let any =
        attestation_der::asn1::Any::new(attestation_der::Tag::Enumerated, vec![value]).unwrap();
    attestation_der::Encode::to_der(&any).unwrap()
}

fn explicit_tag_raw(tag: u32, inner: &[u8]) -> Vec<u8> {
    let any = attestation_der::asn1::Any::new(
        attestation_der::Tag::ContextSpecific {
            constructed: true,
            number: attestation_der::TagNumber(tag),
        },
        inner.to_vec(),
    )
    .unwrap();
    attestation_der::Encode::to_der(&any).unwrap()
}

fn encode_sequence<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut value = Vec::new();
    for part in parts {
        value.extend_from_slice(part);
    }
    let any = attestation_der::asn1::Any::new(attestation_der::Tag::Sequence, value).unwrap();
    attestation_der::Encode::to_der(&any).unwrap()
}
