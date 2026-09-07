// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
use cleverestricky_attestation_core::{rewrite_extension, PatchLevels, RewriteRequest};
use der::asn1::Any;
use der::{Decode, Encode, Tag, Tagged};

#[test]
fn rejects_zero_verified_boot_material() {
    let extension = key_description();
    let zero = [0u8; 32];
    let nonzero = [0x42u8; 32];

    for (boot_key, boot_hash) in [(&zero, &nonzero), (&nonzero, &zero)] {
        let result = rewrite_extension(&RewriteRequest {
            extension_der: &extension,
            patch_levels: PatchLevels::default(),
            id_overrides: &[],
            module_hash: None,
            verified_boot_key: boot_key,
            verified_boot_hash: boot_hash,
        });
        assert!(
            result.is_err(),
            "zero verified boot material must fail closed",
        );
    }
}

const ROOT_OF_TRUST_TAG: u32 = 704;

#[test]
fn rewrites_unlocked_root_of_trust_to_locked_and_verified_state() {
    let raw_key = [0x33u8; 32];
    let raw_hash = [0x44u8; 32];
    let expected_boot_key = [0x11u8; 32];
    let expected_boot_hash = [0x22u8; 32];

    // Genuine hardware RootOfTrust: deviceLocked = false (unlocked), verifiedBootState = 2 (Unverified)
    let unlocked_root = sequence([
        Any::new(Tag::OctetString, raw_key.to_vec())
            .unwrap()
            .to_der()
            .unwrap(),
        false.to_der().unwrap(),
        Any::new(Tag::Enumerated, vec![2])
            .unwrap()
            .to_der()
            .unwrap(),
        Any::new(Tag::OctetString, raw_hash.to_vec())
            .unwrap()
            .to_der()
            .unwrap(),
    ]);
    let tee = sequence([explicit_tag(ROOT_OF_TRUST_TAG, &unlocked_root)]);
    let software = sequence([]);
    let extension = sequence([
        400i32.to_der().unwrap(),
        Any::new(Tag::Enumerated, vec![1])
            .unwrap()
            .to_der()
            .unwrap(),
        400i32.to_der().unwrap(),
        Any::new(Tag::Enumerated, vec![1])
            .unwrap()
            .to_der()
            .unwrap(),
        Any::new(Tag::OctetString, Vec::<u8>::new())
            .unwrap()
            .to_der()
            .unwrap(),
        Any::new(Tag::OctetString, Vec::<u8>::new())
            .unwrap()
            .to_der()
            .unwrap(),
        software,
        tee,
    ]);

    let result = rewrite_extension(&RewriteRequest {
        extension_der: &extension,
        patch_levels: PatchLevels::default(),
        id_overrides: &[],
        module_hash: None,
        verified_boot_key: &expected_boot_key,
        verified_boot_hash: &expected_boot_hash,
    })
    .expect("rewrite_extension must succeed");

    let (key, locked, state, hash) = extract_root_of_trust(&result.extension_der);
    assert!(locked, "deviceLocked must be forced to true (locked)");
    assert_eq!(state, 0, "verifiedBootState must be forced to 0 (Verified)");
    assert_eq!(
        key, expected_boot_key,
        "verifiedBootKey must match spoofed key"
    );
    assert_eq!(
        hash, expected_boot_hash,
        "verifiedBootHash must match ro.boot.vbmeta.digest"
    );
}

fn key_description() -> Vec<u8> {
    sequence([
        400i32.to_der().unwrap(),
        Any::new(Tag::Enumerated, vec![1])
            .unwrap()
            .to_der()
            .unwrap(),
        400i32.to_der().unwrap(),
        Any::new(Tag::Enumerated, vec![1])
            .unwrap()
            .to_der()
            .unwrap(),
        Any::new(Tag::OctetString, Vec::<u8>::new())
            .unwrap()
            .to_der()
            .unwrap(),
        Any::new(Tag::OctetString, Vec::<u8>::new())
            .unwrap()
            .to_der()
            .unwrap(),
        sequence([]),
        sequence([]),
    ])
}

fn sequence<const N: usize>(fields: [Vec<u8>; N]) -> Vec<u8> {
    let mut value = Vec::new();
    for field in fields {
        value.extend_from_slice(&field);
    }
    Any::new(Tag::Sequence, value).unwrap().to_der().unwrap()
}

fn explicit_tag(tag: u32, inner: &[u8]) -> Vec<u8> {
    Any::new(
        Tag::ContextSpecific {
            constructed: true,
            number: der::TagNumber(tag),
        },
        inner.to_vec(),
    )
    .unwrap()
    .to_der()
    .unwrap()
}

fn split(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>, der::Error> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (_, rest) = der::asn1::AnyRef::from_der_partial(bytes)?;
        let used = bytes.len() - rest.len();
        out.push(bytes[..used].to_vec());
        bytes = rest;
    }
    Ok(out)
}

fn extract_root_of_trust(extension_der: &[u8]) -> ([u8; 32], bool, u8, [u8; 32]) {
    use der::Decode;
    let outer = Any::from_der(extension_der).expect("KeyDescription DER");
    let fields = split(outer.value()).expect("KeyDescription fields");
    let tee = split(Any::from_der(&fields[7]).expect("tee DER").value()).expect("tee fields");
    for field in tee {
        let tagged = Any::from_der(&field).expect("tagged field");
        if tagged.tag()
            == (Tag::ContextSpecific {
                constructed: true,
                number: der::TagNumber(ROOT_OF_TRUST_TAG),
            })
        {
            let root_seq = Any::from_der(tagged.value()).expect("root seq");
            let root_fields = split(root_seq.value()).expect("root fields");
            let key_any = Any::from_der(&root_fields[0]).expect("key");
            let key: [u8; 32] = key_any.value().try_into().expect("32 byte key");
            let locked = root_fields[1] == true.to_der().unwrap();
            let state_any = Any::from_der(&root_fields[2]).expect("state");
            let state = state_any.value()[0];
            let hash_any = Any::from_der(&root_fields[3]).expect("hash");
            let hash: [u8; 32] = hash_any.value().try_into().expect("32 byte hash");
            return (key, locked, state, hash);
        }
    }
    panic!("ROOT_OF_TRUST_TAG not found");
}
