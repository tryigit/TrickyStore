// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
use crate::{
    parse_any, parse_extension, validate_v3_version, Error, TlvIterator,
    ANDROID_ATTESTATION_OID_BYTES, MAX_CERTIFICATE_DER_BYTES,
};
use attestation_der::asn1::AnyRef;
use attestation_der::{Decode as AttestationDecode, Tag, TagNumber, Tagged};
use cleverestricky_attestation_core::CapturedPatchLevels;

const SOFTWARE_INDEX: usize = 6;
const TEE_INDEX: usize = 7;
const ROOT_OF_TRUST_TAG: u32 = 704;
const SYSTEM_PATCH_TAG: u32 = 706;
const VENDOR_PATCH_TAG: u32 = 718;
const BOOT_PATCH_TAG: u32 = 719;
const ID_TAGS: [u32; 9] = [710, 711, 712, 713, 714, 715, 716, 717, 723];
const MAX_FIELDS: usize = 16;
const MAX_TAGS: usize = 256;

/// Canonical Android KeyMint security levels carried by KeyDescription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    StrongBox = 2,
}

impl SecurityLevel {
    pub const fn wire_value(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SecurityLevels {
    attestation: SecurityLevel,
    keymint: SecurityLevel,
}

#[derive(Clone, Copy, Debug, Default)]
struct AuthorizationScan<'a> {
    root_count: usize,
    root_of_trust: Option<&'a [u8]>,
    present_id_mask: u16,
    system_patch: Option<i32>,
    vendor_patch: Option<i32>,
    boot_patch: Option<i32>,
}

type BootDigests = (Option<[u8; 32]>, Option<[u8; 32]>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateInspection {
    pub captured_patch_levels: CapturedPatchLevels,
    pub present_id_mask: u16,
    pub supports_module_hash: bool,
    pub original_boot_key: Option<[u8; 32]>,
    pub original_boot_hash: Option<[u8; 32]>,
    pub attestation_security_level: SecurityLevel,
    pub keymint_security_level: SecurityLevel,
}

pub fn inspect_certificate(leaf_der: &[u8]) -> Result<CertificateInspection, Error> {
    if leaf_der.is_empty() || leaf_der.len() > MAX_CERTIFICATE_DER_BYTES {
        return Err(Error::Bounds);
    }
    let cert_seq = parse_any(leaf_der)?;
    if cert_seq.tag() != Tag::Sequence {
        return Err(Error::InvalidCertificate);
    }
    let mut cert_iter = TlvIterator::new(cert_seq.value());
    let tbs_der = cert_iter.next().ok_or(Error::InvalidCertificate)??;
    let algo_der = cert_iter.next().ok_or(Error::InvalidCertificate)??;
    let sig_der = cert_iter.next().ok_or(Error::InvalidCertificate)??;
    if cert_iter.next().is_some()
        || parse_any(algo_der)?.tag() != Tag::Sequence
        || parse_any(sig_der)?.tag() != Tag::BitString
    {
        return Err(Error::InvalidCertificate);
    }

    let tbs_seq = parse_any(tbs_der)?;
    if tbs_seq.tag() != Tag::Sequence {
        return Err(Error::InvalidCertificate);
    }
    let mut tbs_iter = TlvIterator::new(tbs_seq.value());
    let version = tbs_iter.next().ok_or(Error::InvalidCertificate)??;
    validate_v3_version(version)?;
    let serial = tbs_iter.next().ok_or(Error::InvalidCertificate)??;
    let tbs_algorithm = tbs_iter.next().ok_or(Error::InvalidCertificate)??;
    let issuer = tbs_iter.next().ok_or(Error::InvalidCertificate)??;
    let validity = tbs_iter.next().ok_or(Error::InvalidCertificate)??;
    let subject = tbs_iter.next().ok_or(Error::InvalidCertificate)??;
    let spki = tbs_iter.next().ok_or(Error::InvalidCertificate)??;
    if parse_any(serial)?.tag() != Tag::Integer
        || parse_any(tbs_algorithm)?.tag() != Tag::Sequence
        || parse_any(issuer)?.tag() != Tag::Sequence
        || parse_any(validity)?.tag() != Tag::Sequence
        || parse_any(subject)?.tag() != Tag::Sequence
        || parse_any(spki)?.tag() != Tag::Sequence
        || tbs_algorithm != algo_der
    {
        return Err(Error::InvalidCertificate);
    }

    let mut issuer_unique_id_seen = false;
    let mut subject_unique_id_seen = false;
    let mut extensions_explicit_der = None;
    for optional in tbs_iter {
        let field = optional?;
        match parse_any(field)?.tag() {
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(1),
            } if !issuer_unique_id_seen
                && !subject_unique_id_seen
                && extensions_explicit_der.is_none() =>
            {
                issuer_unique_id_seen = true;
            }
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(2),
            } if !subject_unique_id_seen && extensions_explicit_der.is_none() => {
                subject_unique_id_seen = true;
            }
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(3),
            } if extensions_explicit_der.is_none() => {
                extensions_explicit_der = Some(field);
            }
            _ => return Err(Error::InvalidCertificate),
        }
    }

    let extensions_explicit_der =
        extensions_explicit_der.ok_or(Error::MissingAttestationExtension)?;
    let extensions_explicit = parse_any(extensions_explicit_der)?;
    let extensions_seq = parse_any(extensions_explicit.value())?;
    if extensions_seq.tag() != Tag::Sequence {
        return Err(Error::InvalidCertificate);
    }

    let mut attestation = None;
    for ext_field in TlvIterator::new(extensions_seq.value()) {
        let ext_der = ext_field?;
        let parsed = parse_extension(ext_der)?;
        let extn_id = parse_any(parsed.id_der)?;
        if extn_id.value() == ANDROID_ATTESTATION_OID_BYTES
            && attestation.replace(parsed.value_bytes).is_some()
        {
            return Err(Error::DuplicateAttestationExtension);
        }
    }
    let extension_der = attestation.ok_or(Error::MissingAttestationExtension)?;
    let outer = AnyRef::from_der(extension_der).map_err(|_| Error::AttestationRewrite)?;
    if outer.tag() != Tag::Sequence {
        return Err(Error::AttestationRewrite);
    }
    let mut kd_iter = TlvIterator::new(outer.value());
    let mut fields: [&[u8]; 8] = [&[]; 8];
    for slot in &mut fields {
        *slot = kd_iter
            .next()
            .ok_or(Error::AttestationRewrite)?
            .map_err(|_| Error::AttestationRewrite)?;
    }
    let mut field_count = 8;
    for extra in kd_iter {
        extra.map_err(|_| Error::AttestationRewrite)?;
        field_count += 1;
        if field_count > MAX_FIELDS {
            return Err(Error::AttestationRewrite);
        }
    }
    let attestation_version = <i32 as attestation_der::Decode>::from_der(fields[0])
        .map_err(|_| Error::AttestationRewrite)?;
    let security_levels = SecurityLevels {
        attestation: decode_security_level(fields[1])?,
        keymint: decode_security_level(fields[3])?,
    };
    let keymint_version = <i32 as attestation_der::Decode>::from_der(fields[2])
        .map_err(|_| Error::AttestationRewrite)?;
    let six = scan_auth_list(fields[SOFTWARE_INDEX])?;
    let seven = scan_auth_list(fields[TEE_INDEX])?;
    if six.root_count + seven.root_count != 1 {
        return Err(Error::AttestationRewrite);
    }
    let captured_patch_levels = CapturedPatchLevels {
        system: combine_patch(six.system_patch, seven.system_patch)?,
        vendor: combine_patch(six.vendor_patch, seven.vendor_patch)?,
        boot: combine_patch(six.boot_patch, seven.boot_patch)?,
    };
    let (root_encoded, present_id_mask) = if six.root_count == 1 {
        (
            six.root_of_trust.ok_or(Error::AttestationRewrite)?,
            six.present_id_mask,
        )
    } else {
        (
            seven.root_of_trust.ok_or(Error::AttestationRewrite)?,
            seven.present_id_mask,
        )
    };
    let (original_boot_key, original_boot_hash) = parse_root_of_trust(root_encoded)?;

    Ok(CertificateInspection {
        captured_patch_levels,
        present_id_mask,
        supports_module_hash: attestation_version >= 400 && keymint_version >= 400,
        original_boot_key,
        original_boot_hash,
        attestation_security_level: security_levels.attestation,
        keymint_security_level: security_levels.keymint,
    })
}

fn decode_security_level(encoded: &[u8]) -> Result<SecurityLevel, Error> {
    let level = AnyRef::from_der(encoded).map_err(|_| Error::AttestationRewrite)?;
    if level.tag() != Tag::Enumerated || level.value().len() != 1 {
        return Err(Error::AttestationRewrite);
    }
    match level.value()[0] {
        0 => Ok(SecurityLevel::Software),
        1 => Ok(SecurityLevel::TrustedEnvironment),
        2 => Ok(SecurityLevel::StrongBox),
        _ => Err(Error::AttestationRewrite),
    }
}

fn scan_auth_list(encoded: &[u8]) -> Result<AuthorizationScan<'_>, Error> {
    let sequence = AnyRef::from_der(encoded).map_err(|_| Error::AttestationRewrite)?;
    if sequence.tag() != Tag::Sequence {
        return Err(Error::AttestationRewrite);
    }
    let mut scan = AuthorizationScan::default();
    let mut tag_count = 0usize;
    for item in TlvIterator::new(sequence.value()) {
        let slice = item.map_err(|_| Error::AttestationRewrite)?;
        tag_count += 1;
        if tag_count > MAX_TAGS {
            return Err(Error::AttestationRewrite);
        }
        let any = AnyRef::from_der(slice).map_err(|_| Error::AttestationRewrite)?;
        let tag = match any.tag() {
            Tag::ContextSpecific {
                constructed: true,
                number,
            } => number.value(),
            _ => return Err(Error::AttestationRewrite),
        };
        match tag {
            ROOT_OF_TRUST_TAG => {
                scan.root_count += 1;
                scan.root_of_trust = Some(slice);
            }
            SYSTEM_PATCH_TAG => {
                scan.system_patch = merge_patch(scan.system_patch, decode_explicit_i32(slice)?)?;
            }
            VENDOR_PATCH_TAG => {
                scan.vendor_patch = merge_patch(scan.vendor_patch, decode_explicit_i32(slice)?)?;
            }
            BOOT_PATCH_TAG => {
                scan.boot_patch = merge_patch(scan.boot_patch, decode_explicit_i32(slice)?)?;
            }
            _ => {}
        }
        if let Some(index) = ID_TAGS.iter().position(|candidate| candidate == &tag) {
            scan.present_id_mask |= 1u16 << index;
        }
    }
    Ok(scan)
}

fn decode_explicit_i32(encoded: &[u8]) -> Result<i32, Error> {
    let outer = AnyRef::from_der(encoded).map_err(|_| Error::AttestationRewrite)?;
    if !matches!(
        outer.tag(),
        Tag::ContextSpecific {
            constructed: true,
            ..
        }
    ) {
        return Err(Error::AttestationRewrite);
    }
    <i32 as AttestationDecode>::from_der(outer.value()).map_err(|_| Error::AttestationRewrite)
}

fn merge_patch(current: Option<i32>, parsed: i32) -> Result<Option<i32>, Error> {
    match current {
        Some(value) if value != parsed => Err(Error::AttestationRewrite),
        Some(value) => Ok(Some(value)),
        None => Ok(Some(parsed)),
    }
}

fn combine_patch(left: Option<i32>, right: Option<i32>) -> Result<Option<i32>, Error> {
    match (left, right) {
        (Some(a), Some(b)) if a != b => Err(Error::AttestationRewrite),
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn parse_root_of_trust(encoded: &[u8]) -> Result<BootDigests, Error> {
    let outer = AnyRef::from_der(encoded).map_err(|_| Error::AttestationRewrite)?;
    let sequence = AnyRef::from_der(outer.value()).map_err(|_| Error::AttestationRewrite)?;
    if sequence.tag() != Tag::Sequence {
        return Err(Error::AttestationRewrite);
    }
    let mut rot_iter = TlvIterator::new(sequence.value());
    let field0 = rot_iter
        .next()
        .ok_or(Error::AttestationRewrite)?
        .map_err(|_| Error::AttestationRewrite)?;
    let field1 = rot_iter
        .next()
        .ok_or(Error::AttestationRewrite)?
        .map_err(|_| Error::AttestationRewrite)?;
    let field2 = rot_iter
        .next()
        .ok_or(Error::AttestationRewrite)?
        .map_err(|_| Error::AttestationRewrite)?;
    let field3 = rot_iter
        .next()
        .ok_or(Error::AttestationRewrite)?
        .map_err(|_| Error::AttestationRewrite)?;
    if rot_iter.next().is_some() {
        return Err(Error::AttestationRewrite);
    }
    let key_ref = AnyRef::from_der(field0).map_err(|_| Error::AttestationRewrite)?;
    if key_ref.tag() != Tag::OctetString {
        return Err(Error::AttestationRewrite);
    }
    <bool as AttestationDecode>::from_der(field1).map_err(|_| Error::AttestationRewrite)?;
    let state_ref = AnyRef::from_der(field2).map_err(|_| Error::AttestationRewrite)?;
    if state_ref.tag() != Tag::Enumerated
        || state_ref.value().len() != 1
        || !matches!(state_ref.value()[0], 0..=3)
    {
        return Err(Error::AttestationRewrite);
    }
    let hash_ref = AnyRef::from_der(field3).map_err(|_| Error::AttestationRewrite)?;
    if hash_ref.tag() != Tag::OctetString {
        return Err(Error::AttestationRewrite);
    }
    let key = decode_digest(field0);
    let hash = decode_digest(field3);
    Ok((key, hash))
}

fn decode_digest(encoded: &[u8]) -> Option<[u8; 32]> {
    let value = AnyRef::from_der(encoded).ok()?;
    if value.tag() != Tag::OctetString || value.value().len() != 32 {
        return None;
    }
    let digest: [u8; 32] = value.value().try_into().ok()?;
    (!digest.iter().all(|byte| *byte == 0)).then_some(digest)
}
