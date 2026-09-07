// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
#![forbid(unsafe_code)]

use der::asn1::{Any, AnyRef};
use der::{Decode, Encode, Tag, TagNumber, Tagged};
use std::fmt;

pub const MAX_ATTESTATION_EXTENSION_BYTES: usize = 64 * 1024;
pub const MAX_AUTHORIZATION_TAGS: usize = 256;
pub const MAX_ATTESTATION_ID_BYTES: usize = 4 * 1024;
pub const MAX_MODULE_HASH_BYTES: usize = 1024;
const MAX_KEY_DESCRIPTION_FIELDS: usize = 16;
const AUTHORIZATION_LIST_SOFTWARE_INDEX: usize = 6;
const AUTHORIZATION_LIST_TEE_INDEX: usize = 7;
const ROOT_OF_TRUST_TAG: u32 = 704;
const SYSTEM_PATCH_TAG: u32 = 706;
const VENDOR_PATCH_TAG: u32 = 718;
const BOOT_PATCH_TAG: u32 = 719;
const MODULE_HASH_TAG: u32 = 724;
const ATTESTATION_ID_TAGS: [u32; 9] = [710, 711, 712, 713, 714, 715, 716, 717, 723];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchDisposition {
    Keep,
    Omit,
    Replace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PatchComponent {
    pub disposition: PatchDisposition,
    pub value: i32,
}

impl PatchComponent {
    pub const KEEP: Self = Self {
        disposition: PatchDisposition::Keep,
        value: 0,
    };

    pub const OMIT: Self = Self {
        disposition: PatchDisposition::Omit,
        value: 0,
    };

    pub const fn replace(value: i32) -> Self {
        Self {
            disposition: PatchDisposition::Replace,
            value,
        }
    }

    const fn replaces_original(self) -> bool {
        !matches!(self.disposition, PatchDisposition::Keep)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PatchLevels {
    pub system: PatchComponent,
    pub vendor: PatchComponent,
    pub boot: PatchComponent,
}

impl Default for PatchLevels {
    fn default() -> Self {
        Self {
            system: PatchComponent::KEEP,
            vendor: PatchComponent::KEEP,
            boot: PatchComponent::KEEP,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapturedPatchLevels {
    pub system: Option<i32>,
    pub vendor: Option<i32>,
    pub boot: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestationIdOverride<'a> {
    pub tag: u32,
    pub value: &'a [u8],
}

pub struct RewriteRequest<'a> {
    pub extension_der: &'a [u8],
    pub patch_levels: PatchLevels,
    pub id_overrides: &'a [AttestationIdOverride<'a>],
    pub module_hash: Option<&'a [u8]>,
    pub verified_boot_key: &'a [u8; 32],
    pub verified_boot_hash: &'a [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub struct RewriteResult {
    pub extension_der: Vec<u8>,
    pub captured_patch_levels: CapturedPatchLevels,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    Der,
    InvalidStructure,
    ConflictingPatch,
    InvalidOverride,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bounds => "attestation input exceeds a bounded limit",
            Self::Der => "attestation input is not canonical DER",
            Self::InvalidStructure => "attestation record has an invalid structure",
            Self::ConflictingPatch => "attestation record has conflicting patch levels",
            Self::InvalidOverride => "attestation override is invalid",
        })
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Default)]
struct AuthorizationSummary {
    has_root_of_trust: bool,
    system_patch: Option<i32>,
    vendor_patch: Option<i32>,
    boot_patch: Option<i32>,
}

#[derive(Clone, Debug)]
struct TaggedTlv<'a> {
    tag: u32,
    encoded: std::borrow::Cow<'a, [u8]>,
}

pub fn rewrite_extension(request: &RewriteRequest<'_>) -> Result<RewriteResult, Error> {
    validate_request(request)?;
    let outer = parse_any(request.extension_der)?;
    if outer.tag() != Tag::Sequence {
        return Err(Error::InvalidStructure);
    }
    let raw_fields = split_tlvs(outer.value(), MAX_KEY_DESCRIPTION_FIELDS)?;
    if raw_fields.len() <= AUTHORIZATION_LIST_TEE_INDEX {
        return Err(Error::InvalidStructure);
    }

    let attestation_version = decode_i32(raw_fields[0])?;
    let attestation_level = decode_security_level(raw_fields[1])?;
    let keymint_version = decode_i32(raw_fields[2])?;
    let keymint_level = decode_security_level(raw_fields[3])?;
    let supports_module_hash = attestation_version >= 400 && keymint_version >= 400;

    let valid_hardware = matches!((attestation_level, keymint_level), (1, 1) | (2, 2) | (1, 2));
    if !valid_hardware {
        return Err(Error::InvalidStructure);
    }

    let list_six = parse_authorization_list(raw_fields[AUTHORIZATION_LIST_SOFTWARE_INDEX])?;
    let list_seven = parse_authorization_list(raw_fields[AUTHORIZATION_LIST_TEE_INDEX])?;
    let summary_six = summarize_authorization_list(&list_six)?;
    let summary_seven = summarize_authorization_list(&list_seven)?;

    // Android attestation has one hardware authorization list carrying RootOfTrust. Accept the
    // historical list-order variance already supported here, but reject missing/ambiguous roots
    // instead of manufacturing a hardware statement in the compatibility layer.
    if summary_six.has_root_of_trust == summary_seven.has_root_of_trust {
        return Err(Error::InvalidStructure);
    }
    let tee_index = if summary_six.has_root_of_trust {
        AUTHORIZATION_LIST_SOFTWARE_INDEX
    } else {
        AUTHORIZATION_LIST_TEE_INDEX
    };
    let software_index = if tee_index == AUTHORIZATION_LIST_SOFTWARE_INDEX {
        AUTHORIZATION_LIST_TEE_INDEX
    } else {
        AUTHORIZATION_LIST_SOFTWARE_INDEX
    };
    let (tee_original, tee_summary, software_original, software_summary) =
        if tee_index == AUTHORIZATION_LIST_SOFTWARE_INDEX {
            (list_six, summary_six, list_seven, summary_seven)
        } else {
            (list_seven, summary_seven, list_six, summary_six)
        };

    let captured = CapturedPatchLevels {
        system: combine_patch(tee_summary.system_patch, software_summary.system_patch)?,
        vendor: combine_patch(tee_summary.vendor_patch, software_summary.vendor_patch)?,
        boot: combine_patch(tee_summary.boot_patch, software_summary.boot_patch)?,
    };

    let mut tee = Vec::with_capacity(tee_original.len().saturating_add(8));
    let mut software = Vec::with_capacity(software_original.len().saturating_add(4));
    let mut original_module_hash: Option<TaggedTlv<'_>> = None;
    let mut pending_ids = Vec::new();

    let mut sorted_overrides = request.id_overrides.to_vec();
    sorted_overrides.sort_unstable_by_key(|o| o.tag);

    for field in tee_original {
        if field.tag == ROOT_OF_TRUST_TAG {
            continue;
        }
        if field.tag == MODULE_HASH_TAG && supports_module_hash {
            original_module_hash = Some(field);
            continue;
        }
        if should_remove_patch(field.tag, request.patch_levels) {
            continue;
        }
        if is_attestation_id_tag(field.tag) {
            if let Ok(index) = sorted_overrides.binary_search_by_key(&field.tag, |o| o.tag) {
                pending_ids.push(TaggedTlv {
                    tag: field.tag,
                    encoded: std::borrow::Cow::Owned(explicit_octet_string(
                        field.tag,
                        sorted_overrides[index].value,
                    )?),
                });
                continue;
            }
        }
        tee.push(field);
    }

    for field in software_original {
        if field.tag == MODULE_HASH_TAG && supports_module_hash {
            if original_module_hash.is_none() {
                original_module_hash = Some(field);
            }
            continue;
        }
        if should_remove_patch(field.tag, request.patch_levels) {
            continue;
        }
        software.push(field);
    }

    add_patch_tag(
        &mut tee,
        &mut software,
        SYSTEM_PATCH_TAG,
        request.patch_levels.system,
        tee_summary.system_patch.is_some(),
        software_summary.system_patch.is_some(),
    )?;
    add_patch_tag(
        &mut tee,
        &mut software,
        VENDOR_PATCH_TAG,
        request.patch_levels.vendor,
        tee_summary.vendor_patch.is_some(),
        software_summary.vendor_patch.is_some(),
    )?;
    add_patch_tag(
        &mut tee,
        &mut software,
        BOOT_PATCH_TAG,
        request.patch_levels.boot,
        tee_summary.boot_patch.is_some(),
        software_summary.boot_patch.is_some(),
    )?;

    tee.extend(pending_ids);
    if supports_module_hash {
        if let Some(module_hash) = request.module_hash {
            software.push(TaggedTlv {
                tag: MODULE_HASH_TAG,
                encoded: std::borrow::Cow::Owned(explicit_octet_string(
                    MODULE_HASH_TAG,
                    module_hash,
                )?),
            });
        } else if let Some(original) = original_module_hash {
            software.push(original);
        }
    }

    tee.push(TaggedTlv {
        tag: ROOT_OF_TRUST_TAG,
        encoded: std::borrow::Cow::Owned(explicit_root_of_trust(
            request.verified_boot_key,
            request.verified_boot_hash,
        )?),
    });
    tee.sort_by_key(|field| field.tag);
    software.sort_by_key(|field| field.tag);

    let mut fields: Vec<std::borrow::Cow<'_, [u8]>> = raw_fields
        .into_iter()
        .map(std::borrow::Cow::Borrowed)
        .collect();
    fields[tee_index] = std::borrow::Cow::Owned(encode_sequence(
        tee.iter().map(|field| field.encoded.as_ref()),
    )?);
    fields[software_index] = std::borrow::Cow::Owned(encode_sequence(
        software.iter().map(|field| field.encoded.as_ref()),
    )?);
    let extension_der = encode_sequence(fields.iter().map(|f| f.as_ref()))?;
    if extension_der.len() > MAX_ATTESTATION_EXTENSION_BYTES {
        return Err(Error::Bounds);
    }

    Ok(RewriteResult {
        extension_der,
        captured_patch_levels: captured,
    })
}

pub fn inspect_captured_patch_levels(extension_der: &[u8]) -> Result<CapturedPatchLevels, Error> {
    if extension_der.is_empty() || extension_der.len() > MAX_ATTESTATION_EXTENSION_BYTES {
        return Err(Error::Bounds);
    }
    let outer = parse_any(extension_der)?;
    if outer.tag() != Tag::Sequence {
        return Err(Error::InvalidStructure);
    }
    let fields = split_tlvs(outer.value(), MAX_KEY_DESCRIPTION_FIELDS)?;
    if fields.len() <= AUTHORIZATION_LIST_TEE_INDEX {
        return Err(Error::InvalidStructure);
    }
    let list_six = parse_authorization_list(fields[AUTHORIZATION_LIST_SOFTWARE_INDEX])?;
    let list_seven = parse_authorization_list(fields[AUTHORIZATION_LIST_TEE_INDEX])?;
    let summary_six = summarize_authorization_list(&list_six)?;
    let summary_seven = summarize_authorization_list(&list_seven)?;
    if summary_six.has_root_of_trust == summary_seven.has_root_of_trust {
        return Err(Error::InvalidStructure);
    }
    Ok(CapturedPatchLevels {
        system: combine_patch(summary_six.system_patch, summary_seven.system_patch)?,
        vendor: combine_patch(summary_six.vendor_patch, summary_seven.vendor_patch)?,
        boot: combine_patch(summary_six.boot_patch, summary_seven.boot_patch)?,
    })
}

fn validate_request(request: &RewriteRequest<'_>) -> Result<(), Error> {
    if request.extension_der.is_empty()
        || request.extension_der.len() > MAX_ATTESTATION_EXTENSION_BYTES
        || request.id_overrides.len() > ATTESTATION_ID_TAGS.len()
        || request
            .module_hash
            .is_some_and(|value| value.is_empty() || value.len() > MAX_MODULE_HASH_BYTES)
    {
        return Err(Error::Bounds);
    }
    if request.verified_boot_key.iter().all(|byte| *byte == 0)
        || request.verified_boot_hash.iter().all(|byte| *byte == 0)
    {
        return Err(Error::InvalidStructure);
    }
    if [
        request.patch_levels.system,
        request.patch_levels.vendor,
        request.patch_levels.boot,
    ]
    .into_iter()
    .any(|component| component.disposition == PatchDisposition::Replace && component.value <= 0)
    {
        return Err(Error::InvalidOverride);
    }
    let mut seen = [false; ATTESTATION_ID_TAGS.len()];
    for configured in request.id_overrides {
        let Some(index) = ATTESTATION_ID_TAGS
            .iter()
            .position(|tag| *tag == configured.tag)
        else {
            return Err(Error::InvalidOverride);
        };
        if configured.value.is_empty()
            || configured.value.len() > MAX_ATTESTATION_ID_BYTES
            || seen[index]
        {
            return Err(Error::InvalidOverride);
        }
        seen[index] = true;
    }
    Ok(())
}

fn parse_authorization_list<'a>(encoded: &'a [u8]) -> Result<Vec<TaggedTlv<'a>>, Error> {
    let sequence = parse_any(encoded)?;
    if sequence.tag() != Tag::Sequence {
        return Err(Error::InvalidStructure);
    }
    let fields = split_tlvs(sequence.value(), MAX_AUTHORIZATION_TAGS)?;
    fields
        .into_iter()
        .map(|slice| {
            let any = parse_any(slice)?;
            let tag = match any.tag() {
                Tag::ContextSpecific {
                    constructed: true,
                    number,
                } => number.value(),
                _ => return Err(Error::InvalidStructure),
            };
            Ok(TaggedTlv {
                tag,
                encoded: std::borrow::Cow::Borrowed(slice),
            })
        })
        .collect()
}

fn summarize_authorization_list(fields: &[TaggedTlv<'_>]) -> Result<AuthorizationSummary, Error> {
    let mut summary = AuthorizationSummary::default();
    for field in fields {
        match field.tag {
            ROOT_OF_TRUST_TAG => {
                if summary.has_root_of_trust {
                    return Err(Error::InvalidStructure);
                }
                validate_root_of_trust(&field.encoded)?;
                summary.has_root_of_trust = true;
            }
            SYSTEM_PATCH_TAG => {
                summary.system_patch =
                    merge_patch(summary.system_patch, decode_explicit_i32(&field.encoded)?)?
            }
            VENDOR_PATCH_TAG => {
                summary.vendor_patch =
                    merge_patch(summary.vendor_patch, decode_explicit_i32(&field.encoded)?)?
            }
            BOOT_PATCH_TAG => {
                summary.boot_patch =
                    merge_patch(summary.boot_patch, decode_explicit_i32(&field.encoded)?)?
            }
            _ => {}
        }
    }
    Ok(summary)
}

fn merge_patch(current: Option<i32>, parsed: i32) -> Result<Option<i32>, Error> {
    match current {
        Some(value) if value != parsed => Err(Error::ConflictingPatch),
        Some(value) => Ok(Some(value)),
        None => Ok(Some(parsed)),
    }
}

fn combine_patch(tee: Option<i32>, software: Option<i32>) -> Result<Option<i32>, Error> {
    match (tee, software) {
        (Some(left), Some(right)) if left != right => Err(Error::ConflictingPatch),
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn should_remove_patch(tag: u32, levels: PatchLevels) -> bool {
    match tag {
        SYSTEM_PATCH_TAG => levels.system.replaces_original(),
        VENDOR_PATCH_TAG => levels.vendor.replaces_original(),
        BOOT_PATCH_TAG => levels.boot.replaces_original(),
        _ => false,
    }
}

fn add_patch_tag<'a>(
    tee: &mut Vec<TaggedTlv<'a>>,
    software: &mut Vec<TaggedTlv<'a>>,
    tag: u32,
    component: PatchComponent,
    was_tee: bool,
    was_software: bool,
) -> Result<(), Error> {
    if component.disposition != PatchDisposition::Replace || component.value <= 0 {
        return Ok(());
    }
    let encoded = explicit_integer(tag, component.value)?;
    if was_tee || !was_software {
        tee.push(TaggedTlv {
            tag,
            encoded: std::borrow::Cow::Owned(encoded.clone()),
        });
    }
    if was_software {
        software.push(TaggedTlv {
            tag,
            encoded: std::borrow::Cow::Owned(encoded),
        });
    }
    Ok(())
}

fn is_attestation_id_tag(tag: u32) -> bool {
    ATTESTATION_ID_TAGS.contains(&tag)
}

fn decode_i32(encoded: &[u8]) -> Result<i32, Error> {
    i32::from_der(encoded).map_err(|_| Error::InvalidStructure)
}

fn decode_security_level(encoded: &[u8]) -> Result<u8, Error> {
    let level = parse_any(encoded)?;
    if level.tag() != Tag::Enumerated
        || level.value().len() != 1
        || !matches!(level.value()[0], 0..=2)
    {
        return Err(Error::InvalidStructure);
    }
    Ok(level.value()[0])
}

fn decode_explicit_i32(encoded: &[u8]) -> Result<i32, Error> {
    let outer = parse_any(encoded)?;
    match outer.tag() {
        Tag::ContextSpecific {
            constructed: true, ..
        } => i32::from_der(outer.value()).map_err(|_| Error::InvalidStructure),
        _ => Err(Error::InvalidStructure),
    }
}

fn explicit_integer(tag: u32, value: i32) -> Result<Vec<u8>, Error> {
    let inner = value.to_der().map_err(|_| Error::Der)?;
    explicit_tag(tag, &inner)
}

fn explicit_octet_string(tag: u32, value: &[u8]) -> Result<Vec<u8>, Error> {
    let inner = Any::new(Tag::OctetString, value.to_vec())
        .map_err(|_| Error::Bounds)?
        .to_der()
        .map_err(|_| Error::Der)?;
    explicit_tag(tag, &inner)
}

fn validate_root_of_trust(encoded: &[u8]) -> Result<(), Error> {
    let explicit = parse_any(encoded)?;
    let sequence = parse_any(explicit.value())?;
    if sequence.tag() != Tag::Sequence {
        return Err(Error::InvalidStructure);
    }
    let fields = split_tlvs(sequence.value(), 4).map_err(|_| Error::InvalidStructure)?;
    if fields.len() != 4 {
        return Err(Error::InvalidStructure);
    }
    let key = parse_any(fields[0])?;
    if key.tag() != Tag::OctetString {
        return Err(Error::InvalidStructure);
    }
    bool::from_der(fields[1]).map_err(|_| Error::InvalidStructure)?;
    let state = parse_any(fields[2])?;
    if state.tag() != Tag::Enumerated
        || state.value().len() != 1
        || !matches!(state.value()[0], 0..=3)
    {
        return Err(Error::InvalidStructure);
    }
    let hash = parse_any(fields[3])?;
    if hash.tag() != Tag::OctetString {
        return Err(Error::InvalidStructure);
    }
    Ok(())
}

fn explicit_root_of_trust(boot_key: &[u8; 32], boot_hash: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let mut root = vec![0u8; 80];
    root[0..4].copy_from_slice(&[0xbf, 0x85, 0x40, 0x4c]);
    root[4..6].copy_from_slice(&[0x30, 0x4a]);
    root[6..8].copy_from_slice(&[0x04, 0x20]);
    root[8..40].copy_from_slice(boot_key);
    root[40..43].copy_from_slice(&[0x01, 0x01, 0xff]);
    root[43..46].copy_from_slice(&[0x0a, 0x01, 0x00]);
    root[46..48].copy_from_slice(&[0x04, 0x20]);
    root[48..80].copy_from_slice(boot_hash);
    Ok(root)
}

fn explicit_tag(tag: u32, inner_der: &[u8]) -> Result<Vec<u8>, Error> {
    Any::new(
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber(tag),
        },
        inner_der.to_vec(),
    )
    .map_err(|_| Error::Bounds)?
    .to_der()
    .map_err(|_| Error::Der)
}

fn encode_sequence<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Result<Vec<u8>, Error> {
    let mut total_len = 0usize;
    let parts_vec: Vec<&'a [u8]> = parts.into_iter().collect();
    for part in &parts_vec {
        total_len = total_len.checked_add(part.len()).ok_or(Error::Bounds)?;
        if total_len > MAX_ATTESTATION_EXTENSION_BYTES {
            return Err(Error::Bounds);
        }
    }

    let mut encoded = Vec::with_capacity(total_len + 5);
    encoded.push(0x30);
    if total_len < 128 {
        encoded.push(total_len as u8);
    } else if total_len <= 0xff {
        encoded.push(0x81);
        encoded.push(total_len as u8);
    } else if total_len <= 0xffff {
        encoded.push(0x82);
        encoded.push((total_len >> 8) as u8);
        encoded.push((total_len & 0xff) as u8);
    } else if total_len <= MAX_ATTESTATION_EXTENSION_BYTES {
        encoded.push(0x83);
        encoded.push((total_len >> 16) as u8);
        encoded.push(((total_len >> 8) & 0xff) as u8);
        encoded.push((total_len & 0xff) as u8);
    } else {
        return Err(Error::Bounds);
    }
    for part in parts_vec {
        encoded.extend_from_slice(part);
    }
    Ok(encoded)
}

fn parse_any(encoded: &[u8]) -> Result<AnyRef<'_>, Error> {
    AnyRef::from_der(encoded).map_err(|_| Error::Der)
}

fn split_tlvs(mut encoded: &[u8], max_items: usize) -> Result<Vec<&[u8]>, Error> {
    let mut output = Vec::new();
    while !encoded.is_empty() {
        if output.len() >= max_items {
            return Err(Error::Bounds);
        }
        let (_, rest) = AnyRef::from_der_partial(encoded).map_err(|_| Error::Der)?;
        let consumed = encoded.len().checked_sub(rest.len()).ok_or(Error::Der)?;
        if consumed == 0 {
            return Err(Error::Der);
        }
        output.push(&encoded[..consumed]);
        encoded = rest;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT_KEY: [u8; 32] = [0x11; 32];
    const BOOT_HASH: [u8; 32] = [0x22; 32];

    #[test]
    fn rewrites_patch_ids_module_hash_and_root_of_trust() {
        let original_root = root_of_trust_with_state([0x33; 32], false, 2, [0x44; 32]);
        let original_root_tag = explicit_tag_raw(ROOT_OF_TRUST_TAG, &original_root);
        let tee = auth_list([
            original_root_tag,
            explicit_integer_raw(SYSTEM_PATCH_TAG, 202401),
            explicit_integer_raw(VENDOR_PATCH_TAG, 20240205),
            explicit_octet_raw(714, b"old-imei"),
            explicit_octet_raw(MODULE_HASH_TAG, b"old-module"),
        ]);
        let software = auth_list([
            explicit_integer_raw(BOOT_PATCH_TAG, 20240305),
            explicit_octet_raw(711, b"software-device-is-not-overridden"),
        ]);
        let extension = key_description(400, 400, software, tee);
        let ids = [AttestationIdOverride {
            tag: 714,
            value: b"new-imei",
        }];
        let request = RewriteRequest {
            extension_der: &extension,
            patch_levels: PatchLevels {
                system: PatchComponent::replace(202512),
                vendor: PatchComponent::OMIT,
                boot: PatchComponent::replace(20251205),
            },
            id_overrides: &ids,
            module_hash: Some(b"new-module"),
            verified_boot_key: &BOOT_KEY,
            verified_boot_hash: &BOOT_HASH,
        };

        let rewritten = rewrite_extension(&request).unwrap();
        assert_eq!(
            rewritten.captured_patch_levels,
            CapturedPatchLevels {
                system: Some(202401),
                vendor: Some(20240205),
                boot: Some(20240305),
            }
        );
        let (software, tee) = authorization_lists(&rewritten.extension_der);
        assert_eq!(decode_tagged_i32(&tee, SYSTEM_PATCH_TAG), Some(202512));
        assert_eq!(decode_tagged_i32(&tee, VENDOR_PATCH_TAG), None);
        assert_eq!(decode_tagged_i32(&software, BOOT_PATCH_TAG), Some(20251205));
        assert_eq!(decode_tagged_octets(&tee, 714), Some(b"new-imei".to_vec()));
        assert_eq!(
            decode_tagged_octets(&software, 711),
            Some(b"software-device-is-not-overridden".to_vec())
        );
        assert_eq!(
            decode_tagged_octets(&software, MODULE_HASH_TAG),
            Some(b"new-module".to_vec())
        );
        assert_eq!(
            root_of_trust_fields(&tee),
            (BOOT_KEY.to_vec(), true, 0, BOOT_HASH.to_vec())
        );
        assert_sorted(&tee);
        assert_sorted(&software);
    }

    #[test]
    fn keep_preserves_patch_location_and_missing_id_override_is_not_injected() {
        let tee = auth_list([
            explicit_tag_raw(ROOT_OF_TRUST_TAG, &root_of_trust([7; 32], [8; 32])),
            explicit_integer_raw(VENDOR_PATCH_TAG, 20240101),
        ]);
        let software = auth_list([explicit_integer_raw(SYSTEM_PATCH_TAG, 202402)]);
        let extension = key_description(300, 300, software, tee);
        let ids = [AttestationIdOverride {
            tag: 713,
            value: b"serial",
        }];
        let request = RewriteRequest {
            extension_der: &extension,
            patch_levels: PatchLevels::default(),
            id_overrides: &ids,
            module_hash: Some(b"ignored-on-pre-400"),
            verified_boot_key: &BOOT_KEY,
            verified_boot_hash: &BOOT_HASH,
        };

        let rewritten = rewrite_extension(&request).unwrap();
        let (software, tee) = authorization_lists(&rewritten.extension_der);
        assert_eq!(decode_tagged_i32(&software, SYSTEM_PATCH_TAG), Some(202402));
        assert_eq!(decode_tagged_i32(&tee, VENDOR_PATCH_TAG), Some(20240101));
        assert_eq!(decode_tagged_octets(&tee, 713), None);
        assert_eq!(decode_tagged_octets(&software, MODULE_HASH_TAG), None);
    }

    #[test]
    fn preserves_strongbox_security_levels_during_rewrite() {
        let tee = auth_list([
            explicit_tag_raw(ROOT_OF_TRUST_TAG, &root_of_trust([7; 32], [8; 32])),
            explicit_integer_raw(VENDOR_PATCH_TAG, 20240101),
        ]);
        let software = auth_list([explicit_integer_raw(SYSTEM_PATCH_TAG, 202402)]);
        let strongbox = Any::new(Tag::Enumerated, vec![2])
            .unwrap()
            .to_der()
            .unwrap();
        let extension = encode_sequence([
            300i32.to_der().unwrap().as_slice(),
            strongbox.as_slice(),
            300i32.to_der().unwrap().as_slice(),
            strongbox.as_slice(),
            Any::new(Tag::OctetString, Vec::<u8>::new())
                .unwrap()
                .to_der()
                .unwrap()
                .as_slice(),
            Any::new(Tag::OctetString, Vec::<u8>::new())
                .unwrap()
                .to_der()
                .unwrap()
                .as_slice(),
            software.as_slice(),
            tee.as_slice(),
        ])
        .unwrap();

        let request = RewriteRequest {
            extension_der: &extension,
            patch_levels: PatchLevels::default(),
            id_overrides: &[],
            module_hash: None,
            verified_boot_key: &BOOT_KEY,
            verified_boot_hash: &BOOT_HASH,
        };

        let rewritten = rewrite_extension(&request).unwrap();
        let outer = parse_any(&rewritten.extension_der).unwrap();
        let fields = split_tlvs(outer.value(), MAX_KEY_DESCRIPTION_FIELDS).unwrap();
        assert_eq!(fields[1], strongbox.as_slice());
        assert_eq!(fields[3], strongbox.as_slice());
    }

    #[test]
    fn rejects_unknown_attestation_security_level() {
        let tee = auth_list([explicit_tag_raw(
            ROOT_OF_TRUST_TAG,
            &root_of_trust([7; 32], [8; 32]),
        )]);
        let software = auth_list([]);
        let unknown = Any::new(Tag::Enumerated, vec![3])
            .unwrap()
            .to_der()
            .unwrap();
        let trusted = Any::new(Tag::Enumerated, vec![1])
            .unwrap()
            .to_der()
            .unwrap();
        let extension = encode_sequence([
            300i32.to_der().unwrap().as_slice(),
            unknown.as_slice(),
            300i32.to_der().unwrap().as_slice(),
            trusted.as_slice(),
            Any::new(Tag::OctetString, Vec::<u8>::new())
                .unwrap()
                .to_der()
                .unwrap()
                .as_slice(),
            Any::new(Tag::OctetString, Vec::<u8>::new())
                .unwrap()
                .to_der()
                .unwrap()
                .as_slice(),
            software.as_slice(),
            tee.as_slice(),
        ])
        .unwrap();
        let request = RewriteRequest {
            extension_der: &extension,
            patch_levels: PatchLevels::default(),
            id_overrides: &[],
            module_hash: None,
            verified_boot_key: &BOOT_KEY,
            verified_boot_hash: &BOOT_HASH,
        };

        assert_eq!(rewrite_extension(&request), Err(Error::InvalidStructure));
    }

    #[test]
    fn replacement_returns_to_original_lists_and_defaults_to_tee_when_absent() {
        let tee = auth_list([
            explicit_tag_raw(ROOT_OF_TRUST_TAG, &root_of_trust([1; 32], [2; 32])),
            explicit_integer_raw(SYSTEM_PATCH_TAG, 1),
        ]);
        let software = auth_list([explicit_integer_raw(SYSTEM_PATCH_TAG, 1)]);
        let extension = key_description(400, 400, software, tee);
        let request = RewriteRequest {
            extension_der: &extension,
            patch_levels: PatchLevels {
                system: PatchComponent::replace(9),
                vendor: PatchComponent::replace(10),
                boot: PatchComponent::KEEP,
            },
            id_overrides: &[],
            module_hash: None,
            verified_boot_key: &BOOT_KEY,
            verified_boot_hash: &BOOT_HASH,
        };

        let rewritten = rewrite_extension(&request).unwrap();
        let (software, tee) = authorization_lists(&rewritten.extension_der);
        assert_eq!(decode_tagged_i32(&tee, SYSTEM_PATCH_TAG), Some(9));
        assert_eq!(decode_tagged_i32(&software, SYSTEM_PATCH_TAG), Some(9));
        assert_eq!(decode_tagged_i32(&tee, VENDOR_PATCH_TAG), Some(10));
        assert_eq!(decode_tagged_i32(&software, VENDOR_PATCH_TAG), None);
    }

    #[test]
    fn conflicting_patch_levels_fail_closed() {
        let tee = auth_list([
            explicit_tag_raw(ROOT_OF_TRUST_TAG, &root_of_trust([1; 32], [2; 32])),
            explicit_integer_raw(SYSTEM_PATCH_TAG, 202401),
        ]);
        let software = auth_list([explicit_integer_raw(SYSTEM_PATCH_TAG, 202402)]);
        let extension = key_description(400, 400, software, tee);
        let request = RewriteRequest {
            extension_der: &extension,
            patch_levels: PatchLevels::default(),
            id_overrides: &[],
            module_hash: None,
            verified_boot_key: &BOOT_KEY,
            verified_boot_hash: &BOOT_HASH,
        };
        assert_eq!(rewrite_extension(&request), Err(Error::ConflictingPatch));
    }

    #[test]
    fn malformed_der_and_unbounded_inputs_fail_closed() {
        let mut oversized = vec![0u8; MAX_ATTESTATION_EXTENSION_BYTES + 1];
        oversized[0] = 0x30;
        let request = RewriteRequest {
            extension_der: &oversized,
            patch_levels: PatchLevels::default(),
            id_overrides: &[],
            module_hash: None,
            verified_boot_key: &BOOT_KEY,
            verified_boot_hash: &BOOT_HASH,
        };
        assert_eq!(rewrite_extension(&request), Err(Error::Bounds));

        let malformed = [0x30, 0x81, 0x01, 0x00];
        let request = RewriteRequest {
            extension_der: &malformed,
            patch_levels: PatchLevels::default(),
            id_overrides: &[],
            module_hash: None,
            verified_boot_key: &BOOT_KEY,
            verified_boot_hash: &BOOT_HASH,
        };
        assert!(matches!(
            rewrite_extension(&request),
            Err(Error::Der | Error::InvalidStructure)
        ));
    }

    #[test]
    fn duplicate_or_unknown_id_override_is_rejected() {
        let tee = auth_list([explicit_tag_raw(
            ROOT_OF_TRUST_TAG,
            &root_of_trust([1; 32], [2; 32]),
        )]);
        let extension = key_description(400, 400, auth_list([]), tee);
        let duplicate = [
            AttestationIdOverride {
                tag: 714,
                value: b"one",
            },
            AttestationIdOverride {
                tag: 714,
                value: b"two",
            },
        ];
        let request = RewriteRequest {
            extension_der: &extension,
            patch_levels: PatchLevels::default(),
            id_overrides: &duplicate,
            module_hash: None,
            verified_boot_key: &BOOT_KEY,
            verified_boot_hash: &BOOT_HASH,
        };
        assert_eq!(rewrite_extension(&request), Err(Error::InvalidOverride));

        let unknown = [AttestationIdOverride {
            tag: 999,
            value: b"bad",
        }];
        let request = RewriteRequest {
            id_overrides: &unknown,
            ..request
        };
        assert_eq!(rewrite_extension(&request), Err(Error::InvalidOverride));
    }

    #[test]
    fn missing_or_duplicate_root_of_trust_is_rejected() {
        let no_root = key_description(400, 400, auth_list([]), auth_list([]));
        let request = RewriteRequest {
            extension_der: &no_root,
            patch_levels: PatchLevels::default(),
            id_overrides: &[],
            module_hash: None,
            verified_boot_key: &BOOT_KEY,
            verified_boot_hash: &BOOT_HASH,
        };
        assert_eq!(rewrite_extension(&request), Err(Error::InvalidStructure));

        let root = explicit_tag_raw(ROOT_OF_TRUST_TAG, &root_of_trust([1; 32], [2; 32]));
        let duplicate = key_description(400, 400, auth_list([]), auth_list([root.clone(), root]));
        let request = RewriteRequest {
            extension_der: &duplicate,
            ..request
        };
        assert_eq!(rewrite_extension(&request), Err(Error::InvalidStructure));
    }

    #[test]
    fn malformed_root_of_trust_fails_closed() {
        let key = Any::new(Tag::OctetString, [1u8; 32].to_vec())
            .unwrap()
            .to_der()
            .unwrap();
        let verified = true.to_der().unwrap();
        let state = Any::new(Tag::Enumerated, vec![0])
            .unwrap()
            .to_der()
            .unwrap();
        let hash = Any::new(Tag::OctetString, [2u8; 32].to_vec())
            .unwrap()
            .to_der()
            .unwrap();

        // 1. RootOfTrust with 3 fields instead of 4
        let three_fields =
            encode_sequence([key.as_slice(), verified.as_slice(), state.as_slice()]).unwrap();
        let bad_root = explicit_tag_raw(ROOT_OF_TRUST_TAG, &three_fields);
        let ext = key_description(400, 400, auth_list([]), auth_list([bad_root]));
        let request = RewriteRequest {
            extension_der: &ext,
            patch_levels: PatchLevels::default(),
            id_overrides: &[],
            module_hash: None,
            verified_boot_key: &BOOT_KEY,
            verified_boot_hash: &BOOT_HASH,
        };
        assert_eq!(rewrite_extension(&request), Err(Error::InvalidStructure));
        assert_eq!(
            inspect_captured_patch_levels(&ext),
            Err(Error::InvalidStructure)
        );

        // 2. RootOfTrust with non-boolean field 1
        let not_bool = Any::new(Tag::OctetString, vec![1])
            .unwrap()
            .to_der()
            .unwrap();
        let bad_fields = encode_sequence([
            key.as_slice(),
            not_bool.as_slice(),
            state.as_slice(),
            hash.as_slice(),
        ])
        .unwrap();
        let bad_root = explicit_tag_raw(ROOT_OF_TRUST_TAG, &bad_fields);
        let ext = key_description(400, 400, auth_list([]), auth_list([bad_root]));
        let request = RewriteRequest {
            extension_der: &ext,
            ..request
        };
        assert_eq!(rewrite_extension(&request), Err(Error::InvalidStructure));
        assert_eq!(
            inspect_captured_patch_levels(&ext),
            Err(Error::InvalidStructure)
        );

        // 3. RootOfTrust with invalid state enumeration (e.g. 4)
        let invalid_state = Any::new(Tag::Enumerated, vec![4])
            .unwrap()
            .to_der()
            .unwrap();
        let bad_state = encode_sequence([
            key.as_slice(),
            verified.as_slice(),
            invalid_state.as_slice(),
            hash.as_slice(),
        ])
        .unwrap();
        let bad_root = explicit_tag_raw(ROOT_OF_TRUST_TAG, &bad_state);
        let ext = key_description(400, 400, auth_list([]), auth_list([bad_root]));
        let request = RewriteRequest {
            extension_der: &ext,
            ..request
        };
        assert_eq!(rewrite_extension(&request), Err(Error::InvalidStructure));
        assert_eq!(
            inspect_captured_patch_levels(&ext),
            Err(Error::InvalidStructure)
        );
    }

    fn key_description(
        attestation_version: i32,
        keymint_version: i32,
        software: Vec<u8>,
        tee: Vec<u8>,
    ) -> Vec<u8> {
        encode_sequence([
            attestation_version.to_der().unwrap().as_slice(),
            Any::new(Tag::Enumerated, vec![1])
                .unwrap()
                .to_der()
                .unwrap()
                .as_slice(),
            keymint_version.to_der().unwrap().as_slice(),
            Any::new(Tag::Enumerated, vec![1])
                .unwrap()
                .to_der()
                .unwrap()
                .as_slice(),
            Any::new(Tag::OctetString, Vec::<u8>::new())
                .unwrap()
                .to_der()
                .unwrap()
                .as_slice(),
            Any::new(Tag::OctetString, Vec::<u8>::new())
                .unwrap()
                .to_der()
                .unwrap()
                .as_slice(),
            software.as_slice(),
            tee.as_slice(),
        ])
        .unwrap()
    }

    fn auth_list<const N: usize>(fields: [Vec<u8>; N]) -> Vec<u8> {
        encode_sequence(fields.iter().map(Vec::as_slice)).unwrap()
    }

    fn explicit_integer_raw(tag: u32, value: i32) -> Vec<u8> {
        explicit_integer(tag, value).unwrap()
    }

    fn explicit_octet_raw(tag: u32, value: &[u8]) -> Vec<u8> {
        explicit_octet_string(tag, value).unwrap()
    }

    fn explicit_tag_raw(tag: u32, inner: &[u8]) -> Vec<u8> {
        explicit_tag(tag, inner).unwrap()
    }

    fn root_of_trust(key: [u8; 32], hash: [u8; 32]) -> Vec<u8> {
        root_of_trust_with_state(key, true, 0, hash)
    }

    fn root_of_trust_with_state(key: [u8; 32], locked: bool, state: u8, hash: [u8; 32]) -> Vec<u8> {
        let key = Any::new(Tag::OctetString, key.to_vec())
            .unwrap()
            .to_der()
            .unwrap();
        let verified = locked.to_der().unwrap();
        let state = Any::new(Tag::Enumerated, vec![state])
            .unwrap()
            .to_der()
            .unwrap();
        let hash = Any::new(Tag::OctetString, hash.to_vec())
            .unwrap()
            .to_der()
            .unwrap();
        encode_sequence([
            key.as_slice(),
            verified.as_slice(),
            state.as_slice(),
            hash.as_slice(),
        ])
        .unwrap()
    }

    fn authorization_lists(extension: &[u8]) -> (Vec<TaggedTlv<'_>>, Vec<TaggedTlv<'_>>) {
        let outer = parse_any(extension).unwrap();
        let fields = split_tlvs(outer.value(), MAX_KEY_DESCRIPTION_FIELDS).unwrap();
        let six = parse_authorization_list(fields[6]).unwrap();
        let seven = parse_authorization_list(fields[7]).unwrap();
        let six_summary = summarize_authorization_list(&six).unwrap();
        let seven_summary = summarize_authorization_list(&seven).unwrap();
        if six_summary.has_root_of_trust && !seven_summary.has_root_of_trust {
            (seven, six)
        } else {
            (six, seven)
        }
    }

    fn decode_tagged_i32(fields: &[TaggedTlv<'_>], tag: u32) -> Option<i32> {
        fields
            .iter()
            .find(|field| field.tag == tag)
            .map(|field| decode_explicit_i32(&field.encoded).unwrap())
    }

    fn decode_tagged_octets(fields: &[TaggedTlv<'_>], tag: u32) -> Option<Vec<u8>> {
        fields.iter().find(|field| field.tag == tag).map(|field| {
            let outer = parse_any(&field.encoded).unwrap();
            let inner = parse_any(outer.value()).unwrap();
            assert_eq!(inner.tag(), Tag::OctetString);
            inner.value().to_vec()
        })
    }

    fn root_of_trust_fields(tee: &[TaggedTlv<'_>]) -> (Vec<u8>, bool, u8, Vec<u8>) {
        let root = tee
            .iter()
            .find(|field| field.tag == ROOT_OF_TRUST_TAG)
            .unwrap();
        let explicit = parse_any(&root.encoded).unwrap();
        let sequence = parse_any(explicit.value()).unwrap();
        assert_eq!(sequence.tag(), Tag::Sequence);
        let fields = split_tlvs(sequence.value(), 4).unwrap();
        assert_eq!(fields.len(), 4);
        let key = parse_any(fields[0]).unwrap();
        assert_eq!(key.tag(), Tag::OctetString);
        let locked = bool::from_der(fields[1]).unwrap();
        let state = parse_any(fields[2]).unwrap();
        assert_eq!(state.tag(), Tag::Enumerated);
        assert_eq!(state.value().len(), 1);
        let hash = parse_any(fields[3]).unwrap();
        assert_eq!(hash.tag(), Tag::OctetString);
        (
            key.value().to_vec(),
            locked,
            state.value()[0],
            hash.value().to_vec(),
        )
    }

    fn assert_sorted(fields: &[TaggedTlv]) {
        assert!(fields.windows(2).all(|pair| pair[0].tag <= pair[1].tag));
    }
}
