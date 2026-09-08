// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
#![forbid(unsafe_code)]

use attestation_der::asn1::{Any, AnyRef, BitString};
use attestation_der::{Decode as X509Decode, Encode as X509Encode, Tag, TagNumber, Tagged};
use cleverestricky_attestation_core::{
    rewrite_extension, AttestationIdOverride, CapturedPatchLevels, PatchLevels, RewriteRequest,
};
use p256::ecdsa::{
    Signature as EcSignature, SigningKey as EcSigningKey, VerifyingKey as EcVerifyingKey,
};
use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use rsa::pkcs1v15::{
    Signature as RsaSignature, SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey,
};
use rsa::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use rsa_sha2::Sha256 as RsaSha256;
use rsa_signature::{SignatureEncoding as _, Signer as _, Verifier as _};
use signature::{Signer as _, Verifier as _};
use std::fmt;
use x509_cert::spki::ObjectIdentifier;
use x509_cert::Certificate;

pub const MAX_CERTIFICATE_DER_BYTES: usize = 256 * 1024;
pub const MAX_PRIVATE_KEY_DER_BYTES: usize = 3 * MAX_CERTIFICATE_DER_BYTES;
pub const ANDROID_ATTESTATION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");

// Keep these canonical encodings local instead of mixing the spki 0.7 traits used by the
// signing-key crates with the spki 0.8 types used by x509-cert 0.3. They are the two fixed
// algorithms accepted by the certificate wire protocol.
const ECDSA_SHA256_ALGORITHM_DER: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];
const RSA_SHA256_ALGORITHM_DER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
];
const PREPARED_ISSUER_VALIDATION_MESSAGE: &[u8] = b"CleveresTricky prepared issuer validation";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningAlgorithm {
    EcP256Sha256,
    RsaPkcs1Sha256,
}

pub struct CertificateRewriteRequest<'a> {
    pub genuine_leaf_der: &'a [u8],
    pub issuer_certificate_der: &'a [u8],
    pub issuer_private_key_pkcs8: &'a [u8],
    pub signing_algorithm: SigningAlgorithm,
    pub patch_levels: PatchLevels,
    pub id_overrides: &'a [AttestationIdOverride<'a>],
    pub module_hash: Option<&'a [u8]>,
    pub verified_boot_key: &'a [u8; 32],
    pub verified_boot_hash: &'a [u8; 32],
}

pub struct PreparedCertificateRewriteRequest<'a> {
    pub genuine_leaf_der: &'a [u8],
    pub issuer: &'a PreparedIssuer,
    pub patch_levels: PatchLevels,
    pub id_overrides: &'a [AttestationIdOverride<'a>],
    pub module_hash: Option<&'a [u8]>,
    pub verified_boot_key: &'a [u8; 32],
    pub verified_boot_hash: &'a [u8; 32],
}

enum PreparedSigner {
    Ec(EcSigningKey),
    Rsa(Box<RsaSigningKey<RsaSha256>>),
}

/// Keybox-owned issuer state that is expensive to validate but invariant across generated keys.
///
/// Construct this when a keybox is registered, not on the generateKey reply path. The constructor
/// parses the private key and issuer certificate and proves that the key can verify under the issuer
/// SPKI exactly once. Fresh attestation rewrites then perform only the unavoidable genuine-leaf DER
/// rewrite plus one signature operation.
pub struct PreparedIssuer {
    algorithm: SigningAlgorithm,
    issuer_name_der: Vec<u8>,
    signer: PreparedSigner,
}

impl PreparedIssuer {
    pub fn new(
        issuer_certificate_der: &[u8],
        issuer_private_key_pkcs8: &[u8],
        signing_algorithm: SigningAlgorithm,
    ) -> Result<Self, Error> {
        if issuer_certificate_der.is_empty()
            || issuer_certificate_der.len() > MAX_CERTIFICATE_DER_BYTES
            || issuer_private_key_pkcs8.is_empty()
            || issuer_private_key_pkcs8.len() > MAX_PRIVATE_KEY_DER_BYTES
        {
            return Err(Error::Bounds);
        }

        let issuer =
            Certificate::from_der(issuer_certificate_der).map_err(|_| Error::InvalidCertificate)?;
        let issuer_name_der = issuer
            .tbs_certificate()
            .subject()
            .to_der()
            .map_err(|_| Error::Encoding)?;
        let issuer_spki = issuer
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|_| Error::Encoding)?;

        let signer = match signing_algorithm {
            SigningAlgorithm::EcP256Sha256 => {
                let signer = EcSigningKey::from_pkcs8_der(issuer_private_key_pkcs8)
                    .map_err(|_| Error::InvalidPrivateKey)?;
                let verifier = EcVerifyingKey::from_public_key_der(&issuer_spki)
                    .map_err(|_| Error::IssuerKeyMismatch)?;
                let signature: EcSignature = signer
                    .try_sign(PREPARED_ISSUER_VALIDATION_MESSAGE)
                    .map_err(|_| Error::Signature)?;
                verifier
                    .verify(PREPARED_ISSUER_VALIDATION_MESSAGE, &signature)
                    .map_err(|_| Error::IssuerKeyMismatch)?;
                PreparedSigner::Ec(signer)
            }
            SigningAlgorithm::RsaPkcs1Sha256 => {
                let signer = RsaSigningKey::<RsaSha256>::from_pkcs8_der(issuer_private_key_pkcs8)
                    .map_err(|_| Error::InvalidPrivateKey)?;
                let issuer_public = rsa::RsaPublicKey::from_public_key_der(&issuer_spki)
                    .map_err(|_| Error::IssuerKeyMismatch)?;
                let verifier = RsaVerifyingKey::<RsaSha256>::new(issuer_public);
                let signature: RsaSignature = signer
                    .try_sign(PREPARED_ISSUER_VALIDATION_MESSAGE)
                    .map_err(|_| Error::Signature)?;
                verifier
                    .verify(PREPARED_ISSUER_VALIDATION_MESSAGE, &signature)
                    .map_err(|_| Error::IssuerKeyMismatch)?;
                PreparedSigner::Rsa(Box::new(signer))
            }
        };

        Ok(Self {
            algorithm: signing_algorithm,
            issuer_name_der,
            signer,
        })
    }

    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    fn sign_certificate(&self, tbs_der: &[u8], algorithm_der: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.signer {
            PreparedSigner::Ec(signer) => {
                let signature: EcSignature =
                    signer.try_sign(tbs_der).map_err(|_| Error::Signature)?;
                let signature_der = signature.to_der();
                encode_signed_certificate(tbs_der, algorithm_der, signature_der.as_bytes())
            }
            PreparedSigner::Rsa(signer) => {
                let signature: RsaSignature =
                    signer.try_sign(tbs_der).map_err(|_| Error::Signature)?;
                let signature_bytes = signature.to_vec();
                encode_signed_certificate(tbs_der, algorithm_der, &signature_bytes)
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CertificateRewriteResult {
    pub leaf_der: Vec<u8>,
    pub captured_patch_levels: CapturedPatchLevels,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    InvalidCertificate,
    MissingAttestationExtension,
    DuplicateAttestationExtension,
    AttestationRewrite,
    InvalidPrivateKey,
    IssuerKeyMismatch,
    Signature,
    Encoding,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bounds => "certificate rewrite input exceeds a bounded limit",
            Self::InvalidCertificate => "certificate DER is invalid",
            Self::MissingAttestationExtension => "Android attestation extension is missing",
            Self::DuplicateAttestationExtension => "Android attestation extension is duplicated",
            Self::AttestationRewrite => "Android attestation extension rewrite failed",
            Self::InvalidPrivateKey => "issuer private key is invalid",
            Self::IssuerKeyMismatch => "issuer private key does not match issuer certificate",
            Self::Signature => "certificate signature failed",
            Self::Encoding => "certificate DER encoding failed",
        })
    }
}

impl std::error::Error for Error {}

pub fn rewrite_certificate(
    request: &CertificateRewriteRequest<'_>,
) -> Result<CertificateRewriteResult, Error> {
    validate_bounds(request)?;
    let issuer = PreparedIssuer::new(
        request.issuer_certificate_der,
        request.issuer_private_key_pkcs8,
        request.signing_algorithm,
    )?;
    rewrite_certificate_prepared(&PreparedCertificateRewriteRequest {
        genuine_leaf_der: request.genuine_leaf_der,
        issuer: &issuer,
        patch_levels: request.patch_levels,
        id_overrides: request.id_overrides,
        module_hash: request.module_hash,
        verified_boot_key: request.verified_boot_key,
        verified_boot_hash: request.verified_boot_hash,
    })
}

pub(crate) const ANDROID_ATTESTATION_OID_BYTES: &[u8] =
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11];

pub fn rewrite_certificate_prepared(
    request: &PreparedCertificateRewriteRequest<'_>,
) -> Result<CertificateRewriteResult, Error> {
    if request.genuine_leaf_der.is_empty()
        || request.genuine_leaf_der.len() > MAX_CERTIFICATE_DER_BYTES
    {
        return Err(Error::Bounds);
    }

    let cert_seq = parse_any(request.genuine_leaf_der)?;
    if cert_seq.tag() != Tag::Sequence {
        return Err(Error::InvalidCertificate);
    }
    let mut cert_iter = TlvIterator::new(cert_seq.value());
    let tbs_der = next_required_tlv(&mut cert_iter)?;
    let outer_algorithm_der = next_required_tlv(&mut cert_iter)?;
    let outer_signature_der = next_required_tlv(&mut cert_iter)?;
    if cert_iter.next().is_some()
        || parse_any(outer_algorithm_der)?.tag() != Tag::Sequence
        || parse_any(outer_signature_der)?.tag() != Tag::BitString
    {
        return Err(Error::InvalidCertificate);
    }

    let tbs_seq = parse_any(tbs_der)?;
    if tbs_seq.tag() != Tag::Sequence {
        return Err(Error::InvalidCertificate);
    }
    let mut tbs_iter = TlvIterator::new(tbs_seq.value());
    let version = next_required_tlv(&mut tbs_iter)?;
    validate_v3_version(version)?;
    let serial = next_required_tlv(&mut tbs_iter)?;
    let original_tbs_algorithm = next_required_tlv(&mut tbs_iter)?;
    let original_issuer = next_required_tlv(&mut tbs_iter)?;
    let validity = next_required_tlv(&mut tbs_iter)?;
    let subject = next_required_tlv(&mut tbs_iter)?;
    let spki = next_required_tlv(&mut tbs_iter)?;

    if parse_any(serial)?.tag() != Tag::Integer
        || parse_any(original_tbs_algorithm)?.tag() != Tag::Sequence
        || parse_any(original_issuer)?.tag() != Tag::Sequence
        || parse_any(validity)?.tag() != Tag::Sequence
        || parse_any(subject)?.tag() != Tag::Sequence
        || parse_any(spki)?.tag() != Tag::Sequence
        || original_tbs_algorithm != outer_algorithm_der
    {
        return Err(Error::InvalidCertificate);
    }

    let mut issuer_unique_id = None;
    let mut subject_unique_id = None;
    let mut extensions_explicit_der = None;
    for optional in tbs_iter {
        let field = optional?;
        match parse_any(field)?.tag() {
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(1),
            } if issuer_unique_id.is_none()
                && subject_unique_id.is_none()
                && extensions_explicit_der.is_none() =>
            {
                issuer_unique_id = Some(field);
            }
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(2),
            } if subject_unique_id.is_none() && extensions_explicit_der.is_none() => {
                subject_unique_id = Some(field);
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

    let mut attestation_info = None;
    let mut extension_count = 0usize;
    for ext_field in TlvIterator::new(extensions_seq.value()) {
        let ext_der = ext_field?;
        let parsed = parse_extension(ext_der)?;
        let extn_id = parse_any(parsed.id_der)?;
        if extn_id.value() == ANDROID_ATTESTATION_OID_BYTES {
            if attestation_info.is_some() {
                return Err(Error::DuplicateAttestationExtension);
            }
            attestation_info = Some((
                extension_count,
                parsed.id_der,
                parsed.critical_der,
                parsed.value_bytes,
            ));
        }
        extension_count = extension_count
            .checked_add(1)
            .ok_or(Error::InvalidCertificate)?;
    }

    let (index, id_der, critical_der, extn_value) =
        attestation_info.ok_or(Error::MissingAttestationExtension)?;

    let rewritten = rewrite_extension(&RewriteRequest {
        extension_der: extn_value,
        patch_levels: request.patch_levels,
        id_overrides: request.id_overrides,
        module_hash: request.module_hash,
        verified_boot_key: request.verified_boot_key,
        verified_boot_hash: request.verified_boot_hash,
    })
    .map_err(|_| Error::AttestationRewrite)?;

    let new_extn_value_der = Any::new(Tag::OctetString, rewritten.extension_der)
        .map_err(|_| Error::Encoding)?
        .to_der()
        .map_err(|_| Error::Encoding)?;

    let new_ext = match critical_der {
        Some(crit) => encode_sequence(&[id_der, crit, &new_extn_value_der])?,
        None => encode_sequence(&[id_der, &new_extn_value_der])?,
    };

    let new_extensions_seq =
        encode_sequence_replacing_tlv(extensions_seq.value(), index, &new_ext)?;
    let new_extensions_explicit = encode_explicit(3, &new_extensions_seq)?;

    let algorithm_der = signature_algorithm_der(request.issuer.algorithm());
    let mut tbs_out: [&[u8]; 10] = [&[]; 10];
    let mut tbs_len = 0usize;
    tbs_out[tbs_len] = version;
    tbs_len += 1;
    tbs_out[tbs_len] = serial;
    tbs_len += 1;
    tbs_out[tbs_len] = algorithm_der;
    tbs_len += 1;
    tbs_out[tbs_len] = &request.issuer.issuer_name_der;
    tbs_len += 1;
    tbs_out[tbs_len] = validity;
    tbs_len += 1;
    tbs_out[tbs_len] = subject;
    tbs_len += 1;
    tbs_out[tbs_len] = spki;
    tbs_len += 1;
    if let Some(uid) = issuer_unique_id {
        tbs_out[tbs_len] = uid;
        tbs_len += 1;
    }
    if let Some(uid) = subject_unique_id {
        tbs_out[tbs_len] = uid;
        tbs_len += 1;
    }
    tbs_out[tbs_len] = &new_extensions_explicit;
    tbs_len += 1;

    let tbs_der = encode_sequence(&tbs_out[..tbs_len])?;

    let leaf_der = request.issuer.sign_certificate(&tbs_der, algorithm_der)?;
    if leaf_der.len() > MAX_CERTIFICATE_DER_BYTES {
        return Err(Error::Bounds);
    }
    Ok(CertificateRewriteResult {
        leaf_der,
        captured_patch_levels: rewritten.captured_patch_levels,
    })
}

fn validate_bounds(request: &CertificateRewriteRequest<'_>) -> Result<(), Error> {
    if request.genuine_leaf_der.is_empty()
        || request.genuine_leaf_der.len() > MAX_CERTIFICATE_DER_BYTES
        || request.issuer_certificate_der.is_empty()
        || request.issuer_certificate_der.len() > MAX_CERTIFICATE_DER_BYTES
        || request.issuer_private_key_pkcs8.is_empty()
        || request.issuer_private_key_pkcs8.len() > MAX_PRIVATE_KEY_DER_BYTES
    {
        return Err(Error::Bounds);
    }
    Ok(())
}

fn signature_algorithm_der(algorithm: SigningAlgorithm) -> &'static [u8] {
    match algorithm {
        SigningAlgorithm::EcP256Sha256 => ECDSA_SHA256_ALGORITHM_DER,
        SigningAlgorithm::RsaPkcs1Sha256 => RSA_SHA256_ALGORITHM_DER,
    }
}

pub(crate) fn parse_any(encoded: &[u8]) -> Result<AnyRef<'_>, Error> {
    X509Decode::from_der(encoded).map_err(|_| Error::InvalidCertificate)
}

pub(crate) fn validate_v3_version(version_der: &[u8]) -> Result<(), Error> {
    let version_explicit = parse_any(version_der)?;
    if !matches!(
        version_explicit.tag(),
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber(0),
        }
    ) {
        return Err(Error::InvalidCertificate);
    }
    let version = parse_any(version_explicit.value())?;
    if version.tag() != Tag::Integer || version.value() != [2] {
        return Err(Error::InvalidCertificate);
    }
    Ok(())
}

pub(crate) struct ParsedExtension<'a> {
    pub(crate) id_der: &'a [u8],
    pub(crate) critical_der: Option<&'a [u8]>,
    pub(crate) value_bytes: &'a [u8],
}

pub(crate) fn parse_extension(ext_der: &[u8]) -> Result<ParsedExtension<'_>, Error> {
    let ext_seq = parse_any(ext_der)?;
    if ext_seq.tag() != Tag::Sequence {
        return Err(Error::InvalidCertificate);
    }

    let mut ext_iter = TlvIterator::new(ext_seq.value());
    let id_der = ext_iter.next().ok_or(Error::InvalidCertificate)??;
    let extn_id = parse_any(id_der)?;
    if extn_id.tag() != Tag::ObjectIdentifier {
        return Err(Error::InvalidCertificate);
    }

    let second_der = ext_iter.next().ok_or(Error::InvalidCertificate)??;
    let second_any = parse_any(second_der)?;

    let (critical_der, value_any) = match ext_iter.next() {
        Some(third_res) => {
            let third_der = third_res?;
            if second_any.tag() != Tag::Boolean {
                return Err(Error::InvalidCertificate);
            }
            let third_any = parse_any(third_der)?;
            if third_any.tag() != Tag::OctetString {
                return Err(Error::InvalidCertificate);
            }
            if ext_iter.next().is_some() {
                return Err(Error::InvalidCertificate);
            }
            (Some(second_der), third_any)
        }
        None => {
            if second_any.tag() != Tag::OctetString {
                return Err(Error::InvalidCertificate);
            }
            (None, second_any)
        }
    };

    Ok(ParsedExtension {
        id_der,
        critical_der,
        value_bytes: value_any.value(),
    })
}

pub(crate) struct TlvIterator<'a> {
    remaining: &'a [u8],
}

impl<'a> TlvIterator<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
}

impl<'a> Iterator for TlvIterator<'a> {
    type Item = Result<&'a [u8], Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        match <AnyRef<'a> as X509Decode>::from_der_partial(self.remaining) {
            Ok((_, rest)) => {
                let consumed = match self.remaining.len().checked_sub(rest.len()) {
                    Some(c) if c > 0 => c,
                    _ => {
                        self.remaining = &[];
                        return Some(Err(Error::InvalidCertificate));
                    }
                };
                let slice = &self.remaining[..consumed];
                self.remaining = rest;
                Some(Ok(slice))
            }
            Err(_) => {
                self.remaining = &[];
                Some(Err(Error::InvalidCertificate))
            }
        }
    }
}

fn next_required_tlv<'a>(iter: &mut TlvIterator<'a>) -> Result<&'a [u8], Error> {
    match iter.next() {
        Some(field) => field,
        None => Err(Error::InvalidCertificate),
    }
}

fn encode_sequence_replacing_tlv(
    encoded_fields: &[u8],
    target_index: usize,
    replacement: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut total_len = 0usize;
    let mut field_count = 0usize;
    for field in TlvIterator::new(encoded_fields) {
        let field = field?;
        let field_len = if field_count == target_index {
            replacement.len()
        } else {
            field.len()
        };
        total_len = total_len.checked_add(field_len).ok_or(Error::Encoding)?;
        field_count = field_count
            .checked_add(1)
            .ok_or(Error::InvalidCertificate)?;
    }
    if target_index >= field_count || total_len > MAX_CERTIFICATE_DER_BYTES {
        return Err(Error::Bounds);
    }

    let mut encoded = Vec::with_capacity(total_len + 5);
    encoded.push(0x30);
    push_der_length(&mut encoded, total_len)?;
    for (index, field) in TlvIterator::new(encoded_fields).enumerate() {
        let field = field?;
        encoded.extend_from_slice(if index == target_index {
            replacement
        } else {
            field
        });
    }
    Ok(encoded)
}

fn push_der_length(encoded: &mut Vec<u8>, total_len: usize) -> Result<(), Error> {
    if total_len > MAX_CERTIFICATE_DER_BYTES {
        return Err(Error::Bounds);
    }
    if total_len < 128 {
        encoded.push(total_len as u8);
    } else if total_len <= 0xff {
        encoded.push(0x81);
        encoded.push(total_len as u8);
    } else if total_len <= 0xffff {
        encoded.push(0x82);
        encoded.push((total_len >> 8) as u8);
        encoded.push((total_len & 0xff) as u8);
    } else {
        encoded.push(0x83);
        encoded.push((total_len >> 16) as u8);
        encoded.push(((total_len >> 8) & 0xff) as u8);
        encoded.push((total_len & 0xff) as u8);
    }
    Ok(())
}

fn encode_explicit(tag: u32, inner: &[u8]) -> Result<Vec<u8>, Error> {
    let total_len = inner.len();
    if total_len > MAX_CERTIFICATE_DER_BYTES {
        return Err(Error::Bounds);
    }
    let mut encoded = Vec::with_capacity(total_len + 6);
    if tag < 31 {
        encoded.push(0x80 | 0x20 | (tag as u8));
    } else {
        return Any::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(tag),
            },
            inner.to_vec(),
        )
        .map_err(|_| Error::Encoding)?
        .to_der()
        .map_err(|_| Error::Encoding);
    }
    push_der_length(&mut encoded, total_len)?;
    encoded.extend_from_slice(inner);
    Ok(encoded)
}

fn encode_sequence(fields: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let mut total_len = 0usize;
    for field in fields {
        total_len = total_len.checked_add(field.len()).ok_or(Error::Encoding)?;
    }
    if total_len > MAX_CERTIFICATE_DER_BYTES {
        return Err(Error::Bounds);
    }
    let mut encoded = Vec::with_capacity(total_len + 5);
    encoded.push(0x30);
    push_der_length(&mut encoded, total_len)?;
    for field in fields {
        encoded.extend_from_slice(field);
    }
    Ok(encoded)
}

fn encode_signed_certificate(
    tbs_der: &[u8],
    algorithm_der: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, Error> {
    let signature = BitString::from_bytes(signature)
        .map_err(|_| Error::Encoding)?
        .to_der()
        .map_err(|_| Error::Encoding)?;
    encode_sequence(&[tbs_der, algorithm_der, &signature])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_sequence_and_explicit_length_boundaries() {
        let zero = encode_sequence(&[]).unwrap();
        assert_eq!(zero, &[0x30, 0x00]);

        let payload_127 = vec![0x11; 127];
        let seq_127 = encode_sequence(&[&payload_127]).unwrap();
        assert_eq!(&seq_127[..2], &[0x30, 0x7f]);
        assert_eq!(&seq_127[2..], payload_127.as_slice());

        let payload_128 = vec![0x22; 128];
        let seq_128 = encode_sequence(&[&payload_128]).unwrap();
        assert_eq!(&seq_128[..3], &[0x30, 0x81, 0x80]);
        assert_eq!(&seq_128[3..], payload_128.as_slice());

        let payload_255 = vec![0x33; 255];
        let seq_255 = encode_sequence(&[&payload_255]).unwrap();
        assert_eq!(&seq_255[..3], &[0x30, 0x81, 0xff]);
        assert_eq!(&seq_255[3..], payload_255.as_slice());

        let payload_256 = vec![0x44; 256];
        let seq_256 = encode_sequence(&[&payload_256]).unwrap();
        assert_eq!(&seq_256[..4], &[0x30, 0x82, 0x01, 0x00]);
        assert_eq!(&seq_256[4..], payload_256.as_slice());

        let payload_65535 = vec![0x55; 65535];
        let seq_65535 = encode_sequence(&[&payload_65535]).unwrap();
        assert_eq!(&seq_65535[..4], &[0x30, 0x82, 0xff, 0xff]);
        assert_eq!(&seq_65535[4..], payload_65535.as_slice());

        let payload_65536 = vec![0x66; 65536];
        let seq_65536 = encode_sequence(&[&payload_65536]).unwrap();
        assert_eq!(&seq_65536[..5], &[0x30, 0x83, 0x01, 0x00, 0x00]);
        assert_eq!(&seq_65536[5..], payload_65536.as_slice());

        let payload_max = vec![0x77; MAX_CERTIFICATE_DER_BYTES];
        let seq_max = encode_sequence(&[&payload_max]).unwrap();
        assert_eq!(&seq_max[..5], &[0x30, 0x83, 0x04, 0x00, 0x00]);
        assert_eq!(&seq_max[5..], payload_max.as_slice());

        let payload_over = vec![0x88; MAX_CERTIFICATE_DER_BYTES + 1];
        assert_eq!(encode_sequence(&[&payload_over]), Err(Error::Bounds));

        // Test encode_explicit (tag < 31)
        let exp_0 = encode_explicit(3, &[]).unwrap();
        assert_eq!(exp_0, &[0xa3, 0x00]);

        let exp_127 = encode_explicit(3, &payload_127).unwrap();
        assert_eq!(&exp_127[..2], &[0xa3, 0x7f]);
        assert_eq!(&exp_127[2..], payload_127.as_slice());

        let exp_128 = encode_explicit(3, &payload_128).unwrap();
        assert_eq!(&exp_128[..3], &[0xa3, 0x81, 0x80]);
        assert_eq!(&exp_128[3..], payload_128.as_slice());

        let exp_256 = encode_explicit(3, &payload_256).unwrap();
        assert_eq!(&exp_256[..4], &[0xa3, 0x82, 0x01, 0x00]);
        assert_eq!(&exp_256[4..], payload_256.as_slice());

        let exp_65536 = encode_explicit(3, &payload_65536).unwrap();
        assert_eq!(&exp_65536[..5], &[0xa3, 0x83, 0x01, 0x00, 0x00]);
        assert_eq!(&exp_65536[5..], payload_65536.as_slice());

        let exp_max = encode_explicit(3, &payload_max).unwrap();
        assert_eq!(&exp_max[..5], &[0xa3, 0x83, 0x04, 0x00, 0x00]);
        assert_eq!(&exp_max[5..], payload_max.as_slice());

        assert_eq!(encode_explicit(3, &payload_over), Err(Error::Bounds));

        // Test encode_explicit (tag >= 31, uses Any::new)
        let exp_high = encode_explicit(31, &[0x01, 0x02]).unwrap();
        assert_eq!(&exp_high[..3], &[0xbf, 0x1f, 0x02]);
        assert_eq!(&exp_high[3..], &[0x01, 0x02]);
    }
}
