// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
#![forbid(unsafe_code)]

use attestation_der::asn1::{Any, BitString, OctetString};
use attestation_der::{Decode as X509Decode, Encode as X509Encode, Tag, TagNumber};
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
use x509_cert::ext::Extensions;
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

pub fn rewrite_certificate_prepared(
    request: &PreparedCertificateRewriteRequest<'_>,
) -> Result<CertificateRewriteResult, Error> {
    if request.genuine_leaf_der.is_empty()
        || request.genuine_leaf_der.len() > MAX_CERTIFICATE_DER_BYTES
    {
        return Err(Error::Bounds);
    }

    let leaf =
        Certificate::from_der(request.genuine_leaf_der).map_err(|_| Error::InvalidCertificate)?;
    let mut extensions = leaf
        .tbs_certificate()
        .extensions()
        .cloned()
        .ok_or(Error::MissingAttestationExtension)?;
    let mut matching_index = None;
    for (index, extension) in extensions.iter().enumerate() {
        if extension.extn_id == ANDROID_ATTESTATION_OID && matching_index.replace(index).is_some() {
            return Err(Error::DuplicateAttestationExtension);
        }
    }
    let index = matching_index.ok_or(Error::MissingAttestationExtension)?;
    let rewritten = rewrite_extension(&RewriteRequest {
        extension_der: extensions[index].extn_value.as_bytes(),
        patch_levels: request.patch_levels,
        id_overrides: request.id_overrides,
        module_hash: request.module_hash,
        verified_boot_key: request.verified_boot_key,
        verified_boot_hash: request.verified_boot_hash,
    })
    .map_err(|_| Error::AttestationRewrite)?;
    extensions[index].critical = false;
    extensions[index].extn_value =
        OctetString::new(rewritten.extension_der).map_err(|_| Error::Encoding)?;

    let algorithm_der = signature_algorithm_der(request.issuer.algorithm());
    let tbs_der = rebuild_tbs_certificate(
        &leaf,
        &request.issuer.issuer_name_der,
        &extensions,
        algorithm_der,
    )?;
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

const VERSION_V3_DER: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];

fn rebuild_tbs_certificate(
    leaf: &Certificate,
    issuer_name_der: &[u8],
    extensions: &Extensions,
    algorithm_der: &[u8],
) -> Result<Vec<u8>, Error> {
    let leaf_tbs = leaf.tbs_certificate();

    // Match the managed X509v3CertificateBuilder oracle: rebuild from genuine serial, validity,
    // subject, SPKI and extensions; issuer comes from the selected keybox. The managed builder did
    // not preserve issuer/subject unique IDs, so they are intentionally omitted here as well.
    let serial = leaf_tbs
        .serial_number()
        .to_der()
        .map_err(|_| Error::Encoding)?;
    let validity = leaf_tbs.validity().to_der().map_err(|_| Error::Encoding)?;
    let subject = leaf_tbs.subject().to_der().map_err(|_| Error::Encoding)?;
    let spki = leaf_tbs
        .subject_public_key_info()
        .to_der()
        .map_err(|_| Error::Encoding)?;
    let extensions = encode_extensions(extensions)?;
    let extensions = encode_explicit(3, &extensions)?;

    encode_sequence(&[
        VERSION_V3_DER,
        &serial,
        algorithm_der,
        issuer_name_der,
        &validity,
        &subject,
        &spki,
        &extensions,
    ])
}

fn encode_extensions(extensions: &Extensions) -> Result<Vec<u8>, Error> {
    let mut total_len = 0usize;
    let mut encoded_fields = Vec::with_capacity(extensions.len());
    for extension in extensions {
        let field = extension.to_der().map_err(|_| Error::Encoding)?;
        total_len = total_len.checked_add(field.len()).ok_or(Error::Encoding)?;
        encoded_fields.push(field);
    }
    if total_len > MAX_CERTIFICATE_DER_BYTES {
        return Err(Error::Bounds);
    }
    let refs: Vec<&[u8]> = encoded_fields.iter().map(Vec::as_slice).collect();
    encode_sequence(&refs)
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
    if total_len < 128 {
        encoded.push(total_len as u8);
    } else if total_len <= 0xff {
        encoded.push(0x81);
        encoded.push(total_len as u8);
    } else if total_len <= 0xffff {
        encoded.push(0x82);
        encoded.push((total_len >> 8) as u8);
        encoded.push((total_len & 0xff) as u8);
    } else if total_len <= MAX_CERTIFICATE_DER_BYTES {
        encoded.push(0x83);
        encoded.push((total_len >> 16) as u8);
        encoded.push(((total_len >> 8) & 0xff) as u8);
        encoded.push((total_len & 0xff) as u8);
    } else {
        return Err(Error::Encoding);
    }
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
    if total_len < 128 {
        encoded.push(total_len as u8);
    } else if total_len <= 0xff {
        encoded.push(0x81);
        encoded.push(total_len as u8);
    } else if total_len <= 0xffff {
        encoded.push(0x82);
        encoded.push((total_len >> 8) as u8);
        encoded.push((total_len & 0xff) as u8);
    } else if total_len <= MAX_CERTIFICATE_DER_BYTES {
        encoded.push(0x83);
        encoded.push((total_len >> 16) as u8);
        encoded.push(((total_len >> 8) & 0xff) as u8);
        encoded.push((total_len & 0xff) as u8);
    } else {
        return Err(Error::Encoding);
    }
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
