use crate::core::{Error, GeneratedEcKeypair};
use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
use p256::SecretKey as P256SecretKey;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const DERIVATION_DOMAIN: &[u8] = b"CleveresTricky deterministic attest signer scalar v1\0";
const MAX_SCALAR_ATTEMPTS: u32 = 16;

/// Deterministically maps a secret 32-byte seed to a valid P-256 keypair.
///
/// The seed is expected to be derived from backend-only secret material. This helper intentionally
/// performs only the scalar mapping so certificate-policy code never needs direct access to p256
/// internals. The private key remains wrapped in `Zeroizing` and never crosses the Rust backend
/// boundary.
pub fn derive_ec_p256_keypair(seed: &[u8; 32]) -> Result<GeneratedEcKeypair, Error> {
    for counter in 0..MAX_SCALAR_ATTEMPTS {
        let mut hash = Sha256::new();
        hash.update(DERIVATION_DOMAIN);
        hash.update(seed);
        hash.update(counter.to_be_bytes());
        let mut scalar: [u8; 32] = hash.finalize().into();

        let secret_key = match P256SecretKey::from_slice(&scalar) {
            Ok(secret_key) => secret_key,
            Err(_) => {
                scalar.zeroize();
                continue;
            }
        };
        scalar.zeroize();

        let pkcs8 = secret_key.to_pkcs8_der().map_err(|_| Error::Encoding)?;
        let spki = secret_key
            .public_key()
            .to_public_key_der()
            .map_err(|_| Error::Encoding)?;
        return Ok(GeneratedEcKeypair {
            public_key_spki_der: spki.as_bytes().to_vec(),
            private_key_pkcs8_der: Zeroizing::new(pkcs8.as_bytes().to_vec()),
        });
    }

    Err(Error::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_derives_same_keypair() {
        let seed = [0x42; 32];
        let first = derive_ec_p256_keypair(&seed).unwrap();
        let second = derive_ec_p256_keypair(&seed).unwrap();
        assert_eq!(first.public_key_spki_der, second.public_key_spki_der);
        assert_eq!(
            first.private_key_pkcs8_der.as_slice(),
            second.private_key_pkcs8_der.as_slice()
        );
    }

    #[test]
    fn distinct_seeds_derive_distinct_public_keys() {
        let first = derive_ec_p256_keypair(&[0x11; 32]).unwrap();
        let second = derive_ec_p256_keypair(&[0x22; 32]).unwrap();
        assert_ne!(first.public_key_spki_der, second.public_key_spki_der);
    }
}
