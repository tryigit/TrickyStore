// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
use cleverestricky_certificate_core::PreparedIssuer;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

pub const MAX_ATTEST_KEYS: usize = 64;

pub type KeyId = [u8; 32];

struct AttestKeyEntry {
    calling_uid: u32,
    key_id: KeyId,
    issuer: Arc<PreparedIssuer>,
}

#[derive(Default)]
struct AttestKeyStore {
    entries: VecDeque<AttestKeyEntry>,
}

static STORE: OnceLock<Mutex<AttestKeyStore>> = OnceLock::new();

#[allow(dead_code)]
pub fn clear() {
    let store = STORE.get_or_init(|| Mutex::new(AttestKeyStore::default()));
    let mut guard = match store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.entries.clear();
}

#[cfg(test)]
pub(crate) fn reset_for_testing() {
    clear();
    let store = STORE.get_or_init(|| Mutex::new(AttestKeyStore::default()));
    store.clear_poison();
}

pub fn insert_attest_key(calling_uid: u32, key_id: KeyId, issuer: Arc<PreparedIssuer>) {
    let store = STORE.get_or_init(|| Mutex::new(AttestKeyStore::default()));
    let mut guard = match store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some(pos) = guard
        .entries
        .iter()
        .position(|e| e.calling_uid == calling_uid && e.key_id == key_id)
    {
        guard.entries.remove(pos);
    }

    if guard.entries.len() >= MAX_ATTEST_KEYS {
        guard.entries.pop_front();
    }

    guard.entries.push_back(AttestKeyEntry {
        calling_uid,
        key_id,
        issuer,
    });
}

pub fn get_attest_key(calling_uid: u32, key_id: &KeyId) -> Option<Arc<PreparedIssuer>> {
    let store = STORE.get_or_init(|| Mutex::new(AttestKeyStore::default()));
    let mut guard = match store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let pos = guard
        .entries
        .iter()
        .position(|e| e.calling_uid == calling_uid && &e.key_id == key_id)?;

    // LRU touch: remove from current position and move to back
    let entry = guard.entries.remove(pos)?;
    let issuer = Arc::clone(&entry.issuer);
    guard.entries.push_back(entry);
    Some(issuer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleverestricky_certificate_core::{generate_ec_p256_keypair, SigningAlgorithm};

    fn make_test_issuer(name: &[u8]) -> Arc<PreparedIssuer> {
        let keypair = generate_ec_p256_keypair().expect("keypair");
        let issuer = PreparedIssuer::from_subject_and_key(
            name.to_vec(),
            &keypair.private_key_pkcs8_der,
            SigningAlgorithm::EcP256Sha256,
        )
        .expect("prepared issuer");
        Arc::new(issuer)
    }

    #[test]
    fn insert_and_get_with_lru_touch() {
        reset_for_testing();
        let issuer = make_test_issuer(b"test-k1");
        let key_id = [1u8; 32];
        insert_attest_key(1000, key_id, issuer);

        let retrieved = get_attest_key(1000, &key_id).expect("retrieved");
        assert_eq!(retrieved.issuer_name_der(), b"test-k1");

        // Wrong UID returns None
        assert!(get_attest_key(1001, &key_id).is_none());

        // Wrong key_id returns None
        assert!(get_attest_key(1000, &[2u8; 32]).is_none());
    }

    #[test]
    fn distinct_key_ids_with_same_uid_do_not_collide() {
        reset_for_testing();
        let k1 = make_test_issuer(b"same-subject-k1");
        let k2 = make_test_issuer(b"same-subject-k2");
        let id1 = [1u8; 32];
        let id2 = [2u8; 32];

        insert_attest_key(1000, id1, k1);
        insert_attest_key(1000, id2, k2);

        let r1 = get_attest_key(1000, &id1).expect("k1");
        let r2 = get_attest_key(1000, &id2).expect("k2");
        assert_eq!(r1.issuer_name_der(), b"same-subject-k1");
        assert_eq!(r2.issuer_name_der(), b"same-subject-k2");
    }

    #[test]
    fn lru_eviction_at_capacity_64() {
        reset_for_testing();
        for i in 0..64 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            insert_attest_key(1000, id, make_test_issuer(&[i as u8]));
        }

        // All 64 are present
        for i in 0..64 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            assert!(get_attest_key(1000, &id).is_some());
        }

        // Touch key 0 so it becomes MRU (moved to back)
        let mut id0 = [0u8; 32];
        id0[0] = 0;
        assert!(get_attest_key(1000, &id0).is_some());

        // Now insert key 64, which should evict key 1 (the oldest untouched key at front)
        let mut id64 = [0u8; 32];
        id64[0] = 64;
        insert_attest_key(1000, id64, make_test_issuer(b"k64"));

        // Key 0 is still present because it was touched
        assert!(get_attest_key(1000, &id0).is_some());
        // Key 1 was evicted
        let mut id1 = [0u8; 32];
        id1[0] = 1;
        assert!(get_attest_key(1000, &id1).is_none());
        // Key 64 is present
        assert!(get_attest_key(1000, &id64).is_some());
    }

    #[test]
    fn clear_empties_the_store() {
        reset_for_testing();
        let id = [42u8; 32];
        insert_attest_key(1000, id, make_test_issuer(b"clear-me"));
        assert!(get_attest_key(1000, &id).is_some());
        clear();
        assert!(get_attest_key(1000, &id).is_none());
    }

    #[test]
    fn nested_attest_key_flow_never_deadlocks() {
        reset_for_testing();
        // Simulate K1 -> K2 -> K3
        let id1 = [10u8; 32];
        let id2 = [20u8; 32];
        let id3 = [30u8; 32];

        // 1. K1 inserted
        insert_attest_key(1000, id1, make_test_issuer(b"root-attest"));

        // 2. K2 created using K1 (read K1, generate K2, insert K2)
        let parent1 = get_attest_key(1000, &id1).expect("k1");
        assert_eq!(parent1.issuer_name_der(), b"root-attest");
        let k2_issuer = make_test_issuer(b"child-attest");
        // Insertion succeeds without deadlock while holding the cloned Arc of parent1
        insert_attest_key(1000, id2, k2_issuer);

        // 3. K3 created using K2 (read K2, generate K3, insert K3)
        let parent2 = get_attest_key(1000, &id2).expect("k2");
        assert_eq!(parent2.issuer_name_der(), b"child-attest");
        let k3_issuer = make_test_issuer(b"leaf-key");
        insert_attest_key(1000, id3, k3_issuer);

        assert!(get_attest_key(1000, &id1).is_some());
        assert!(get_attest_key(1000, &id2).is_some());
        assert!(get_attest_key(1000, &id3).is_some());
    }
}
