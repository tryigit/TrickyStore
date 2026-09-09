// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
use cleverestricky_certificate_core::PreparedIssuer;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

pub const MAX_ATTEST_KEYS: usize = 64;

pub type KeyId = [u8; 32];

struct AttestKeyEntry {
    calling_uid: u32,
    key_id: KeyId,
    #[allow(dead_code)]
    parent_key_id: Option<KeyId>,
    issuer: Arc<PreparedIssuer>,
}

#[derive(Default)]
struct AttestKeyStore {
    entries: VecDeque<AttestKeyEntry>,
}

impl AttestKeyStore {
    fn subtree_contains(&self, calling_uid: u32, root_key_id: &KeyId, key_id: &KeyId) -> bool {
        let mut to_visit = vec![*root_key_id];
        while let Some(target) = to_visit.pop() {
            if &target == key_id {
                return true;
            }
            to_visit.extend(
                self.entries
                    .iter()
                    .filter(|entry| {
                        entry.calling_uid == calling_uid
                            && entry.parent_key_id.as_ref() == Some(&target)
                    })
                    .map(|entry| entry.key_id),
            );
        }
        false
    }

    fn remove_subtree(&mut self, calling_uid: u32, key_id: &KeyId) -> bool {
        let mut to_remove = vec![*key_id];
        let mut any_removed = false;
        while let Some(target) = to_remove.pop() {
            let children: Vec<KeyId> = self
                .entries
                .iter()
                .filter(|entry| {
                    entry.calling_uid == calling_uid
                        && entry.parent_key_id.as_ref() == Some(&target)
                })
                .map(|entry| entry.key_id)
                .collect();
            to_remove.extend(children);
            let original_len = self.entries.len();
            self.entries
                .retain(|entry| entry.calling_uid != calling_uid || entry.key_id != target);
            any_removed |= self.entries.len() != original_len;
        }
        any_removed
    }

    fn evict_oldest_subtree(&mut self) {
        if let Some(oldest) = self.entries.front() {
            let calling_uid = oldest.calling_uid;
            let key_id = oldest.key_id;
            self.remove_subtree(calling_uid, &key_id);
        }
    }
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

    guard.remove_subtree(calling_uid, &key_id);

    if guard.entries.len() >= MAX_ATTEST_KEYS {
        guard.evict_oldest_subtree();
    }

    guard.entries.push_back(AttestKeyEntry {
        calling_uid,
        key_id,
        parent_key_id: None,
        issuer,
    });
}

pub fn insert_child_attest_key(
    calling_uid: u32,
    parent_key_id: &KeyId,
    child_key_id: KeyId,
    issuer: Arc<PreparedIssuer>,
) -> bool {
    if parent_key_id == &child_key_id {
        return false;
    }
    let store = STORE.get_or_init(|| Mutex::new(AttestKeyStore::default()));
    let mut guard = match store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let parent_pos = guard
        .entries
        .iter()
        .position(|e| e.calling_uid == calling_uid && &e.key_id == parent_key_id);
    let Some(parent_pos) = parent_pos else {
        return false;
    };
    if guard.subtree_contains(calling_uid, &child_key_id, parent_key_id) {
        return false;
    }

    let parent = guard.entries.remove(parent_pos).expect("parent exists");
    guard.entries.push_back(parent);

    guard.remove_subtree(calling_uid, &child_key_id);

    if guard.entries.len() >= MAX_ATTEST_KEYS {
        guard.evict_oldest_subtree();
    }
    if !guard
        .entries
        .iter()
        .any(|entry| entry.calling_uid == calling_uid && &entry.key_id == parent_key_id)
    {
        return false;
    }

    guard.entries.push_back(AttestKeyEntry {
        calling_uid,
        key_id: child_key_id,
        parent_key_id: Some(*parent_key_id),
        issuer,
    });
    true
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

    let entry = guard.entries.remove(pos)?;
    let issuer = Arc::clone(&entry.issuer);
    guard.entries.push_back(entry);
    Some(issuer)
}

#[allow(dead_code)]
pub fn touch_attest_key(calling_uid: u32, key_id: &KeyId) -> bool {
    let store = STORE.get_or_init(|| Mutex::new(AttestKeyStore::default()));
    let mut guard = match store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let pos = match guard
        .entries
        .iter()
        .position(|e| e.calling_uid == calling_uid && &e.key_id == key_id)
    {
        Some(pos) => pos,
        None => return false,
    };

    let entry = guard.entries.remove(pos).expect("entry exists");
    guard.entries.push_back(entry);
    true
}

#[allow(dead_code)]
pub fn remove_attest_key(calling_uid: u32, key_id: &KeyId) -> bool {
    let store = STORE.get_or_init(|| Mutex::new(AttestKeyStore::default()));
    let mut guard = match store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    guard.remove_subtree(calling_uid, key_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleverestricky_certificate_core::{generate_ec_p256_keypair, SigningAlgorithm};
    use std::sync::MutexGuard;

    static TEST_STORE_SEQUENCE: OnceLock<Mutex<()>> = OnceLock::new();

    fn isolate_store_sequence() -> MutexGuard<'static, ()> {
        TEST_STORE_SEQUENCE
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

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
        let _sequence = isolate_store_sequence();
        reset_for_testing();
        let issuer = make_test_issuer(b"test-k1");
        let key_id = [1u8; 32];
        insert_attest_key(1000, key_id, issuer);

        let retrieved = get_attest_key(1000, &key_id).expect("retrieved");
        assert_eq!(retrieved.issuer_name_der(), b"test-k1");
        assert!(get_attest_key(1001, &key_id).is_none());
        assert!(get_attest_key(1000, &[2u8; 32]).is_none());
    }

    #[test]
    fn distinct_key_ids_with_same_uid_do_not_collide() {
        let _sequence = isolate_store_sequence();
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
        let _sequence = isolate_store_sequence();
        reset_for_testing();
        for i in 0..64 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            insert_attest_key(1000, id, make_test_issuer(&[i as u8]));
        }

        for i in 0..64 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            assert!(get_attest_key(1000, &id).is_some());
        }

        let mut id0 = [0u8; 32];
        id0[0] = 0;
        assert!(get_attest_key(1000, &id0).is_some());

        let mut id64 = [0u8; 32];
        id64[0] = 64;
        insert_attest_key(1000, id64, make_test_issuer(b"k64"));

        assert!(get_attest_key(1000, &id0).is_some());
        let mut id1 = [0u8; 32];
        id1[0] = 1;
        assert!(get_attest_key(1000, &id1).is_none());
        assert!(get_attest_key(1000, &id64).is_some());
    }

    #[test]
    fn clear_empties_the_store() {
        let _sequence = isolate_store_sequence();
        reset_for_testing();
        let id = [42u8; 32];
        insert_attest_key(1000, id, make_test_issuer(b"clear-me"));
        assert!(get_attest_key(1000, &id).is_some());
        clear();
        assert!(get_attest_key(1000, &id).is_none());
    }

    #[test]
    fn nested_attest_key_flow_never_deadlocks() {
        let _sequence = isolate_store_sequence();
        reset_for_testing();
        let id1 = [10u8; 32];
        let id2 = [20u8; 32];
        let id3 = [30u8; 32];

        insert_attest_key(1000, id1, make_test_issuer(b"root-attest"));

        let parent1 = get_attest_key(1000, &id1).expect("k1");
        assert_eq!(parent1.issuer_name_der(), b"root-attest");
        let k2_issuer = make_test_issuer(b"child-attest");
        insert_attest_key(1000, id2, k2_issuer);

        let parent2 = get_attest_key(1000, &id2).expect("k2");
        assert_eq!(parent2.issuer_name_der(), b"child-attest");
        let k3_issuer = make_test_issuer(b"leaf-key");
        insert_attest_key(1000, id3, k3_issuer);

        assert!(get_attest_key(1000, &id1).is_some());
        assert!(get_attest_key(1000, &id2).is_some());
        assert!(get_attest_key(1000, &id3).is_some());
    }

    #[test]
    fn touch_attest_key_updates_lru_and_returns_existence() {
        let _sequence = isolate_store_sequence();
        reset_for_testing();

        let id_missing = [99u8; 32];
        assert!(!touch_attest_key(1000, &id_missing));

        for i in 0..64 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            insert_attest_key(1000, id, make_test_issuer(&[i as u8]));
        }

        let mut id0 = [0u8; 32];
        id0[0] = 0;
        assert!(touch_attest_key(1000, &id0));
        assert!(!touch_attest_key(1001, &id0));

        let mut id64 = [0u8; 32];
        id64[0] = 64;
        insert_attest_key(1000, id64, make_test_issuer(b"k64"));

        assert!(get_attest_key(1000, &id0).is_some());
        let mut id1 = [0u8; 32];
        id1[0] = 1;
        assert!(get_attest_key(1000, &id1).is_none());
        assert!(get_attest_key(1000, &id64).is_some());
    }

    #[test]
    fn remove_attest_key_revokes_only_the_selected_entry() {
        let _sequence = isolate_store_sequence();
        reset_for_testing();
        let first = [1u8; 32];
        let second = [2u8; 32];
        insert_attest_key(1000, first, make_test_issuer(b"first"));
        insert_attest_key(1000, second, make_test_issuer(b"second"));

        assert!(remove_attest_key(1000, &first));
        assert!(!remove_attest_key(1000, &first));
        assert!(get_attest_key(1000, &first).is_none());
        assert!(get_attest_key(1000, &second).is_some());
        assert!(!remove_attest_key(1001, &second));
    }

    #[test]
    fn insert_child_attest_key_requires_parent_and_cascades_removal() {
        let _sequence = isolate_store_sequence();
        reset_for_testing();
        let parent = [10u8; 32];
        let child = [11u8; 32];
        let grandchild = [12u8; 32];

        assert!(!insert_child_attest_key(
            1000,
            &parent,
            child,
            make_test_issuer(b"child")
        ));
        assert!(get_attest_key(1000, &child).is_none());

        insert_attest_key(1000, parent, make_test_issuer(b"parent"));
        assert!(insert_child_attest_key(
            1000,
            &parent,
            child,
            make_test_issuer(b"child")
        ));
        assert!(insert_child_attest_key(
            1000,
            &child,
            grandchild,
            make_test_issuer(b"grandchild")
        ));

        assert!(get_attest_key(1000, &parent).is_some());
        assert!(get_attest_key(1000, &child).is_some());
        assert!(get_attest_key(1000, &grandchild).is_some());

        assert!(remove_attest_key(1000, &parent));
        assert!(get_attest_key(1000, &parent).is_none());
        assert!(get_attest_key(1000, &child).is_none());
        assert!(get_attest_key(1000, &grandchild).is_none());
    }

    #[test]
    fn child_cannot_replace_its_parent_with_a_self_cycle() {
        let _sequence = isolate_store_sequence();
        reset_for_testing();
        let parent = [10u8; 32];
        insert_attest_key(1000, parent, make_test_issuer(b"parent"));

        assert!(!insert_child_attest_key(
            1000,
            &parent,
            parent,
            make_test_issuer(b"self")
        ));
        assert!(remove_attest_key(1000, &parent));
        assert!(get_attest_key(1000, &parent).is_none());
    }

    #[test]
    fn replacing_node_removes_its_existing_descendants() {
        let _sequence = isolate_store_sequence();
        reset_for_testing();
        let first_parent = [10u8; 32];
        let second_parent = [20u8; 32];
        let child = [11u8; 32];
        let grandchild = [12u8; 32];
        insert_attest_key(1000, first_parent, make_test_issuer(b"first-parent"));
        insert_attest_key(1000, second_parent, make_test_issuer(b"second-parent"));
        assert!(insert_child_attest_key(
            1000,
            &first_parent,
            child,
            make_test_issuer(b"child")
        ));
        assert!(insert_child_attest_key(
            1000,
            &child,
            grandchild,
            make_test_issuer(b"grandchild")
        ));

        assert!(insert_child_attest_key(
            1000,
            &second_parent,
            child,
            make_test_issuer(b"replacement-child")
        ));
        assert!(get_attest_key(1000, &child).is_some());
        assert!(get_attest_key(1000, &grandchild).is_none());
    }

    #[test]
    fn ancestor_cannot_be_reparented_below_its_descendant() {
        let _sequence = isolate_store_sequence();
        reset_for_testing();
        let root = [10u8; 32];
        let child = [11u8; 32];
        let grandchild = [12u8; 32];
        insert_attest_key(1000, root, make_test_issuer(b"root"));
        assert!(insert_child_attest_key(
            1000,
            &root,
            child,
            make_test_issuer(b"child")
        ));
        assert!(insert_child_attest_key(
            1000,
            &child,
            grandchild,
            make_test_issuer(b"grandchild")
        ));

        assert!(!insert_child_attest_key(
            1000,
            &grandchild,
            root,
            make_test_issuer(b"invalid-root")
        ));
        assert!(get_attest_key(1000, &root).is_some());
        assert!(get_attest_key(1000, &child).is_some());
        assert!(get_attest_key(1000, &grandchild).is_some());
    }

    #[test]
    fn capacity_eviction_removes_the_oldest_subtree() {
        let _sequence = isolate_store_sequence();
        reset_for_testing();
        let parent = [1u8; 32];
        let child = [2u8; 32];
        let grandchild = [3u8; 32];
        insert_attest_key(1000, parent, make_test_issuer(b"parent"));
        assert!(insert_child_attest_key(
            1000,
            &parent,
            child,
            make_test_issuer(b"child")
        ));
        assert!(insert_child_attest_key(
            1000,
            &child,
            grandchild,
            make_test_issuer(b"grandchild")
        ));
        for i in 4..=64 {
            let mut id = [0u8; 32];
            id[0] = i;
            insert_attest_key(1000, id, make_test_issuer(&[i]));
        }

        insert_attest_key(1000, [65u8; 32], make_test_issuer(b"overflow"));

        assert!(get_attest_key(1000, &parent).is_none());
        assert!(get_attest_key(1000, &child).is_none());
        assert!(get_attest_key(1000, &grandchild).is_none());
    }
}
