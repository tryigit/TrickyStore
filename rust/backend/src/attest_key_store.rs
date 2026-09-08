// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
use cleverestricky_certificate_core::PreparedIssuer;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

pub const MAX_ATTEST_KEYS: usize = 32;

struct AttestKeyEntry {
    calling_uid: u32,
    subject_der: Vec<u8>,
    issuer: PreparedIssuer,
}

#[derive(Default)]
struct AttestKeyStore {
    entries: VecDeque<AttestKeyEntry>,
}

static STORE: OnceLock<Mutex<AttestKeyStore>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn reset_for_testing() {
    let store = STORE.get_or_init(|| Mutex::new(AttestKeyStore::default()));
    let mut guard = match store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.entries.clear();
    drop(guard);
    store.clear_poison();
}

pub fn insert_attest_key(calling_uid: u32, subject_der: Vec<u8>, issuer: PreparedIssuer) {
    let store = STORE.get_or_init(|| Mutex::new(AttestKeyStore::default()));
    let mut guard = match store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some(pos) = guard
        .entries
        .iter()
        .position(|e| e.calling_uid == calling_uid && e.subject_der == subject_der)
    {
        guard.entries.remove(pos);
    }

    if guard.entries.len() >= MAX_ATTEST_KEYS {
        guard.entries.pop_front();
    }

    guard.entries.push_back(AttestKeyEntry {
        calling_uid,
        subject_der,
        issuer,
    });
}

pub fn with_attest_key<R>(
    calling_uid: u32,
    issuer_der: &[u8],
    f: impl FnOnce(&PreparedIssuer) -> R,
) -> Option<R> {
    let store = STORE.get_or_init(|| Mutex::new(AttestKeyStore::default()));
    let guard = match store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    guard
        .entries
        .iter()
        .rev()
        .find(|e| e.calling_uid == calling_uid && e.subject_der == issuer_der)
        .map(|entry| f(&entry.issuer))
}
