// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../../NOTICE.
use super::{
    export_transaction_to_root, restore_transactions, RestoreOriginal, RestoreTransaction,
};
use cleverestricky_service_core::secure_fs::TrustedDir;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

const RESTORE_JANITOR_STACK_BYTES: usize = 256 * 1024;
static RESTORE_JANITOR_WAKE: OnceLock<Condvar> = OnceLock::new();

fn wake() -> &'static Condvar {
    RESTORE_JANITOR_WAKE.get_or_init(Condvar::new)
}

pub(super) fn notify() {
    wake().notify_one();
}

pub(super) fn spawn_restore_janitor(root: Arc<TrustedDir>) -> io::Result<()> {
    thread::Builder::new()
        .name("ct-restore-gc".to_string())
        .stack_size(RESTORE_JANITOR_STACK_BYTES)
        .spawn(move || {
            if let Err(error) = crate::service_guard::run(|| {
                run_restore_janitor(root);
                Ok(())
            }) {
                eprintln!("cleverestrickyd: restore janitor failed: {error}");
                std::process::exit(1);
            }
        })?;
    Ok(())
}

fn recover_poison<T, U>(mutex: &Mutex<T>, poisoned: PoisonError<U>) -> U {
    mutex.clear_poison();
    poisoned.into_inner()
}

fn run_restore_janitor(root: Arc<TrustedDir>) {
    let mutex = restore_transactions();
    let mut transactions = match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            eprintln!("cleverestrickyd: restore janitor recovered poisoned transaction state");
            recover_poison(mutex, poisoned)
        }
    };
    loop {
        let pending_exports = stage_expired_exports(&mut transactions, Instant::now());
        if !pending_exports.is_empty() {
            drop(transactions);
            let mut completed_tokens = Vec::with_capacity(pending_exports.len());
            for (token, transaction) in pending_exports {
                let _ = export_transaction_to_root(&root, &token, &transaction);
                // Zeroize the moved snapshot bytes before releasing the placeholder's accounting.
                drop(transaction);
                completed_tokens.push(token);
            }
            transactions = match mutex.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    eprintln!(
                        "cleverestrickyd: restore janitor recovered poisoned transaction state"
                    );
                    recover_poison(mutex, poisoned)
                }
            };
            for token in completed_tokens {
                transactions.remove(&token);
            }
            continue;
        }

        let now = Instant::now();
        match next_expiry_wait(&transactions, now) {
            Some(wait) => {
                let (guard, _) = match wake().wait_timeout(transactions, wait) {
                    Ok(result) => result,
                    Err(poisoned) => {
                        eprintln!("cleverestrickyd: restore janitor recovered poisoned timed wait");
                        recover_poison(mutex, poisoned)
                    }
                };
                transactions = guard;
            }
            None => {
                transactions = match wake().wait(transactions) {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        eprintln!("cleverestrickyd: restore janitor recovered poisoned wait");
                        recover_poison(mutex, poisoned)
                    }
                };
            }
        }
    }
}

fn stage_expired_exports(
    transactions: &mut HashMap<String, RestoreTransaction>,
    now: Instant,
) -> Vec<(String, RestoreTransaction)> {
    let stale: Vec<String> = transactions
        .iter()
        .filter_map(|(token, transaction)| {
            if transaction.mutation_in_progress {
                return None;
            }
            now.checked_duration_since(transaction.touched)
                .filter(|age| *age >= super::RESTORE_TRANSACTION_TTL)
                .map(|_| token.clone())
        })
        .collect();
    let mut pending = Vec::with_capacity(stale.len());
    for token in stale {
        let Some(transaction) = transactions.remove(&token) else {
            continue;
        };
        let placeholder = RestoreTransaction {
            keyboxes: transaction.keyboxes.clone(),
            mutation_in_progress: true,
            max_snapshot_bytes: transaction.max_snapshot_bytes,
            snapshot_bytes: transaction.snapshot_bytes,
            originals: transaction
                .originals
                .iter()
                .map(|original| RestoreOriginal {
                    path: original.path.clone(),
                    bytes: None,
                })
                .collect(),
            touched: transaction.touched,
        };
        transactions.insert(token.clone(), placeholder);
        pending.push((token, transaction));
    }
    pending
}

fn next_expiry_wait(
    transactions: &HashMap<String, RestoreTransaction>,
    now: Instant,
) -> Option<Duration> {
    transactions
        .values()
        .filter(|transaction| !transaction.mutation_in_progress)
        .map(|transaction| {
            let age = now
                .checked_duration_since(transaction.touched)
                .unwrap_or(Duration::ZERO);
            super::RESTORE_TRANSACTION_TTL.saturating_sub(age)
        })
        .min()
}

#[cfg(test)]
mod tests {
    use super::super::{refresh_restore_transaction, RestoreMutationLease};
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn transaction(touched: Instant, mutation_in_progress: bool) -> RestoreTransaction {
        RestoreTransaction {
            keyboxes: None,
            mutation_in_progress,
            max_snapshot_bytes: 4096,
            snapshot_bytes: 0,
            originals: Vec::new(),
            touched,
        }
    }

    #[test]
    fn nearest_idle_transaction_drives_exact_expiry_wait() {
        let now = Instant::now();
        let mut transactions = HashMap::new();
        transactions.insert(
            "later".to_string(),
            transaction(now - Duration::from_secs(60), false),
        );
        transactions.insert(
            "sooner".to_string(),
            transaction(now - Duration::from_secs(120), false),
        );
        transactions.insert(
            "mutating".to_string(),
            transaction(now - super::super::RESTORE_TRANSACTION_TTL, true),
        );

        assert_eq!(
            next_expiry_wait(&transactions, now),
            Some(super::super::RESTORE_TRANSACTION_TTL - Duration::from_secs(120))
        );
    }

    #[test]
    fn expired_idle_transaction_requests_immediate_collection() {
        let now = Instant::now();
        let mut transactions = HashMap::new();
        transactions.insert(
            "expired".to_string(),
            transaction(now - super::super::RESTORE_TRANSACTION_TTL, false),
        );

        assert_eq!(next_expiry_wait(&transactions, now), Some(Duration::ZERO));
    }

    #[test]
    fn staged_expiry_keeps_token_targets_and_snapshot_accounting_reserved() {
        let now = Instant::now();
        let token = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let mut expired = transaction(
            now - super::super::RESTORE_TRANSACTION_TTL - Duration::from_secs(1),
            false,
        );
        expired.snapshot_bytes = 3;
        expired.originals.push(RestoreOriginal {
            path: "state.txt".to_string(),
            bytes: Some(b"old".to_vec()),
        });
        let mut transactions = HashMap::new();
        transactions.insert(token.to_string(), expired);

        let mut pending = stage_expired_exports(&mut transactions, now);
        assert_eq!(pending.len(), 1);
        let placeholder = transactions.get(token).expect("token remains reserved");
        assert!(placeholder.mutation_in_progress);
        assert_eq!(placeholder.snapshot_bytes, 3);
        assert_eq!(placeholder.originals.len(), 1);
        assert_eq!(placeholder.originals[0].path, "state.txt");
        assert!(placeholder.originals[0].bytes.is_none());
        assert_eq!(
            pending[0].1.originals[0].bytes.as_deref(),
            Some(b"old".as_slice())
        );

        drop(pending.pop());
        transactions.remove(token);
    }

    #[test]
    fn mutating_transactions_do_not_arm_expiry_until_lease_release() {
        let now = Instant::now();
        let mut transactions = HashMap::new();
        transactions.insert(
            "mutating".to_string(),
            transaction(now - super::super::RESTORE_TRANSACTION_TTL, true),
        );

        assert_eq!(next_expiry_wait(&transactions, now), None);
        assert!(stage_expired_exports(&mut transactions, now).is_empty());
    }

    #[test]
    fn operation_completion_restarts_full_expiry_window() {
        let before_refresh = Instant::now();
        let mut refreshed = transaction(
            before_refresh - super::super::RESTORE_TRANSACTION_TTL,
            false,
        );
        refresh_restore_transaction(&mut refreshed);
        assert!(refreshed.touched >= before_refresh);

        let refreshed_at = refreshed.touched;
        let mut transactions = HashMap::new();
        transactions.insert("refreshed".to_string(), refreshed);
        assert_eq!(
            next_expiry_wait(&transactions, refreshed_at),
            Some(super::super::RESTORE_TRANSACTION_TTL)
        );
    }

    #[test]
    fn mutation_lease_drop_releases_during_unwind() {
        let token = "ffffffffffffffffffffffffffffffff";
        let stale_touch = Instant::now() - Duration::from_secs(60);
        {
            let mut transactions = restore_transactions()
                .lock()
                .expect("restore registry lock");
            transactions.remove(token);
            transactions.insert(token.to_string(), transaction(stale_touch, true));
        }

        let before_unwind = Instant::now();
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _lease = RestoreMutationLease::new(token);
            panic!("simulated streaming worker panic");
        }));
        assert!(unwind.is_err());

        let mut transactions = restore_transactions()
            .lock()
            .expect("restore registry lock");
        let transaction = transactions
            .get(token)
            .expect("transaction remains recoverable");
        assert!(!transaction.mutation_in_progress);
        assert!(transaction.touched >= before_unwind);
        transactions.remove(token);
    }

    #[test]
    fn poison_recovery_clears_shared_mutex_state() {
        let mutex = Mutex::new(());
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = mutex.lock().expect("initial lock");
            panic!("poison test mutex");
        }));
        assert!(mutex.is_poisoned());

        let poisoned = mutex
            .lock()
            .expect_err("mutex should remain poisoned until recovery");
        drop(recover_poison(&mutex, poisoned));

        assert!(!mutex.is_poisoned());
        assert!(mutex.lock().is_ok());
    }
}
