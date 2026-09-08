// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../../NOTICE.
use super::{
    prune_stale_restore_transactions, restore_transactions, RestoreTransaction,
    RESTORE_TRANSACTION_TTL,
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
        prune_stale_restore_transactions(&root, &mut transactions);
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
            RESTORE_TRANSACTION_TTL.saturating_sub(age)
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
            transaction(now - RESTORE_TRANSACTION_TTL, true),
        );

        assert_eq!(
            next_expiry_wait(&transactions, now),
            Some(RESTORE_TRANSACTION_TTL - Duration::from_secs(120))
        );
    }

    #[test]
    fn expired_idle_transaction_requests_immediate_collection() {
        let now = Instant::now();
        let mut transactions = HashMap::new();
        transactions.insert(
            "expired".to_string(),
            transaction(now - RESTORE_TRANSACTION_TTL, false),
        );

        assert_eq!(next_expiry_wait(&transactions, now), Some(Duration::ZERO));
    }

    #[test]
    fn mutating_transactions_do_not_arm_expiry_until_lease_release() {
        let now = Instant::now();
        let mut transactions = HashMap::new();
        transactions.insert(
            "mutating".to_string(),
            transaction(now - RESTORE_TRANSACTION_TTL, true),
        );

        assert_eq!(next_expiry_wait(&transactions, now), None);
    }

    #[test]
    fn operation_completion_restarts_full_expiry_window() {
        let before_refresh = Instant::now();
        let mut refreshed = transaction(before_refresh - RESTORE_TRANSACTION_TTL, false);
        refresh_restore_transaction(&mut refreshed);
        assert!(refreshed.touched >= before_refresh);

        let refreshed_at = refreshed.touched;
        let mut transactions = HashMap::new();
        transactions.insert("refreshed".to_string(), refreshed);
        assert_eq!(
            next_expiry_wait(&transactions, refreshed_at),
            Some(RESTORE_TRANSACTION_TTL)
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
