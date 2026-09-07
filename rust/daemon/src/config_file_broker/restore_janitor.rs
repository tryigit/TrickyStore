// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../../NOTICE.
use super::{
    prune_stale_restore_transactions, restore_transactions, RestoreTransaction,
    RESTORE_TRANSACTION_TTL,
};
use cleverestricky_service_core::secure_fs::TrustedDir;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Condvar, MutexGuard, OnceLock};
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
        .spawn(move || run_restore_janitor(root))?;
    Ok(())
}

fn run_restore_janitor(root: Arc<TrustedDir>) {
    let mut transactions = match restore_transactions().lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            eprintln!("cleverestrickyd: restore janitor recovered poisoned transaction state");
            poisoned.into_inner()
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
                        poisoned.into_inner()
                    }
                };
                transactions = guard;
            }
            None => {
                transactions = match wake().wait(transactions) {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        eprintln!("cleverestrickyd: restore janitor recovered poisoned wait");
                        poisoned.into_inner()
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
    use super::*;

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
}
