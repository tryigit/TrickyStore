// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub(crate) fn run<F>(service: F) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()>,
{
    match catch_unwind(AssertUnwindSafe(service)) {
        Ok(Ok(())) => Err(io::Error::other("service thread exited unexpectedly")),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(io::Error::other("service thread panicked")),
    }
}

pub(crate) fn run_allow_clean_exit<F>(service: F) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()>,
{
    match catch_unwind(AssertUnwindSafe(service)) {
        Ok(result) => result,
        Err(_) => Err(io::Error::other("service thread panicked")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_is_reported_as_service_failure_after_unwind() {
        let result = run(|| -> io::Result<()> { panic!("simulated service panic") });
        assert_eq!(
            result.expect_err("panic must become an error").to_string(),
            "service thread panicked"
        );
    }

    #[test]
    fn unexpected_clean_exit_is_also_a_service_failure() {
        let result = run(|| Ok(()));
        assert_eq!(
            result
                .expect_err("long-lived service must not exit cleanly")
                .to_string(),
            "service thread exited unexpectedly"
        );
    }

    #[test]
    fn ordinary_service_error_is_preserved() {
        let result = run(|| {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport failed",
            ))
        });
        let error = result.expect_err("service error must propagate");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "transport failed");
    }

    #[test]
    fn clean_exit_can_be_explicitly_allowed_for_bounded_services() {
        assert!(run_allow_clean_exit(|| Ok(())).is_ok());
        let error = run_allow_clean_exit(|| {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport failed",
            ))
        })
        .expect_err("real service errors must still propagate");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
}
