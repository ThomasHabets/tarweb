use anyhow::Result;
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

/// Drop privileges to bare minimum.
pub fn drop_privs(with_rustls: bool) -> Result<()> {
    seccomp(with_rustls)?;
    Ok(())
}

/// Filter syscalls via seccomp.
///
/// This is of course security theatre, since any exploit could just issue
/// syscalls via io-uring.
fn seccomp(with_rustls: bool) -> Result<()> {
    let mut f = ScmpFilterContext::new(ScmpAction::KillProcess)?;

    // Intentionally turned on.
    for name in [
        "write",
        "close",
        "futex",
        "io_uring_enter",
        "io_uring_register",
        "getrandom",
    ] {
        f.add_rule(ScmpAction::Allow, ScmpSyscall::from_name(name)?)?;
    }

    if with_rustls {
        // Rustls does some memory allocation.
        for name in [
            // on /dev/sysgenid
            "newfstatat",
            // memory allocations.
            "mmap",
            "madvise",
            "mprotect",
            "munmap",
        ] {
            f.add_rule(ScmpAction::Allow, ScmpSyscall::from_name(name)?)?;
        }
    }
    f.load()?;
    Ok(())
}
