use anyhow::{Context, Result, anyhow};
use caps::CapSet;
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

/// Drop privileges to bare minimum.
pub fn drop_privs(with_rustls: bool) -> Result<()> {
    no_new_privs()?;
    drop_caps()?;
    seccomp(with_rustls)?;
    Ok(())
}

/// Prevent adding back privileges, such as by running a suid binary.
fn no_new_privs() -> Result<()> {
    tracing::trace!("Setting no new privs");
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        Err(anyhow!(
            "prctl(no new privs): {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

/// Drop all capabilities, if present.
fn drop_caps() -> Result<()> {
    tracing::trace!("Dropping caps");

    // These should not fail.
    for set in [
        CapSet::Effective,
        CapSet::Inheritable,
        CapSet::Ambient,
        CapSet::Permitted,
    ] {
        caps::clear(None, set).context(format!("dropping privs for {set:?}"))?;
    }

    // Dropping bounding caps can fail.
    {
        let set = CapSet::Bounding;
        if let Err(e) = caps::clear(None, set) {
            tracing::debug!("Dropping priv {set:?} failed: {e}");
        }
    }
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
