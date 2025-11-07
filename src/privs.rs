use anyhow::{Context, Result, anyhow};
use caps::CapSet;
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
use tracing::{info, trace, warn};

/// Drop privs suitable for SNI router.
///
/// # Errors
///
/// If dropping privs fails.
///
// Not actually dead code, just not used in tarweb, only SNI.
#[allow(dead_code)]
pub fn sni_drop(dirs: &[&std::path::Path]) -> Result<()> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
        Scope, path_beneath_rules,
    };
    let abi = ABI::V6;

    // Kernel 5.13 or better. tarweb already requires 6.7.
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::BindTcp)?
        .create()?
        .set_no_new_privs(true)
        .add_rules(path_beneath_rules(dirs, AccessFs::from_read(abi)))?
        .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock enabled and fully enforced for filesystem and network");
        }
        other => {
            return Err(anyhow!(
                "Landlock status not fully enforced for filesystem and network: {other:?}"
            ));
        }
    }

    // These require kernel 6.12 or newer.
    let status = Ruleset::default()
        .scope(Scope::Signal)?
        // .scope(Scope::AbstractUnixSocket)?
        .create()?
        .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock enabled and fully enforced for signal");
        }
        other => warn!(
            "Landlock status not fully enforced for signal (probably kernel <6.12): {other:?}"
        ),
    }
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(_) => return Err(anyhow!("landlock failed to prevent tcp bind")),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(e) => {
            return Err(anyhow!(
                "unexpected error verifying landlock blocking connects: {e}"
            ));
        }
    }
    Ok(())
}

/// Drop privileges to bare minimum.
///
/// # Errors
///
/// If dropping privs fails.
pub fn drop_privs(with_rustls: bool) -> Result<()> {
    landlock()?;
    no_new_privs()?;
    drop_caps()?;
    seccomp(with_rustls)?;
    Ok(())
}

/// Prevent adding back privileges, such as by running a suid binary.
fn no_new_privs() -> Result<()> {
    trace!("Setting no new privs");
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

fn landlock() -> Result<()> {
    use landlock::{ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetStatus, Scope};
    let abi = ABI::V6;

    // Kernel 5.13 or better. tarweb already requires 6.7.
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::from_all(abi))?
        .create()?
        .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock enabled and fully enforced for filesystem and network");
        }
        other => {
            return Err(anyhow!(
                "Landlock status not fully enforced for filesystem and network: {other:?}"
            ));
        }
    }

    // These require kernel 6.12 or newer.
    let status = Ruleset::default()
        .scope(Scope::Signal)?
        .scope(Scope::AbstractUnixSocket)?
        .create()?
        .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock enabled and fully enforced for signal & abstract unix socket");
        }
        other => warn!(
            "Landlock status not fully enforced for signal & abstract unix socket (probably kernel <6.12): {other:?}"
        ),
    }

    // Test the access.
    if std::fs::read_dir("/").is_ok() {
        return Err(anyhow!("landlock failed to prevent listing root fs"));
    }
    match std::net::TcpStream::connect("127.0.0.1:8080") {
        Ok(_) => return Err(anyhow!("landlock failed to prevent tcp connect")),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(e) => {
            return Err(anyhow!(
                "unexpected error verifying landlock blocking connects: {e}"
            ));
        }
    }
    Ok(())
}

/// Drop all capabilities, if present.
fn drop_caps() -> Result<()> {
    trace!("Dropping caps");

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
            trace!("Expected: Dropping priv {set:?} failed: {e}");
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
