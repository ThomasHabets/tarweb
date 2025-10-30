/// Set TCP NODELAY via a standard sync call.
///
/// Used by tarweb for the listening socket, and in the SNI router.
///
/// # Errors
///
/// System setsockopt errors.
pub fn set_nodelay(fd: libc::c_int) -> anyhow::Result<()> {
    let flag: libc::c_int = 1; // Enable TCP_NODELAY (disable Nagle)
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP, // Protocol
            libc::TCP_NODELAY, // Option
            (&raw const flag).cast::<libc::c_void>(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())?,
        )
    };

    if ret == -1 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}
