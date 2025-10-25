/// Set TCP NODELAY via a standard sync call.
///
/// Used by tarweb for the listening socket, and in the sni_router.
pub fn set_nodelay(fd: i32) -> std::io::Result<()> {
    let flag: libc::c_int = 1; // Enable TCP_NODELAY (disable Nagle)
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP, // Protocol
            libc::TCP_NODELAY, // Option
            &flag as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}
