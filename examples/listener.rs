extern crate systemd_socket;

use std::net::TcpListener;
use std::os::unix::io::FromRawFd;

pub fn main() {
    let fds = systemd_socket::listen_fds(true).unwrap_or(vec!());

    let _listener = if fds.len() > 1 {
        // socket already open
        unsafe { TcpListener::from_raw_fd(fds[0]) }
    } else {
        // need new socket
        TcpListener::bind("127.0.0.1:9876").unwrap()
    };
}
