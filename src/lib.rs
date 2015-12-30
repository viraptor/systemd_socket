//! systemd_socket implements the daemon side of the socket activation. The interface is similar to
//! the one provided by the systemd/sd-daemon library, but adjusted for easier usage in rust. It
//! relies on `nix` for all low-level operations. All checks are ported from the systemd code.
//!
//! Enums required for socket type (`SockType`) and address family (`AddressFamily`) are reexported
//! from nix.
//!
//! The library is based on [rust-systemd](https://github.com/jmesmon/rust-systemd) by Cody P
//! Schafer, but it does not require any extra libraries and works on rust stable.

extern crate nix;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

use nix::fcntl;
use nix::sys::ioctl::libc;
use nix::sys::socket;
use nix::sys::stat;
use std::collections::HashMap;
use std::convert::From;
use std::env;
use std::error::Error as StdError;
use std::fmt;
use std::num::ParseIntError;
use std::os::unix::io::RawFd as Fd;
use std::path;
use std::result::Result as StdResult;

pub use nix::sys::socket::SockType;
pub use nix::sys::socket::AddressFamily;

const VAR_FDS: &'static str = "LISTEN_FDS";
const VAR_NAMES: &'static str = "LISTEN_FDNAMES";
const VAR_PID: &'static str = "LISTEN_PID";

#[derive(Debug, PartialEq)]
pub enum Error {
    Var(env::VarError),
    Parse(ParseIntError),
    DifferentProcess,
    InvalidFdValue,
    InvalidVariableValue,
    Nix(nix::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match self {
            &Error::InvalidFdValue => "Received invalid 'fd' value",
            &Error::InvalidVariableValue => "Environment variable could not be parsed",
            &Error::DifferentProcess =>
                "Environment variables are meant for a different process (pid mismatch)",
            &Error::Var(_) => "Required environment variable missing or unreadable",
            &Error::Parse(_) => "Could not parse number in 'LISTEN_FDS'",
            &Error::Nix(_) => "Calling system function on socket failed",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match self {
            &Error::Var(ref e) => Some(e),
            &Error::Parse(ref e) => Some(e),
            &Error::Nix(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<env::VarError> for Error {
    fn from(e: env::VarError) -> Error {
        Error::Var(e)
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Error {
        Error::Parse(e)
    }
}

impl From<nix::Error> for Error {
    fn from(e: nix::Error) -> Error {
        Error::Nix(e)
    }
}

/// Encapsulates the possible failure modes of local functions.
pub type Result<T> = StdResult<T, Error>;

/// Number of the first passed file descriptor
const LISTEN_FDS_START: Fd = 3;

fn unset_all_env() {
    env::remove_var(VAR_PID);
    env::remove_var(VAR_FDS);
    env::remove_var(VAR_NAMES);
}

/// Returns the file descriptors passed in by init process. Removes the `$LISTEN_FDS` and
/// `$LISTEN_PID` variables from the environment if `unset_environment` is `true`.
pub fn listen_fds(unset_environment: bool) -> Result<Vec<Fd>> {
    let pid_str = try!(env::var(VAR_PID));
    let pid: libc::pid_t = try!(pid_str.parse());

    if pid != nix::unistd::getpid() {
        return Err(Error::DifferentProcess);
    }

    let fds_str = try!(env::var(VAR_FDS));
    let fds: libc::c_int = try!(fds_str.parse());

    if fds < 0 {
        return Err(Error::InvalidVariableValue);
    }

    for fd in LISTEN_FDS_START .. (LISTEN_FDS_START+fds) {
        try!(fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFD(fcntl::FD_CLOEXEC)));
    }
    
    if unset_environment {
        unset_all_env();
    }
    let fd_vec: Vec<Fd> = (LISTEN_FDS_START .. (LISTEN_FDS_START+fds)).collect();
    Ok(fd_vec)
}

/// Returns file descriptors with names. Removes the `$LISTEN_FDS` and `$LISTEN_PID` variables from
/// the environment if `unset_environment` is `true`.
pub fn listen_fds_with_names(unset_environment: bool) -> Result<HashMap<String,Fd>> {
    let names_str = try!(env::var(VAR_NAMES));
    let names: Vec<&str> = names_str.split(':').collect();

    let fds: Vec<Fd> = try!(listen_fds(unset_environment));
    if fds.len() != names.len() {
        return Err(Error::InvalidVariableValue);
    }

    let mut map = HashMap::new();
    for (name, fd) in names.into_iter().zip(fds) {
        map.insert(name.to_string(), fd);
    }
    Ok(map)
}

/// Identifies whether the passed file descriptor is a FIFO. If a path is
/// supplied, the file descriptor must also match the path.
pub fn is_fifo(fd: Fd, path: Option<&str>) -> Result<bool> {
    if fd < 0 {
        return Err(Error::InvalidFdValue);
    }
    let fs = try!(stat::fstat(fd));
    let mode = stat::SFlag::from_bits_truncate(fs.st_mode);
    if !mode.contains(stat::S_IFIFO) {
        return Ok(false);
    }
    if let Some(path_str) = path {
        let path_stat = match stat::stat(path::Path::new(path_str)) {
            Ok(x) => x,
            Err(_) => {return Ok(false)},
        };
        return Ok(path_stat.st_dev == fs.st_dev && path_stat.st_ino == fs.st_ino);
    }
    Ok(true)
}

/// Identifies whether the passed file descriptor is a special character device.
/// If a path is supplied, the file descriptor must also match the path.
pub fn is_special(fd: Fd, path: Option<&str>) -> Result<bool> {
    if fd < 0 {
        return Err(Error::InvalidFdValue);
    }
    let fs = try!(stat::fstat(fd));
    let mode = stat::SFlag::from_bits_truncate(fs.st_mode);
    if !mode.contains(stat::S_IFREG) && !mode.contains(stat::S_IFCHR) {
        // path not comparable
        return Ok(true);
    }

    if let Some(path_str) = path {
        let path_stat = match stat::stat(path::Path::new(path_str)) {
            Ok(x) => x,
            Err(_) => {return Ok(false)},
        };

        let path_mode = stat::SFlag::from_bits_truncate(path_stat.st_mode);
        if (mode & path_mode).contains(stat::S_IFREG) {
            return Ok(path_stat.st_dev == fs.st_dev && path_stat.st_ino == fs.st_ino);
        }

        if (mode & path_mode).contains(stat::S_IFCHR) {
            return Ok(path_stat.st_rdev == fs.st_rdev);
        }

        return Ok(false);
    }
    
    Ok(true)
}

/// Do checks common to all socket verification functions. (type, listening state)
fn is_socket_internal(fd: Fd, socktype: Option<SockType>,
                      listening: Option<bool>) -> Result<bool> {
    if fd < 0 {
        return Err(Error::InvalidFdValue);
    }
    let fs = try!(stat::fstat(fd));
    let mode = stat::SFlag::from_bits_truncate(fs.st_mode);
    if !mode.contains(stat::S_IFSOCK) {
        return Ok(false);
    }
    if let Some(val) = socktype {
        let typ: SockType = try!(socket::getsockopt(fd, socket::sockopt::SockType));
        if typ != val {
            return Ok(false);
        }
    }
    if let Some(val) = listening {
        let acc = try!(socket::getsockopt(fd, socket::sockopt::AcceptConn));
        if acc != val {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Identifies whether the passed file descriptor is a socket. If family,
/// type, and listening state are supplied, they must match as well.
pub fn is_socket(fd: Fd, family: Option<AddressFamily>, socktype: Option<SockType>,
                 listening: Option<bool>) -> Result<bool> {
    if ! try!(is_socket_internal(fd, socktype, listening)) {
        return Ok(false);
    }

    if let Some(val) = family {
        let sock_addr = try!(socket::getsockname(fd));
        if sock_addr.family() != val {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Identifies whether the passed file descriptor is an Internet socket. If family, type, listening
/// state, and/or port are supplied, they must match as well.
pub fn is_socket_inet(fd: Fd, family: Option<AddressFamily>, socktype: Option<SockType>,
                      listening: Option<bool>, port: Option<u16>) -> Result<bool> {
    if ! try!(is_socket_internal(fd, socktype, listening)) {
        return Ok(false);
    }

    let sock_addr = try!(socket::getsockname(fd));
    let sock_family = sock_addr.family();
    if sock_family != AddressFamily::Inet && sock_family != AddressFamily::Inet6 {
        return Ok(false);
    }

    if let Some(val) = family {
        if sock_family != val {
            return Ok(false);
        }
    }

    if let Some(val) = port {
        let addr = match sock_addr {
            socket::SockAddr::Inet(x) => x,
            _ => {unreachable!();}
        };
        if addr.port() != val {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Identifies whether the passed file descriptor is an AF_UNIX socket. If type are supplied, it
/// must match as well. Path checking is currently unsupported and will be ignored
pub fn is_socket_unix(fd: Fd, socktype: Option<SockType>, listening: Option<bool>,
                      path: Option<&str>) -> Result<bool> {
    if ! try!(is_socket_internal(fd, socktype, listening)) {
        return Ok(false);
    }

    let sock_addr = try!(socket::getsockname(fd));
    let sock_family = sock_addr.family();
    if sock_family != AddressFamily::Unix {
        return Ok(false);
    }

    if let Some(_val) = path {
        // TODO: unsupported
    }

    Ok(true)
}

// TODO
///// Identifies whether the passed file descriptor is a POSIX message queue. If a
///// path is supplied, it will also verify the name.
//pub fn is_mq(fd: Fd, path: Option<&str>) -> Result<bool> {
//}

#[cfg(test)]
mod tests {
    use std::env;
    use super::nix;
    use ::std::os::unix::io::RawFd;
    use ::std::sync::{Mutex,MutexGuard};

    // Even with one -j1, cargo runs multiple tests at once.  That doesn't work with environment
    // variables, or specific socket ordering, so mutexes are required.
    lazy_static! {
        static ref LOCK: Mutex<()> = Mutex::new(());
    }

    fn lock_env<'a>() -> MutexGuard<'a, ()> {
        LOCK.lock().unwrap()
    }

    fn set_current_pid() {
        let pid = nix::unistd::getpid();
        env::set_var(super::VAR_PID, format!("{}", pid));
    }

    fn create_fd(no: i32, family: super::AddressFamily, typ: super::SockType) -> RawFd {
        let fd = nix::sys::socket::socket(family, typ,
                                          nix::sys::socket::SockFlag::empty(), 0).unwrap();
        // to verify the test itself is running in normal conditions
        assert_eq!(fd, no);
        fd
    }

    fn open_file(no: i32) -> RawFd {
        let path = ::std::path::Path::new("/etc/hosts");
        let fd = nix::fcntl::open(path, nix::fcntl::O_RDONLY, nix::sys::stat::Mode::empty()).unwrap();
        // to verify the test itself is running in normal conditions
        assert_eq!(fd, no);
        fd
    }

    fn close_fds<'a, I: Iterator<Item=&'a RawFd>>(fds: I) {
        for fd in fds {
            nix::unistd::close(*fd).unwrap();
        }
    }

    #[test]
    fn listen_fds_success() {
        let _l = lock_env();
        set_current_pid();
        create_fd(3, super::AddressFamily::Inet, super::SockType::Stream);
        env::set_var(super::VAR_FDS, "1");
        let fds = super::listen_fds(true).unwrap();
        assert_eq!(fds, vec!(3));
        close_fds(fds.iter());
    }

    #[test]
    fn names() {
        let _l = lock_env();
        set_current_pid();
        env::set_var(super::VAR_FDS, "2");
        env::set_var(super::VAR_NAMES, "a:b");
        create_fd(3, super::AddressFamily::Inet, super::SockType::Stream);
        create_fd(4, super::AddressFamily::Inet, super::SockType::Stream);
        let fds = super::listen_fds_with_names(true).unwrap();
        assert_eq!(fds.len(), 2);
        assert_eq!(fds["a"], 3);
        assert_eq!(fds["b"], 4);
        close_fds(fds.values());
    }

    #[test]
    fn listen_fds_cleans() {
        let _l = lock_env();
        set_current_pid();
        env::set_var(super::VAR_FDS, "0");
        super::listen_fds(false).unwrap();
        assert_eq!(env::var(super::VAR_FDS), Ok("0".into()));
        super::listen_fds(true).unwrap();
        assert_eq!(env::var(super::VAR_FDS), Err(env::VarError::NotPresent));
        assert_eq!(env::var(super::VAR_PID), Err(env::VarError::NotPresent));
        assert_eq!(env::var(super::VAR_NAMES), Err(env::VarError::NotPresent));
    }

    #[test]
    fn is_socket() {
        let fds: Vec<RawFd> = vec!(3);
        let _l = lock_env();
        create_fd(3, super::AddressFamily::Inet, super::SockType::Stream);
        assert!(super::is_socket(3, None, None, None).unwrap());
        assert!(super::is_socket(3, Some(super::AddressFamily::Inet),
                                 Some(super::SockType::Stream), Some(false)).unwrap());
        close_fds(fds.iter());

        open_file(3);
        assert!(!super::is_socket(3, None, None, None).unwrap());
        close_fds(fds.iter());
    }

    #[test]
    fn is_socket_inet() {
        let fds: Vec<RawFd> = vec!(3);
        let _l = lock_env();
        create_fd(3, super::AddressFamily::Inet, super::SockType::Stream);
        assert!(super::is_socket_inet(3, None, None, None, None).unwrap());
        assert!(super::is_socket_inet(3, Some(super::AddressFamily::Inet),
                                      Some(super::SockType::Stream), Some(false), None).unwrap());
        close_fds(fds.iter());

        open_file(3);
        assert!(!super::is_socket_inet(3, None, None, None, None).unwrap());
        close_fds(fds.iter());
    }
    
    #[test]
    fn is_socket_unix() {
        let fds: Vec<RawFd> = vec!(3);
        let _l = lock_env();
        create_fd(3, super::AddressFamily::Unix, super::SockType::Stream);
        assert!(super::is_socket_unix(3, None, None, None).unwrap());
        assert!(super::is_socket_unix(3, Some(super::SockType::Stream),
                                      Some(false), None).unwrap());
        close_fds(fds.iter());

        open_file(3);
        assert!(!super::is_socket_unix(3, None, None, None).unwrap());
        close_fds(fds.iter());
    }
}
