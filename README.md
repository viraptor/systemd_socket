# Rust port of systemd socket activation support

[![Build Status](https://travis-ci.org/viraptor/systemd_socket.svg?branch=master)](https://travis-ci.org/viraptor/systemd_socket)

## Usage

To use `systemd_socket`, add to your `Cargo.toml`:

```toml
[dependencies]
systemd_socket = "*"
```
Then, add this to your crate root:

```rust
extern crate systemd_socket;
```

The interface is slightly different than systemd C interface. To get a `Vec` of
all file descriptors passed into the app, call `listen_fds` and then use the
file descriptor numbers as you need:

```rust
let fds = systemd_socket::listen_fds(true).unwrap();
let listener = TcpListener::from_raw_fd(fds[0]);
```

See more complete example in `examples/listener.rs`.

## Notes

Path verification is not implemented for unix sockets.

Crate uses modified [nix](https://github.com/carllerche/nix-rust) until
[SO_TYPE support](https://github.com/carllerche/nix-rust/pull/225) is merged
into upstream.

Crate is based on [rust-systemd](https://github.com/jmesmon/rust-systemd), but
does not depend on linking with the systemd libraries. This also allows running
on rust-stable.
