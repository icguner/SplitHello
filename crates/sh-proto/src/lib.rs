//! Pure wire-format logic: no sockets, no Windows API, no allocation on the
//! read paths beyond what a result needs. Every parser is bounds-checked and is
//! a fuzz target (see `fuzz/`).
#![forbid(unsafe_code)]

pub mod dns;
pub mod packet;
pub mod quic;
pub mod tls;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
