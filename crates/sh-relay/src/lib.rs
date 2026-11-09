//! The local relay (port of `src/SocksProxy.cpp`, `src/DirectRelay.cpp`).
//!
//! Each accepted connection is a tokio task instead of an OS thread; the
//! lifecycle rules of the C++ fix for the 1 GB leak stay: at most 1024 live
//! connections (RST beyond that), every session is owned and awaited on stop,
//! a 10-minute idle limit, and a 10-second handshake budget in manual mode.

mod direct;
mod listener;
mod negotiate;
mod pump;

pub use direct::{RelayContext, TunnelSettings, relay};
pub use listener::{Listener, ListenerMode};
