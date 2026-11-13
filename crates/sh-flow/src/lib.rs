//! Bookkeeping for the WinDivert packet loop and the DNS proxy.
//!
//! Every method takes the current monotonic time in milliseconds (`now_ms`) so
//! the expiry rules are deterministic in tests; production callers pass
//! `GetTickCount64`-style monotonic time.
#![forbid(unsafe_code)]

mod address;
mod policy;
pub mod quic;
mod registry;
mod route;

pub use address::PeerAddr;
pub use policy::HopRegistry;
pub use registry::DatagramRegistry;
pub use route::{DatagramRoute, route_datagram};
