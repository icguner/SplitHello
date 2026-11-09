//! Outbound networking for the engine.
//!
//! Every connection the engine itself makes to the Internet (Worker DoH, the
//! tunnel, list downloads) dials the private *connect port*; the packet loop
//! rewrites that to :443. That keeps the engine's own traffic from being
//! reflected back into its relay (C++ invariant 3).

pub mod connect;
pub mod http;
pub mod tls;
pub mod tunnel;

pub use connect::{connect_any, is_ip_literal};
pub use http::{Fetch, HttpClient, Request, Response};
