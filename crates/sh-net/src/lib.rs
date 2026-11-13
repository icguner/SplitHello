//! Outbound networking for the engine: HTTPS to the Worker (DoH) and for
//! list downloads. Callers pass the addresses to dial, because the system
//! resolver would lead back into the engine's own DNS proxy.

pub mod http;
pub mod tls;

pub use http::{Fetch, HttpClient, Request, Response};

pub fn is_ip_literal(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}
