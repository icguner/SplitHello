//! Encrypted DNS (port of `src/Dns.cpp` and `src/TransparentDnsProxy.cpp`).
//! The ISP resolver returns poisoned answers for blocked names, so A/AAAA go
//! to public JSON DoH resolvers (the optional Worker's `/resolve` last) and
//! every other type through the same chain as wire DoH.

mod proxy;
mod resolver;

pub use proxy::{DnsProxy, build_reply};
pub use resolver::{Clock, DnsResult, Resolver};
