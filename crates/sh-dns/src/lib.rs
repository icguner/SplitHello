//! DNS through the Cloudflare Worker (port of `src/Dns.cpp` and
//! `src/TransparentDnsProxy.cpp`). The ISP resolver returns poisoned answers
//! for blocked names, so A/AAAA go to the Worker's `/resolve` (DoH upstream)
//! and every other type through the authenticated wire relay.

mod proxy;
mod resolver;

pub use proxy::{DnsProxy, build_reply};
pub use resolver::{Clock, DnsResult, Resolver};
