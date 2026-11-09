//! Flow bookkeeping shared by the WinDivert packet loop and the relay.
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
pub use policy::PolicyRegistry;
pub use registry::{DatagramRegistry, FlowKind, FlowRegistry, Target, TcpFlowTable};
pub use route::{DatagramRoute, PacketRoute, route_datagram, route_packet};
