//! WinDivert packet interception (port of `WinDivertInterceptor`,
//! `WinDivertPacket` and `ProcessFilter`). All `unsafe` lives in `ffi` and the
//! Win32 lookups of `process`; packet logic is pure and tested without the driver.

pub mod ffi;
mod interceptor;
pub mod packet;
pub mod process;
pub mod rules;

pub use interceptor::{Batch, Interceptor, Processor, QuicMode, Registries, Settings};
