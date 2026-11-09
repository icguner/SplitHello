//! WinDivert packet interception. Stage 1 holds only the pure process-scope
//! rules; the FFI, packet loop and owner lookup arrive in stage 4.

pub mod rules;
