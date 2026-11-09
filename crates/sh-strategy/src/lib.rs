//! Bypass profiles, differential diagnosis and the learned-profile store
//! (port of `src/Strategy.cpp` and `src/Diagnosis.cpp`).
#![forbid(unsafe_code)]

pub mod diagnosis;
mod profile;
mod store;

pub use profile::{
    FragmentPlan, PROFILES, Profile, build_plan, find_profile, normalize_host, scope_key,
};
pub use store::{DEFAULT_NETWORK, Outcome, Store};
