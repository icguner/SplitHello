//! One rustls configuration for all outbound TLS: ring crypto and the Windows
//! certificate store (platform verifier), so a corporate or user-installed root
//! is trusted exactly as WinHTTP trusted it.

use std::sync::{Arc, OnceLock};

use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt;

pub fn client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .with_platform_verifier()
                .expect("platform certificate verifier")
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}
