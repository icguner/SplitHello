//! Small HTTPS client for the few calls the engine makes (Worker DoH, the
//! bootstrap lookup, list downloads). Port of `src/Http.cpp` semantics:
//! no system proxy (this process *is* the proxy), redirects never followed (the
//! Authorization header must not travel to another host), a capped body where
//! an over-cap body is a failure, and `Retry-After` read on 429/503.
//!
//! When `connect` is given, the connection goes to those addresses on that
//! port while TLS SNI and the Host header keep the real host name: this is how
//! the engine's own traffic uses the private connect port.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

pub const DEFAULT_MAX_BODY: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: &'static str,
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub timeout: Duration,
    /// Dial these addresses on this port instead of resolving `host` on 443.
    pub connect: Option<(Vec<IpAddr>, u16)>,
    pub max_body: usize,
}

impl Request {
    pub fn get(host: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: "GET",
            host: host.into(),
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: Duration::from_millis(8000),
            connect: None,
            max_body: DEFAULT_MAX_BODY,
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    /// HTTP status, or -1 when the transport failed (or the body hit the cap).
    pub status: i32,
    pub body: Vec<u8>,
    /// `Retry-After` delta-seconds on 429/503; 0 = absent.
    pub retry_after_seconds: u32,
}

impl Response {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn transport_failed(&self) -> bool {
        self.status < 0
    }

    fn failed() -> Self {
        Self {
            status: -1,
            ..Self::default()
        }
    }
}

pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = Response> + Send + 'a>>;

/// Test seam: the resolver and updaters take any fetcher.
pub trait Fetch: Send + Sync {
    fn fetch(&self, request: Request) -> FetchFuture<'_>;
}

/// reqwest clients keyed by their connect override, so keep-alive connections
/// to the same Worker are reused across DoH queries.
pub struct HttpClient {
    clients: Mutex<HashMap<Option<(String, Vec<SocketAddr>)>, reqwest::Client>>,
}

impl Default for HttpClient {
    fn default() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
        }
    }
}

impl HttpClient {
    fn client_for(&self, request: &Request) -> Option<reqwest::Client> {
        let key = request.connect.as_ref().map(|(addresses, port)| {
            (
                request.host.clone(),
                addresses
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, *port))
                    .collect::<Vec<_>>(),
            )
        });
        let mut clients = self.clients.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(client) = clients.get(&key) {
            return Some(client.clone());
        }
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured((*crate::tls::client_config()).clone())
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("SplitHello/1.0")
            .pool_idle_timeout(Duration::from_secs(60));
        if let Some((host, addresses)) = &key {
            builder = builder.resolve_to_addrs(host, addresses);
        }
        let client = builder
            .build()
            .map_err(|error| tracing::error!("HTTP istemcisi kurulamadi: {error}"))
            .ok()?;
        // A Worker moves its addresses rarely; old keys are dropped wholesale.
        if clients.len() > 32 {
            clients.clear();
        }
        clients.insert(key, client.clone());
        Some(client)
    }

    pub async fn perform(&self, request: Request) -> Response {
        let Some(client) = self.client_for(&request) else {
            return Response::failed();
        };
        let url = format!("https://{}{}", request.host, request.path);
        let method =
            reqwest::Method::from_bytes(request.method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut builder = client.request(method, &url).timeout(request.timeout);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body.clone());
        }
        let mut response = match builder.send().await {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(
                    "HTTPS {} {} basarisiz: {error}",
                    request.host,
                    request.path.split('?').next().unwrap_or("")
                );
                return Response::failed();
            }
        };
        let status = i32::from(response.status().as_u16());
        let retry_after_seconds = if status == 429 || status == 503 {
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u32>().ok())
                .unwrap_or(0)
        } else {
            0
        };
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > request.max_body {
                        // A capped body is a failure, never a silently truncated success.
                        return Response {
                            status: -1,
                            body: Vec::new(),
                            retry_after_seconds,
                        };
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => return Response::failed(),
            }
        }
        Response {
            status,
            body,
            retry_after_seconds,
        }
    }
}

impl Fetch for HttpClient {
    fn fetch(&self, request: Request) -> FetchFuture<'_> {
        Box::pin(self.perform(request))
    }
}

/// `wss://name.sub.workers.dev/x` -> `name.sub.workers.dev`. Accepts ws/wss/
/// http/https and bare hosts; empty on failure.
pub fn host_from_url(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let rest = rest.split('/').next().unwrap_or("");
    rest.split(':').next().unwrap_or("").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_from_url_handles_schemes_ports_and_paths() {
        assert_eq!(
            host_from_url("wss://relay.acct.workers.dev"),
            "relay.acct.workers.dev"
        );
        assert_eq!(host_from_url("https://h.example:8443/x/y"), "h.example");
        assert_eq!(host_from_url("bare.example"), "bare.example");
        assert_eq!(host_from_url(""), "");
    }

    #[test]
    fn status_helpers() {
        assert!(
            Response {
                status: 204,
                ..Default::default()
            }
            .ok()
        );
        assert!(
            !Response {
                status: 404,
                ..Default::default()
            }
            .ok()
        );
        assert!(Response::failed().transport_failed());
    }

    /// Live HTTPS through the connect override (port 443 here, as no packet
    /// loop is running). Run with `-- --ignored`.
    #[tokio::test]
    #[ignore = "needs Internet access"]
    async fn live_request_with_connect_override_keeps_sni_and_host() {
        let addresses: Vec<IpAddr> = tokio::net::lookup_host("one.one.one.one:443")
            .await
            .unwrap()
            .map(|a| a.ip())
            .collect();
        let client = HttpClient::default();
        let mut request = Request::get("one.one.one.one", "/dns-query?name=example.com&type=A")
            .header("Accept", "application/dns-json");
        request.connect = Some((addresses, 443));
        let response = client.perform(request).await;
        assert!(response.ok(), "status {}", response.status);
        assert!(String::from_utf8_lossy(&response.body).contains("\"Answer\""));
    }
}
