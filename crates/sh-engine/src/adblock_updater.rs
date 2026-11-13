//! Keeps the global ad-block list filled (port of `adblock::Updater`,
//! `src/AdBlock.cpp`): loads the cached lists at once, refreshes each from
//! raw.githubusercontent.com when older than a day, re-reads the allow file
//! the tray appends to, and publishes the recent-blocks file for the tray.
//!
//! Fixes a C++ shortcoming: downloads dial the private connect port, so they
//! no longer loop back through the engine's own relay.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use sh_adblock::{CompactSet, for_each_domain, parse_domains};
use sh_dns::Resolver;
use sh_net::http::{HttpClient, Request};
use tokio::sync::watch;

const REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const RETRY_MIN: Duration = Duration::from_secs(10 * 60);
const RETRY_MAX: Duration = Duration::from_secs(60 * 60);
const TICK: Duration = Duration::from_secs(5);
const RECENT_PUBLISH_INTERVAL: Duration = Duration::from_secs(30);
/// Floor for a list that does not declare its size.
const MIN_PLAUSIBLE_ENTRIES: usize = 1000;
const MAX_LIST_BYTES: usize = 32 * 1024 * 1024;
const LIST_HOST: &str = "raw.githubusercontent.com";

pub struct UpdaterFiles {
    pub cache_dir: PathBuf,
    /// One domain per line; the tray appends to it.
    pub allow_file: PathBuf,
    /// `#total<TAB>N` then `host<TAB>count` lines, read by the tray.
    pub recent_file: PathBuf,
}

/// How downloads reach the Internet.
pub struct Route {
    pub http: Arc<HttpClient>,
    /// Resolves the list host (Worker DNS when available).
    pub resolver: Option<Arc<Resolver>>,
    /// Port dialed at addresses resolved here; 0 leaves resolving to the HTTP client.
    pub connect_port: u16,
}

struct Source {
    name: String,
    path: String,
    cache_file: PathBuf,
    next_attempt: Instant,
    retry: Duration,
}

fn modified_age(path: &PathBuf) -> Option<Duration> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified).ok()
}

async fn list_addresses(route: &Route) -> Option<Vec<IpAddr>> {
    match &route.resolver {
        Some(resolver) => {
            Some(resolver.resolve(LIST_HOST, 0).await.candidates(8)).filter(|a| !a.is_empty())
        }
        None => tokio::net::lookup_host((LIST_HOST, 443))
            .await
            .ok()
            .map(|a| a.map(|s| s.ip()).collect()),
    }
}

async fn download(route: &Route, source: &Source) -> bool {
    let mut request = Request::get(LIST_HOST, source.path.clone());
    request.timeout = Duration::from_secs(15);
    request.max_body = MAX_LIST_BYTES;
    if route.connect_port != 0 {
        let Some(addresses) = list_addresses(route).await else {
            tracing::warn!(
                "Reklam listesi '{}' indirilemedi: adres cozulemedi",
                source.name
            );
            return false;
        };
        request.connect = Some((addresses, route.connect_port));
    }
    let response = route.http.perform(request).await;
    if !response.ok() {
        tracing::warn!(
            "Reklam listesi '{}' indirilemedi: HTTP {}",
            source.name,
            response.status
        );
        return false;
    }
    let text = String::from_utf8_lossy(&response.body);
    let mut entries = 0;
    for_each_domain(&text, |_| entries += 1);
    if !plausible(&text, entries) {
        tracing::warn!(
            "Reklam listesi '{}' reddedildi: cok az gecerli girdi",
            source.name
        );
        return false;
    }
    if let Err(error) = sh_core::fsutil::write_atomic(&source.cache_file, &response.body) {
        tracing::warn!(
            "Reklam listesi diske yazilamadi: {}: {error}",
            source.cache_file.display()
        );
        return false;
    }
    true
}

/// An error page or a truncated body must not replace a good list. HaGeZi
/// lists declare their entry count, so a complete one is recognised whatever
/// its size (the Windows/Office tracker list has a few hundred names); a list
/// without that line has to clear a size floor instead.
fn plausible(text: &str, entries: usize) -> bool {
    let declared = text
        .lines()
        .take_while(|line| line.starts_with('#'))
        .find_map(|line| {
            line.strip_prefix("# Number of entries:")?
                .trim()
                .parse()
                .ok()
        });
    match declared {
        Some(declared) => entries != 0 && entries * 10 >= usize::saturating_mul(declared, 9),
        None => entries >= MIN_PLAUSIBLE_ENTRIES,
    }
}

/// One list file at a time is in memory as text; names go straight into the
/// compact hash set, so peak memory is the largest file plus the set.
fn rebuild(sources: &[Source]) {
    let mut merged = CompactSet::default();
    for source in sources {
        let Some(bytes) = sh_core::fsutil::read_all(&source.cache_file) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let mut parsed = CompactSet::default();
        for_each_domain(&text, |name| parsed.push(name));
        if !plausible(&text, parsed.len()) {
            continue;
        }
        tracing::info!(
            "Reklam listesi '{}': {} alan adi",
            source.name,
            parsed.len()
        );
        merged.append(parsed);
    }
    let merged = merged.finish();
    if !merged.is_empty() {
        tracing::info!("Reklam engeli aktif: toplam {} alan adi", merged.len());
        sh_adblock::global().replace(merged);
    }
}

fn refresh_allow(files: &UpdaterFiles, config_allow: &[String]) {
    let mut allowed: Vec<String> = config_allow.to_vec();
    if let Some(bytes) = sh_core::fsutil::read_all(&files.allow_file) {
        allowed.extend(
            parse_domains(&String::from_utf8_lossy(&bytes))
                .into_iter()
                .collect::<HashSet<_>>(),
        );
    }
    sh_adblock::global().set_allow(&allowed);
}

fn publish_recent(files: &UpdaterFiles) {
    let mut content = format!("#total\t{}\n", sh_adblock::blocked_count());
    for (host, count) in sh_adblock::top_blocked(10) {
        content.push_str(&format!("{host}\t{count}\n"));
    }
    let _ = sh_core::fsutil::write_atomic(&files.recent_file, content.as_bytes());
}

/// Runs until `shutdown` turns true.
pub async fn run(
    files: UpdaterFiles,
    list_names: Vec<String>,
    config_allow: Vec<String>,
    route: Route,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sources: Vec<Source> = list_names
        .iter()
        .filter_map(|name| match sh_adblock::list_path(name) {
            Some(path) => Some(Source {
                name: name.clone(),
                path,
                cache_file: files.cache_dir.join(format!("adblock-{name}.txt")),
                next_attempt: Instant::now(),
                retry: RETRY_MIN,
            }),
            None => {
                tracing::warn!("ad_block_lists: bilinmeyen liste '{name}' atlandi");
                None
            }
        })
        .collect();

    rebuild(&sources);
    refresh_allow(&files, &config_allow);
    let mut allow_stamp = std::fs::metadata(&files.allow_file)
        .and_then(|m| m.modified())
        .ok();
    let mut published = u64::MAX;
    let mut last_publish = Instant::now() - RECENT_PUBLISH_INTERVAL;

    loop {
        let mut changed = false;
        for source in &mut sources {
            if Instant::now() < source.next_attempt {
                continue;
            }
            if modified_age(&source.cache_file).is_some_and(|age| age < REFRESH_INTERVAL) {
                continue;
            }
            if download(&route, source).await {
                source.retry = RETRY_MIN;
                changed = true;
            } else {
                source.next_attempt = Instant::now() + source.retry;
                source.retry = (source.retry * 2).min(RETRY_MAX);
            }
        }
        if changed {
            rebuild(&sources);
        }
        // A tray click appends to the allow file: pick it up without a restart.
        let stamp = std::fs::metadata(&files.allow_file)
            .and_then(|m| m.modified())
            .ok();
        if stamp.is_some() && stamp != allow_stamp {
            allow_stamp = stamp;
            refresh_allow(&files, &config_allow);
        }
        // The count changes constantly while browsing; the tray and panel
        // only need a fresh file now and then, not a fsync'd write per tick.
        let total = sh_adblock::blocked_count();
        if total != published && last_publish.elapsed() >= RECENT_PUBLISH_INTERVAL {
            published = total;
            last_publish = Instant::now();
            publish_recent(&files);
        }
        tokio::select! {
            () = tokio::time::sleep(TICK) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(declared: Option<usize>, names: usize) -> (String, usize) {
        let mut text = String::from("# Title: test\n");
        if let Some(declared) = declared {
            text.push_str(&format!("# Number of entries: {declared}\n#\n"));
        }
        for i in 0..names {
            text.push_str(&format!("host{i}.example\n"));
        }
        let mut entries = 0;
        for_each_domain(&text, |_| entries += 1);
        (text, entries)
    }

    #[test]
    fn a_small_complete_list_is_kept_and_a_truncated_one_is_not() {
        let (text, entries) = list(Some(365), 365);
        assert!(plausible(&text, entries));
        let (text, entries) = list(Some(224_729), 5_000);
        assert!(!plausible(&text, entries));
        let (text, entries) = list(Some(365), 0);
        assert!(!plausible(&text, entries));
        // No declared size (not a HaGeZi file, or an error page): the floor.
        let (text, entries) = list(None, 365);
        assert!(!plausible(&text, entries));
        let (text, entries) = list(None, MIN_PLAUSIBLE_ENTRIES);
        assert!(plausible(&text, entries));
        assert!(!plausible("<html>Not Found</html>", 0));
    }
}
