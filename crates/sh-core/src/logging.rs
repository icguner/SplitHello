//! Logging setup (port of `initializeLogging`, `src/main.cpp`).
//!
//! Same line format as the C++ spdlog pattern
//! `[%Y-%m-%d %H:%M:%S.%e] [%P] [%l] %v`, same rotation (512 KiB, two backups
//! named `splithello.1.log` / `splithello.2.log`), info level on disk whatever
//! `--verbose` says, and SplitHello files older than a week are pruned so the
//! log never becomes a browsing history.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{Layer, filter::LevelFilter};

pub const MAX_LOG_BYTES: u64 = 512 * 1024;
pub const LOG_BACKUPS: usize = 2;
const PRUNE_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// spdlog's level names, so old and new log lines read the same.
fn level_name(level: &Level) -> &'static str {
    match *level {
        Level::TRACE => "trace",
        Level::DEBUG => "debug",
        Level::INFO => "info",
        Level::WARN => "warning",
        Level::ERROR => "error",
    }
}

struct SpdlogFormat;

impl<S, N> FormatEvent<S, N> for SpdlogFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        write!(
            writer,
            "[{now}] [{}] [{}] ",
            std::process::id(),
            level_name(event.metadata().level())
        )?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// `splithello.log` -> `splithello.<index>.log` (spdlog's rotating naming).
fn backup_name(path: &Path, index: usize) -> PathBuf {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = match path.extension() {
        Some(ext) => format!("{stem}.{index}.{}", ext.to_string_lossy()),
        None => format!("{stem}.{index}"),
    };
    path.with_file_name(name)
}

/// Size-rotating file shared by every thread.
pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    backups: usize,
    state: Mutex<(File, u64)>,
}

impl RotatingFile {
    pub fn open(path: PathBuf, max_bytes: u64, backups: usize) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path,
            max_bytes,
            backups,
            state: Mutex::new((file, size)),
        })
    }

    fn rotate(&self, state: &mut (File, u64)) -> io::Result<()> {
        state.0.flush()?;
        for index in (1..=self.backups).rev() {
            let target = backup_name(&self.path, index);
            let source = if index == 1 {
                self.path.clone()
            } else {
                backup_name(&self.path, index - 1)
            };
            if source.exists() {
                let _ = fs::remove_file(&target);
                fs::rename(&source, &target)?;
            }
        }
        *state = (
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.path)?,
            0,
        );
        Ok(())
    }

    fn write_line(&self, line: &[u8]) -> io::Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.1 > 0 && state.1 + line.len() as u64 > self.max_bytes {
            // A failed rotation keeps appending rather than losing the line.
            let _ = self.rotate(&mut state);
        }
        state.0.write_all(line)?;
        state.0.flush()?; // flush on info, like the C++ build
        state.1 += line.len() as u64;
        Ok(())
    }
}

/// Buffers one formatted event and hands it to the file in one write.
pub struct LineWriter<'a> {
    file: &'a RotatingFile,
    buffer: Vec<u8>,
}

impl Write for LineWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LineWriter<'_> {
    fn drop(&mut self) {
        if !self.buffer.is_empty() {
            let _ = self.file.write_line(&self.buffer);
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RotatingFile {
    type Writer = LineWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LineWriter {
            file: self,
            buffer: Vec::with_capacity(256),
        }
    }
}

/// Deletes SplitHello files in `dir` (other than `keep`) older than a week.
fn prune_old_logs(dir: &Path, keep: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let oldest_allowed = SystemTime::now() - PRUNE_AGE;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_ours = entry
            .file_name()
            .to_string_lossy()
            .starts_with("splithello");
        let old = entry
            .metadata()
            .ok()
            .filter(|m| m.is_file())
            .and_then(|m| m.modified().ok())
            .is_some_and(|t| t < oldest_allowed);
        if is_ours && path != keep && old {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Installs the global subscriber: console always, the rotating file when
/// `log_file` is given (only the engine owns it, avoiding rotation races).
pub fn init(verbose: bool, log_file: Option<&Path>) {
    let console_level = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let console = tracing_subscriber::fmt::layer()
        .event_format(SpdlogFormat)
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_filter(console_level);

    let file_layer = log_file.and_then(|path| {
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
            prune_old_logs(dir, path);
        }
        match RotatingFile::open(path.to_path_buf(), MAX_LOG_BYTES, LOG_BACKUPS) {
            Ok(file) => Some(
                tracing_subscriber::fmt::layer()
                    .event_format(SpdlogFormat)
                    .with_writer(file)
                    .with_ansi(false)
                    .with_filter(LevelFilter::INFO),
            ),
            Err(error) => {
                eprintln!("Kalici log acilamadi: {error}");
                None
            }
        }
    });

    let subscriber = tracing_subscriber::registry()
        .with(console)
        .with(file_layer);
    let _ = tracing::subscriber::set_global_default(subscriber);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_names_follow_spdlog() {
        let path = Path::new("C:\\x\\splithello.log");
        assert_eq!(backup_name(path, 1), Path::new("C:\\x\\splithello.1.log"));
        assert_eq!(backup_name(path, 2), Path::new("C:\\x\\splithello.2.log"));
    }

    #[test]
    fn rotates_at_the_size_limit_and_keeps_two_backups() {
        let dir = std::env::temp_dir().join(format!("sh-core-log-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("splithello.log");
        let file = RotatingFile::open(path.clone(), 100, 2).unwrap();
        for index in 0..10 {
            file.write_line(format!("line {index:03} {}\n", "x".repeat(30)).as_bytes())
                .unwrap();
        }
        assert!(fs::metadata(&path).unwrap().len() <= 100);
        assert!(backup_name(&path, 1).exists());
        assert!(backup_name(&path, 2).exists());
        assert!(!backup_name(&path, 3).exists());
        assert!(fs::read_to_string(&path).unwrap().contains("line 009"));
        drop(file);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn line_format_matches_the_cpp_pattern() {
        let dir = std::env::temp_dir().join(format!("sh-core-logfmt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("splithello.log");
        let file = RotatingFile::open(path.clone(), MAX_LOG_BYTES, LOG_BACKUPS).unwrap();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .event_format(SpdlogFormat)
                .with_writer(file)
                .with_ansi(false),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("Port {} kullanilamiyor", 1080)
        });
        let line = fs::read_to_string(&path).unwrap();
        // [2026-11-09 21:46:11.066] [59784] [warning] Port 1080 kullanilamiyor
        let parts: Vec<&str> = line.trim_end().splitn(4, "] ").collect();
        assert_eq!(parts.len(), 4, "{line}");
        assert_eq!(parts[0].len(), "[2026-11-09 21:46:11.066".len());
        assert_eq!(parts[1], format!("[{}", std::process::id()));
        assert_eq!(parts[2], "[warning");
        assert_eq!(parts[3], "Port 1080 kullanilamiyor");
        fs::remove_dir_all(&dir).unwrap();
    }
}
