//! Crash-safe file writes (port of `src/FileUtil.cpp`): the content goes to a
//! sibling temp file, is flushed to the device, and only then replaces the
//! target. A hard kill leaves either the old file or the new one, never a
//! truncated mix.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

pub fn write_atomic(path: impl AsRef<Path>, content: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let result = (|| {
        let mut file = File::create(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        // MoveFileExW(MOVEFILE_REPLACE_EXISTING) on Windows.
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Reads a whole file; None when it is missing or unreadable.
pub fn read_all(path: impl AsRef<Path>) -> Option<Vec<u8>> {
    fs::read(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_existing_content_and_leaves_no_temp_file() {
        let dir = std::env::temp_dir().join(format!("sh-core-fsutil-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(read_all(&path).unwrap(), b"second");
        assert!(!dir.join("state.json.tmp").exists());
        assert!(read_all(dir.join("missing")).is_none());
        fs::remove_dir_all(&dir).unwrap();
    }
}
