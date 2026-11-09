//! Process scope rules (port of `process_filter::Rules`, `src/ProcessFilter.cpp`).
//!
//! Exclude rules always win. When at least one include rule exists, processes
//! that match none stay on the normal Windows path. Patterns are
//! case-insensitive with `*` and `?`; a pattern containing a slash matches the
//! full image path, any other one the executable's file name.

const MAXIMUM_RULES: usize = 128;
const MAXIMUM_RULE_LENGTH: usize = 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    includes: Vec<String>,
    excludes: Vec<String>,
    rejected_includes: usize,
    rejected_excludes: usize,
}

fn is_blank(value: &str) -> bool {
    value.trim_matches([' ', '\t', '\r', '\n']).is_empty()
}

fn normalize(value: &str) -> String {
    let trimmed = value.trim_matches([' ', '\t', '\r', '\n']);
    if trimmed.len() > MAXIMUM_RULE_LENGTH {
        return String::new();
    }
    trimmed.to_ascii_lowercase().replace('/', "\\")
}

/// `rejected` counts non-blank patterns that could not be kept (too long, or
/// past the rule cap), so a silently emptied list can be told from a blank one.
fn normalize_rules<S: AsRef<str>>(values: &[S], rejected: &mut usize) -> Vec<String> {
    let mut result: Vec<String> = Vec::with_capacity(values.len().min(MAXIMUM_RULES));
    for value in values {
        let value = value.as_ref();
        let normalized = normalize(value);
        if normalized.is_empty() {
            if !is_blank(value) {
                *rejected += 1;
            }
            continue;
        }
        if result.contains(&normalized) {
            continue;
        }
        if result.len() == MAXIMUM_RULES {
            *rejected += 1;
            continue;
        }
        result.push(normalized);
    }
    result
}

/// Iterative `*`/`?` matcher with single-star backtracking (linear in practice).
fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<usize> = None;
    let mut retry = 0;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = t;
        } else if let Some(s) = star {
            p = s + 1;
            retry += 1;
            t = retry;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

fn matches_any(patterns: &[String], full_path: &str, basename: &str) -> bool {
    patterns.iter().any(|pattern| {
        let subject = if pattern.contains('\\') {
            full_path
        } else {
            basename
        };
        wildcard_match(pattern.as_bytes(), subject.as_bytes())
    })
}

impl Rules {
    pub fn new<S: AsRef<str>>(includes: &[S], excludes: &[S]) -> Self {
        let mut rules = Self::default();
        rules.includes = normalize_rules(includes, &mut rules.rejected_includes);
        rules.excludes = normalize_rules(excludes, &mut rules.rejected_excludes);
        rules
    }

    pub fn enabled(&self) -> bool {
        !self.includes.is_empty() || !self.excludes.is_empty() || self.include_list_invalid()
    }

    /// The include list was given but no pattern survived. Treating that as "no
    /// include rules" would intercept every process, so the rules stay enabled
    /// and allow nothing (fail closed).
    pub fn include_list_invalid(&self) -> bool {
        self.includes.is_empty() && self.rejected_includes != 0
    }

    pub fn allows_image(&self, image_path: &str) -> bool {
        if self.include_list_invalid() {
            return false;
        }
        let full_path = normalize(image_path);
        if full_path.is_empty() {
            return false;
        }
        let basename = full_path.rsplit('\\').next().unwrap_or(&full_path);
        if matches_any(&self.excludes, &full_path, basename) {
            return false;
        }
        self.includes.is_empty() || matches_any(&self.includes, &full_path, basename)
    }

    pub fn include_count(&self) -> usize {
        self.includes.len()
    }

    pub fn exclude_count(&self) -> usize {
        self.excludes.len()
    }

    pub fn rejected_include_count(&self) -> usize {
        self.rejected_includes
    }

    pub fn rejected_exclude_count(&self) -> usize {
        self.rejected_excludes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: [&str; 0] = [];

    #[test]
    fn allow_everything_when_empty() {
        let rules = Rules::new(&NONE, &NONE);
        assert!(!rules.enabled());
        assert!(rules.allows_image("C:\\Program Files\\Browser\\browser.exe"));
    }

    #[test]
    fn use_include_as_allow_list() {
        let rules = Rules::new(&["chrome.exe", "firefox*.exe"], &[]);
        assert!(rules.enabled());
        assert!(rules.allows_image("C:\\Program Files\\Google\\Chrome.EXE"));
        assert!(rules.allows_image("firefox-nightly.exe"));
        assert!(!rules.allows_image("C:\\Windows\\System32\\curl.exe"));
    }

    #[test]
    fn give_exclude_precedence() {
        let rules = Rules::new(&["*.exe"], &["steam*.exe"]);
        assert!(rules.allows_image("browser.exe"));
        assert!(!rules.allows_image("C:\\Games\\Steam.exe"));
        assert!(!rules.allows_image("steamwebhelper.exe"));
    }

    #[test]
    fn can_match_full_paths_and_question_marks() {
        let rules = Rules::new(&["c:/portable/*/app?.exe"], &[]);
        assert!(rules.allows_image("C:\\Portable\\Browser\\App1.exe"));
        assert!(!rules.allows_image("C:\\Installed\\Browser\\App1.exe"));
        assert!(!rules.allows_image("C:\\Portable\\Browser\\App10.exe"));
    }

    #[test]
    fn normalize_and_deduplicate_patterns() {
        let rules = Rules::new(
            &[" Chrome.exe ", "chrome.EXE", ""],
            &[" helper.exe ", "HELPER.EXE"],
        );
        assert_eq!(rules.include_count(), 1);
        assert_eq!(rules.exclude_count(), 1);
        assert!(rules.allows_image("chrome.exe"));
        assert!(!rules.allows_image("helper.exe"));
        assert_eq!(rules.rejected_include_count(), 0);
        assert!(!rules.include_list_invalid());
    }

    #[test]
    fn fail_closed_when_an_include_list_normalizes_to_nothing() {
        // A pattern over the length limit is dropped; if that empties the
        // include list, "no include rules" would mean "intercept everything".
        let rules = Rules::new(&["a".repeat(2000)], &[]);
        assert_eq!(rules.include_count(), 0);
        assert_eq!(rules.rejected_include_count(), 1);
        assert!(rules.include_list_invalid());
        assert!(rules.enabled());
        assert!(!rules.allows_image("chrome.exe"));

        // Blank entries are not a request for anything.
        let blank = Rules::new(&[" ", "\t", ""], &[]);
        assert!(!blank.enabled());
        assert!(!blank.include_list_invalid());
        assert!(blank.allows_image("chrome.exe"));

        // A partly usable list keeps working and reports what it dropped.
        let partial = Rules::new(
            &["chrome.exe".to_string(), "b".repeat(2000)],
            &["c".repeat(2000)],
        );
        assert!(!partial.include_list_invalid());
        assert_eq!(partial.rejected_include_count(), 1);
        assert_eq!(partial.rejected_exclude_count(), 1);
        assert!(partial.allows_image("chrome.exe"));
        assert!(!partial.allows_image("curl.exe"));
    }

    #[test]
    fn report_patterns_beyond_the_rule_cap() {
        let includes: Vec<String> = (0..130).map(|i| format!("app{i}.exe")).collect();
        let rules = Rules::new(&includes, &[]);
        assert_eq!(rules.include_count(), 128);
        assert_eq!(rules.rejected_include_count(), 2);
        assert!(rules.allows_image("app127.exe"));
        assert!(!rules.allows_image("app128.exe"));
    }
}
