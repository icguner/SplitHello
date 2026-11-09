//! Windows command-line quoting (port of `cmdline::quoteArgument`,
//! `src/CommandLine.hpp`). The result round-trips through
//! `CommandLineToArgvW` / the MSVC CRT argv rules.

pub fn quote_argument(argument: &str) -> String {
    // An empty argument must still be one argv element, so it is written as "".
    if !argument.is_empty() && !argument.contains([' ', '\t', '\n', '\x0B', '"']) {
        return argument.to_string();
    }
    let mut result = String::from("\"");
    let mut backslashes = 0;
    for character in argument.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                result.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                result.push('"');
                backslashes = 0;
            }
            _ => {
                result.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                result.push(character);
            }
        }
    }
    result.extend(std::iter::repeat_n('\\', backslashes * 2));
    result.push('"');
    result
}

/// Joins arguments into one command-line string.
pub fn join<S: AsRef<str>>(arguments: &[S]) -> String {
    arguments
        .iter()
        .map(|a| quote_argument(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_like_the_crt_expects() {
        assert_eq!(quote_argument("plain"), "plain");
        assert_eq!(quote_argument(""), "\"\"");
        assert_eq!(quote_argument("a b"), "\"a b\"");
        assert_eq!(quote_argument("C:\\dir with\\"), "\"C:\\dir with\\\\\"");
        assert_eq!(quote_argument("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(join(&["--port", "1 2"]), "--port \"1 2\"");
    }
}
