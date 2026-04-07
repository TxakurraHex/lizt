use std::cmp::Ordering;

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Num(u64),
    Str(String),
}

impl PartialOrd for Token {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Token {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Token::Num(a), Token::Num(b)) => a.cmp(b),
            (Token::Str(a), Token::Str(b)) => a.cmp(b),
            // Sort numeric before string elements
            (Token::Num(_), Token::Str(_)) => Ordering::Less,
            (Token::Str(_), Token::Num(_)) => Ordering::Greater,
        }
    }
}

fn tokenize(version: &str) -> Vec<Token> {
    let mut tokens = vec![];
    for segment in version.split(|c| c == '.' || c == '-') {
        let mut buf = String::new();
        let mut is_digit = None;

        for char in segment.chars() {
            let digit = char.is_ascii_digit();
            if is_digit == Some(!digit) && !buf.is_empty() {
                tokens.push(make_token(&buf));
                buf.clear();
            }
            buf.push(char);
            is_digit = Some(digit);
        }
        if !buf.is_empty() {
            tokens.push(make_token(&buf));
        }
    }
    tokens
}

fn make_token(buf: &str) -> Token {
    match buf.parse::<u64>() {
        Ok(num) => Token::Num(num),
        Err(_) => Token::Str(buf.to_string()),
    }
}

pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let token_a = tokenize(a);
    let token_b = tokenize(b);

    for (x, y) in token_a.iter().zip(token_b.iter()) {
        match x.cmp(y) {
            Ordering::Equal => continue,
            order => return order,
        }
    }
    token_a.len().cmp(&token_b.len())
}

pub fn version_in_range(
    version: &str,
    start_including: Option<&str>,
    start_excluding: Option<&str>,
    end_including: Option<&str>,
    end_excluding: Option<&str>,
) -> bool {
    if let Some(start) = start_including {
        if compare_versions(version, start) == Ordering::Less {
            return false;
        }
    }

    if let Some(start) = start_excluding {
        if compare_versions(version, start) != Ordering::Greater {
            return false;
        }
    }

    if let Some(end) = end_including {
        if compare_versions(version, end) == Ordering::Greater {
            return false;
        }
    }

    if let Some(end) = end_excluding {
        if compare_versions(version, end) != Ordering::Less {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_numeric() {
        assert_eq!(compare_versions("1.0.0", "2.0.0"), Ordering::Less);
        assert_eq!(compare_versions("2.0.0", "1.0.0"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0.0"), Ordering::Equal);
    }

    #[test]
    fn patch_level() {
        assert_eq!(compare_versions("1.1.1", "1.1.2"), Ordering::Less);
        assert_eq!(compare_versions("2.28", "2.9"), Ordering::Greater);
    }

    #[test]
    fn openssl_letter_suffixes() {
        assert_eq!(compare_versions("1.1.1f", "1.1.1g"), Ordering::Less);
        assert_eq!(compare_versions("1.1.1k", "1.1.1f"), Ordering::Greater);
        assert_eq!(compare_versions("1.1.1f", "1.1.1f"), Ordering::Equal);
    }

    #[test]
    fn different_length() {
        assert_eq!(compare_versions("1.1", "1.1.0"), Ordering::Less);
        assert_eq!(compare_versions("1.1.0", "1.1"), Ordering::Greater);
    }

    #[test]
    fn prerelease() {
        // "alpha" is a string token, sorts after numeric 0
        assert_eq!(compare_versions("3.0.0", "3.0.0-alpha1"), Ordering::Less);
    }

    #[test]
    fn range_all_none() {
        assert!(version_in_range("1.0.0", None, None, None, None));
    }

    #[test]
    fn range_start_including() {
        assert!(version_in_range("1.0.0", Some("1.0.0"), None, None, None));
        assert!(!version_in_range("0.9.0", Some("1.0.0"), None, None, None));
    }

    #[test]
    fn range_end_excluding() {
        assert!(version_in_range("1.1.1", None, None, None, Some("1.1.2")));
        assert!(!version_in_range("1.1.2", None, None, None, Some("1.1.2")));
    }

    #[test]
    fn range_end_including() {
        assert!(version_in_range("1.1.2", None, None, Some("1.1.2"), None));
        assert!(!version_in_range("1.1.3", None, None, Some("1.1.2"), None));
    }

    #[test]
    fn range_combined() {
        // OpenSSL 1.1.1f in range [1.1.1, 1.1.1l)
        assert!(version_in_range(
            "1.1.1f",
            Some("1.1.1"),
            None,
            None,
            Some("1.1.1l"),
        ));
        // 1.1.1z would be past 1.1.1l
        assert!(!version_in_range(
            "1.1.1z",
            Some("1.1.1"),
            None,
            None,
            Some("1.1.1l"),
        ));
    }

    #[test]
    fn range_before_start() {
        // Version 0.9.8 should NOT be in range [1.1.1, 1.1.1l)
        assert!(!version_in_range(
            "0.9.8",
            Some("1.1.1"),
            None,
            None,
            Some("1.1.1l"),
        ));
    }
}
