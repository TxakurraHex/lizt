use regex::Regex;
use std::sync::OnceLock;

/// English words that slip past the 3-char minimum in regex patterns.
pub const STOP_WORDS_ENGLISH: &[&str] = &[
    "the",
    "does",
    "when",
    "these",
    "those",
    "this",
    "that",
    "with",
    "from",
    "into",
    "have",
    "been",
    "will",
    "data",
    "used",
    "user",
    "file",
    "path",
    "name",
    "size",
    "list",
    "info",
    "code",
    "test",
    "check",
    "allow",
    "cause",
    "issue",
    "could",
    "which",
    "there",
    "their",
    "other",
    "after",
    "where",
    "before",
    "should",
    "would",
    "because",
    "through",
    "between",
    "possible",
    "result",
    "allows",
    "attacker",
    "remote",
    "local",
    "denial",
    "service",
    "overflow",
    "impact",
    "version",
    "affect",
    "leading",
    "certain",
    "specific",
    "condition",
    "vulnerability",
    "function",
    "method",
    "symbol",
    "helper",
    "streaming",
    "error",
    "value",
    "buffer",
    "memory",
    "pointer",
    "integer",
    "string",
    "type",
    "true",
    "false",
    "null",
    "none",
    "some",
    "also",
    "such",
    "than",
    "only",
    "more",
    "most",
    "each",
    "just",
    "like",
    "over",
    "uses",
    "make",
    "call",
    "able",
    "upon",
    "case",
    "based",
    "access",
    "input",
    "output",
];

/// Programming terms too generic to be useful probe targets.
pub const STOP_WORDS_GENERIC: &[&str] = &[
    "init", "main", "exit", "open", "close", "start", "stop", "create", "delete", "update", "get",
    "set", "run", "exec", "send", "recv", "print", "log", "debug", "assert", "test", "setup",
    "teardown", "handle", "process", "parse", "format", "convert", "copy", "move", "compare",
    "destroy", "release", "acquire", "lock", "unlock", "alloc", "dealloc", "abort", "callback",
    "handler", "dispatch", "read", "write",
];

/// Known C type names that regex patterns often catch.
const C_TYPE_NAMES: &[&str] = &[
    "size_t",
    "ssize_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "uintptr_t",
    "intptr_t",
    "ptrdiff_t",
    "pid_t",
    "uid_t",
    "gid_t",
    "off_t",
    "mode_t",
    "dev_t",
    "ino_t",
    "time_t",
    "bool_t",
    "socklen_t",
];

fn version_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d+\.\d+").unwrap())
}

/// Returns `true` if `name` looks like a plausible function/symbol name worth probing.
pub fn is_likely_function_name(name: &str) -> bool {
    let lower = name.to_lowercase();

    // Reject stop words
    if STOP_WORDS_ENGLISH.contains(&lower.as_str()) || STOP_WORDS_GENERIC.contains(&lower.as_str())
    {
        return false;
    }

    // Reject known C type names
    if C_TYPE_NAMES.contains(&lower.as_str()) {
        return false;
    }

    // Reject if starts with a digit
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }

    // Reject file paths (contain / or .)
    if name.contains('/') || (name.contains('.') && !name.ends_with('.')) {
        return false;
    }

    // Reject version-like strings
    if version_regex().is_match(name) {
        return false;
    }

    // Reject ALL_CAPS names >6 chars (likely macros/constants) — except kernel-style __prefixed
    if name.len() > 6
        && name == name.to_uppercase()
        && name.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        && !name.starts_with("__")
    {
        return false;
    }

    // Too short
    if name.len() < 3 {
        return false;
    }

    true
}

/// Returns `true` if the path looks like test/example code.
pub fn is_test_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("/test/")
        || lower.contains("/tests/")
        || lower.contains("/testing/")
        || lower.contains("/examples/")
        || lower.contains("/benchmarks/")
        || lower.contains("/fixtures/")
        || lower.ends_with("_test.go")
        || lower.ends_with("_test.rs")
        || lower.ends_with("_test.py")
        || lower.ends_with("_test.c")
        || lower.ends_with("_test.cpp")
        || lower
            .rsplit('/')
            .next()
            .is_some_and(|f| f.starts_with("test_") && f.ends_with(".py"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_stop_words() {
        assert!(!is_likely_function_name("the"));
        assert!(!is_likely_function_name("init"));
        assert!(!is_likely_function_name("handle"));
        assert!(!is_likely_function_name("vulnerability"));
        assert!(!is_likely_function_name("attacker"));
    }

    #[test]
    fn rejects_c_types() {
        assert!(!is_likely_function_name("size_t"));
        assert!(!is_likely_function_name("uint32_t"));
        assert!(!is_likely_function_name("ssize_t"));
    }

    #[test]
    fn rejects_all_caps_macros() {
        assert!(!is_likely_function_name("MAX_BUFFER_SIZE"));
        assert!(!is_likely_function_name("PAGE_SIZE"));
        assert!(!is_likely_function_name("GFP_KERNEL"));
    }

    #[test]
    fn allows_kernel_double_underscore() {
        assert!(is_likely_function_name("__tcp_transmit_skb"));
        assert!(is_likely_function_name("__NR_openat"));
    }

    #[test]
    fn rejects_file_paths_and_versions() {
        assert!(!is_likely_function_name("net/ipv4"));
        assert!(!is_likely_function_name("lib.rs"));
        assert!(!is_likely_function_name("v2.3"));
    }

    #[test]
    fn rejects_short_names() {
        assert!(!is_likely_function_name("ab"));
        assert!(!is_likely_function_name("x"));
    }

    #[test]
    fn rejects_digit_start() {
        assert!(!is_likely_function_name("3des_encrypt"));
    }

    #[test]
    fn allows_real_function_names() {
        assert!(is_likely_function_name("tcp_v4_connect"));
        assert!(is_likely_function_name("do_execveat_common"));
        assert!(is_likely_function_name("SSL_read"));
        assert!(is_likely_function_name("nf_conntrack_in"));
        assert!(is_likely_function_name("ext4_fill_super"));
    }

    #[test]
    fn test_path_detection() {
        assert!(is_test_path("src/tests/test_parser.py"));
        assert!(is_test_path("net/core/test/something.c"));
        assert!(is_test_path("pkg/handler_test.go"));
        assert!(is_test_path("examples/demo.rs"));
        assert!(!is_test_path("src/net/tcp_input.c"));
        assert!(!is_test_path("lib/parser.rs"));
    }
}
