//! Post-match content allowlist.
//!
//! Some vendors publish documentation-only "example" keys that are syntactically
//! valid for our regex but are not real credentials and never need rotation.
//! AWS is the canonical case: the IAM docs use `AKIAIOSFODNN7EXAMPLE` and
//! `AKIAI44QH8DHBEXAMPLE` as illustrative access-key IDs throughout. If we
//! report these we waste a maintainer's time and look like we don't know what
//! we're doing.
//!
//! `is_known_example_key` is called from `scan::match_blob` immediately after
//! the regex matches and the `min_len` check passes, before redaction or the
//! emission of any `Finding`. The check is exact-string and case-sensitive —
//! we deliberately do NOT do heuristic detection (e.g. "contains EXAMPLE")
//! because that risks suppressing real keys that happen to embed the substring.
//!
//! Source-literal note: every entry is built via `format!` so this file never
//! contains a contiguous secret-format literal. Same convention as
//! `redact.rs::tests::redacted_output_never_contains_full_key`.

use std::collections::HashSet;

use once_cell::sync::Lazy;

static KNOWN_EXAMPLE_KEYS: Lazy<HashSet<String>> = Lazy::new(|| {
    let mut s = HashSet::new();
    // AWS access-key IDs from official IAM documentation.
    s.insert(format!("AKIA{}", "IOSFODNN7EXAMPLE"));
    s.insert(format!("AKIAI44{}", "QH8DHBEXAMPLE"));
    // AWS secret access key from the same docs. Our current `aws-access-key`
    // rule does not match this string (regex is `[A-Z0-9]{16}`, this contains
    // `/` and lowercase), but we list it so a future secret-key rule cannot
    // re-introduce the same false positive.
    s.insert(format!(
        "wJalrXUtnFEMI/{}/{}",
        "K7MDENG", "bPxRfiCYEXAMPLEKEY"
    ));
    s
});

pub fn is_known_example_key(key: &str) -> bool {
    KNOWN_EXAMPLE_KEYS.contains(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_aws_documented_examples() {
        assert!(is_known_example_key(&format!("AKIA{}", "IOSFODNN7EXAMPLE")));
        assert!(is_known_example_key(&format!("AKIAI44{}", "QH8DHBEXAMPLE")));
    }

    #[test]
    fn rejects_other_aws_shaped_strings() {
        // Same prefix, same length, not on the allowlist.
        assert!(!is_known_example_key("AKIAREALKEY1234567890"));
        assert!(!is_known_example_key("AKIA0000000000000000"));
    }

    #[test]
    fn case_sensitive() {
        // Lowercased example must NOT be allowlisted — real AWS keys are
        // upper-case and a lowercase variant in source is more likely to be
        // an obfuscation attempt than a documentation reference.
        assert!(!is_known_example_key(
            &format!("AKIA{}", "IOSFODNN7EXAMPLE").to_lowercase()
        ));
    }

    #[test]
    fn empty_and_short_inputs() {
        assert!(!is_known_example_key(""));
        assert!(!is_known_example_key("AKIA"));
    }
}
