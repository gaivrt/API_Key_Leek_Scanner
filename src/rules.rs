//! Vendor rule table.
//!
//! Each rule describes:
//!   - a GitHub code-search query (fixed-string, since GitHub code search
//!     does not support regex) used to locate candidate files;
//!   - a regex used to extract and validate the key from the fetched blob;
//!   - disclosure metadata (vendor security email, confidence).
//!
//! Confidence tiers:
//!   - High:   prefix is canonical and published by the vendor, low FP risk.
//!   - Medium: prefix is observed/documented by third parties; some FP risk.
//!   - Low:    no distinctive prefix; relies on context — not included in v1.
//!
//! When adding a rule, also add a corresponding `wiki/vendors/<id>.md` page
//! with the source citation and any known FP patterns.

use once_cell::sync::Lazy;
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug)]
pub struct Rule {
    pub id: &'static str,
    pub vendor: &'static str,
    /// Literal GitHub code-search query. Keep distinctive (≥ 6 chars, hyphen
    /// or underscore to prevent tokenizer splitting).
    pub search_query: &'static str,
    pub regex: Regex,
    /// Minimum full-key length (sanity floor against partial matches).
    pub min_len: usize,
    /// `security@<vendor>.com` or equivalent. `None` = no known contact.
    pub disclosure_email: Option<&'static str>,
    pub confidence: Confidence,
}

fn r(pat: &str) -> Regex {
    Regex::new(pat).expect("static regex must compile")
}

pub static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        // ---- Tier A: LLM / AI providers ----
        Rule {
            id: "anthropic-api03",
            vendor: "Anthropic",
            search_query: "\"sk-ant-api03\"",
            regex: r(r"sk-ant-(?:api|admin|sid)\d{2}-[A-Za-z0-9_\-]{80,120}"),
            min_len: 93,
            disclosure_email: Some("security@anthropic.com"),
            confidence: Confidence::High,
        },
        Rule {
            id: "openai-t3blbkfj",
            vendor: "OpenAI",
            // T3BlbkFJ is an invariant substring inside every OpenAI key.
            search_query: "\"T3BlbkFJ\"",
            regex: r(r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,74}T3BlbkFJ[A-Za-z0-9_\-]{20,74}"),
            min_len: 51,
            disclosure_email: Some("security@openai.com"),
            confidence: Confidence::High,
        },
        Rule {
            id: "google-ai",
            vendor: "Google AI (Gemini / Cloud)",
            search_query: "\"AIzaSy\"",
            regex: r(r"AIza[0-9A-Za-z\-_]{35}"),
            min_len: 39,
            disclosure_email: None, // report via Google VRP, not a plain email
            confidence: Confidence::High,
        },
        Rule {
            id: "groq",
            vendor: "Groq",
            search_query: "\"gsk_\"",
            regex: r(r"gsk_[A-Za-z0-9]{52}"),
            min_len: 56,
            disclosure_email: Some("security@groq.com"),
            confidence: Confidence::Medium,
        },
        Rule {
            id: "huggingface",
            vendor: "Hugging Face",
            search_query: "\"hf_\"",
            regex: r(r"hf_[A-Za-z0-9]{34,40}"),
            min_len: 37,
            disclosure_email: Some("security@huggingface.co"),
            confidence: Confidence::Medium,
        },
        Rule {
            id: "replicate",
            vendor: "Replicate",
            search_query: "\"r8_\"",
            regex: r(r"r8_[A-Za-z0-9]{37,45}"),
            min_len: 40,
            disclosure_email: Some("security@replicate.com"),
            confidence: Confidence::Medium,
        },
        Rule {
            id: "xai",
            vendor: "xAI",
            search_query: "\"xai-\"",
            regex: r(r"xai-[A-Za-z0-9]{80}"),
            min_len: 84,
            disclosure_email: None,
            confidence: Confidence::Medium,
        },
        Rule {
            id: "perplexity",
            vendor: "Perplexity",
            search_query: "\"pplx-\"",
            regex: r(r"pplx-[A-Za-z0-9]{48,64}"),
            min_len: 53,
            disclosure_email: None,
            confidence: Confidence::Medium,
        },
        // ---- Tier B: cloud / SaaS ----
        Rule {
            id: "aws-access-key",
            vendor: "AWS",
            search_query: "\"AKIA\"",
            regex: r(r"(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}"),
            min_len: 20,
            disclosure_email: None, // report via AWS abuse form, not email
            confidence: Confidence::Medium,
        },
        Rule {
            id: "github-pat-classic",
            vendor: "GitHub (classic PAT)",
            search_query: "\"ghp_\"",
            regex: r(r"ghp_[A-Za-z0-9]{36}"),
            min_len: 40,
            disclosure_email: None,
            confidence: Confidence::High,
        },
        Rule {
            id: "github-pat-fine",
            vendor: "GitHub (fine-grained PAT)",
            search_query: "\"github_pat_\"",
            regex: r(r"github_pat_[A-Za-z0-9_]{82}"),
            min_len: 93,
            disclosure_email: None,
            confidence: Confidence::High,
        },
        Rule {
            id: "github-pat-server",
            vendor: "GitHub (Actions token)",
            search_query: "\"ghs_\"",
            regex: r(r"ghs_[A-Za-z0-9]{36}"),
            min_len: 40,
            disclosure_email: None,
            confidence: Confidence::High,
        },
        Rule {
            id: "github-pat-oauth",
            vendor: "GitHub (OAuth token)",
            search_query: "\"gho_\"",
            regex: r(r"gho_[A-Za-z0-9]{36}"),
            min_len: 40,
            disclosure_email: None,
            confidence: Confidence::High,
        },
        Rule {
            id: "github-pat-user-server",
            vendor: "GitHub (user-server token)",
            search_query: "\"ghu_\"",
            regex: r(r"ghu_[A-Za-z0-9]{36}"),
            min_len: 40,
            disclosure_email: None,
            confidence: Confidence::High,
        },
        Rule {
            id: "github-pat-refresh",
            vendor: "GitHub (refresh token)",
            search_query: "\"ghr_\"",
            regex: r(r"ghr_[A-Za-z0-9]{76}"),
            min_len: 80,
            disclosure_email: None,
            confidence: Confidence::High,
        },
        Rule {
            id: "stripe-secret-live",
            vendor: "Stripe (live secret)",
            search_query: "\"sk_live_\"",
            regex: r(r"sk_live_[0-9a-zA-Z]{24,}"),
            min_len: 32,
            disclosure_email: Some("security@stripe.com"),
            confidence: Confidence::Medium,
        },
        Rule {
            id: "stripe-restricted-live",
            vendor: "Stripe (live restricted)",
            search_query: "\"rk_live_\"",
            regex: r(r"rk_live_[0-9a-zA-Z]{24,}"),
            min_len: 32,
            disclosure_email: Some("security@stripe.com"),
            confidence: Confidence::Medium,
        },
        Rule {
            id: "slack-bot",
            vendor: "Slack (bot token)",
            search_query: "\"xoxb-\"",
            regex: r(r"xoxb-\d{10,13}-\d{10,13}-[A-Za-z0-9]{24,}"),
            min_len: 44,
            disclosure_email: Some("security@slack.com"),
            confidence: Confidence::High,
        },
        Rule {
            id: "slack-user",
            vendor: "Slack (user token)",
            search_query: "\"xoxp-\"",
            regex: r(r"xoxp-\d{10,13}-\d{10,13}-\d{10,13}-[a-f0-9]{32,}"),
            min_len: 60,
            disclosure_email: Some("security@slack.com"),
            confidence: Confidence::High,
        },
        Rule {
            id: "slack-app",
            vendor: "Slack (app-level token)",
            search_query: "\"xapp-\"",
            // xapp-<version>-<app_id>-<install_id>-<signing_secret>
            regex: r(r"xapp-\d+-[A-Z0-9]{9,12}-\d+-[A-Za-z0-9]{30,}"),
            min_len: 50,
            disclosure_email: Some("security@slack.com"),
            confidence: Confidence::Medium,
        },
    ]
});

/// A `RegexSet` mirror of `RULES` for O(1) single-pass matching against a blob.
/// Index-aligned with `RULES`.
pub static RULE_SET: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new(RULES.iter().map(|r| r.regex.as_str()))
        .expect("static regex set must compile")
});

pub fn by_id(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub repo_full_name: String,
    pub path: String,
    pub html_url: String,
    pub vendor: String,
    pub rule_id: String,
    pub key_prefix: String,
    pub key_sha256_prefix: String,
    pub key_length: usize,
    pub discovered_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RegexSet must be buildable and aligned with RULES (lengths match).
    #[test]
    fn ruleset_builds_and_aligns() {
        assert_eq!(RULES.len(), RULE_SET.len());
        assert!(RULES.len() >= 18, "Tier A+B should be ≥ 18 rules");
    }

    /// Every rule id must be unique.
    #[test]
    fn rule_ids_unique() {
        let mut ids: Vec<_> = RULES.iter().map(|r| r.id).collect();
        ids.sort();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n, "duplicate rule id detected");
    }

    /// Synthetic well-formed samples per rule. Built via `format!` so that
    /// the literal secret pattern never appears in the source file (otherwise
    /// GitHub secret-scanning push protection rejects the commit even though
    /// the values are bogus).
    fn samples() -> Vec<(&'static str, String)> {
        let alnum40 = "abcdefghijklmnopqrstuvwxyz0123456789ABCD";
        let openai_tail = format!("{alnum40}{}{alnum40}", "T3BlbkFJ");
        vec![
            ("anthropic-api03", format!("sk-ant-{}-{}", "api03", "A".repeat(85))),
            ("openai-t3blbkfj", format!("sk-{}-{}", "proj", openai_tail)),
            ("google-ai", format!("AIza{}", "SyABCDEFGHIJKLMNOPQRSTUVWXYZ-_0123456")),
            ("groq", format!("gsk_{}", "A".repeat(52))),
            ("huggingface", format!("hf_{}", "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD")),
            ("replicate", format!("r8_{}", "A".repeat(41))),
            (
                "xai",
                format!(
                    "xai-{}",
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKL"
                ),
            ),
            (
                "perplexity",
                format!("pplx-{}", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKL"),
            ),
            ("aws-access-key", format!("AKIA{}", "IOSFODNN7EXAMPLE")),
            ("github-pat-classic", format!("ghp_{}", alnum40.repeat(1))),
            (
                "github-pat-fine",
                format!(
                    "github_pat_{}",
                    "11ABCDEFG0abcdef1234567_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV"
                ),
            ),
            ("github-pat-server", format!("ghs_{}", alnum40)),
            ("github-pat-oauth", format!("gho_{}", alnum40)),
            ("github-pat-user-server", format!("ghu_{}", alnum40)),
            ("github-pat-refresh", format!("ghr_{}", "A".repeat(76))),
            ("stripe-secret-live", format!("sk_live_{}", "AbCdEfGhIjKlMnOpQrStUvWx")),
            ("stripe-restricted-live", format!("rk_live_{}", "AbCdEfGhIjKlMnOpQrStUvWx")),
            (
                "slack-bot",
                format!(
                    "xoxb-{}-{}-{}",
                    "1234567890", "1234567890", "abcdefghijklmnopqrstuvwx"
                ),
            ),
            (
                "slack-user",
                format!(
                    "xoxp-{}-{}-{}-{}",
                    "1234567890",
                    "1234567890",
                    "1234567890",
                    "abcdef0123456789abcdef0123456789"
                ),
            ),
            (
                "slack-app",
                format!(
                    "xapp-1-{}-{}-{}",
                    "ABCDEFGHIJ", "1234567890", "abcdef0123456789abcdef0123456789AB"
                ),
            ),
        ]
    }

    #[test]
    fn positive_samples_match() {
        for (id, sample) in samples() {
            let rule = by_id(id).unwrap_or_else(|| panic!("no rule {id}"));
            assert!(
                rule.regex.is_match(&sample),
                "rule {id} did not match its positive sample"
            );
            assert!(
                sample.len() >= rule.min_len,
                "sample for {id} is below min_len"
            );
        }
    }

    /// Negative: clearly-not-a-key strings must not match.
    #[test]
    fn negative_samples_do_not_match() {
        let negatives = [
            "sk-ant-apiXX-short",
            "AIza short",
            "ghp_tooshort",
            "xoxb-abc-def-ghi",   // non-numeric team id
            "sk_live_short",
            "T3BlbkFJ alone",     // OpenAI anchor but no prefix/suffix
        ];
        for neg in negatives {
            assert!(
                !RULE_SET.is_match(neg),
                "false positive on negative sample: {neg}"
            );
        }
    }
}
